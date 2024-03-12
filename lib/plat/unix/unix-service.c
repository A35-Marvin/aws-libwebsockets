/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "private-lib-core.h"

int
aws_lws_poll_listen_fd(struct aws_lws_pollfd *fd)
{
	return poll(fd, 1, 0);
}

int
aws__lws_plat_service_forced_tsi(struct aws_lws_context *context, int tsi)
{
	struct aws_lws_context_per_thread *pt = &context->pt[tsi];
	int m, n, r;

	r = aws_lws_service_flag_pending(context, tsi);

	/* any socket with events to service? */
	for (n = 0; n < (int)pt->fds_count; n++) {
		aws_lws_sockfd_type fd = pt->fds[n].fd;

		if (!pt->fds[n].revents)
			continue;

		m = aws_lws_service_fd_tsi(context, &pt->fds[n], tsi);
		if (m < 0) {
			aws_lwsl_err("%s: aws_lws_service_fd_tsi returned %d\n",
				 __func__, m);
			return -1;
		}

		/* if something closed, retry this slot since may have been
		 * swapped with end fd */
		if (m && pt->fds[n].fd != fd)
			n--;
	}

	aws_lws_service_do_ripe_rxflow(pt);

	return r;
}

#define LWS_POLL_WAIT_LIMIT 2000000000

int
aws__lws_plat_service_tsi(struct aws_lws_context *context, int timeout_ms, int tsi)
{
	volatile struct aws_lws_foreign_thread_pollfd *ftp, *next;
	volatile struct aws_lws_context_per_thread *vpt;
	struct aws_lws_context_per_thread *pt;
	aws_lws_usec_t timeout_us, us;
#if defined(LWS_WITH_SYS_METRICS)
	aws_lws_usec_t a, b;
#endif
	int n;
#if (defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)) || defined(LWS_WITH_TLS)
	int m;
#endif

	/* stay dead once we are dead */

	if (!context)
		return 1;

#if defined(LWS_WITH_SYS_METRICS)
	b =
#endif
			us = aws_lws_now_usecs();

	pt = &context->pt[tsi];
	vpt = (volatile struct aws_lws_context_per_thread *)pt;

	if (timeout_ms < 0)
		timeout_ms = 0;
	else
		/* force a default timeout of 23 days */
		timeout_ms = LWS_POLL_WAIT_LIMIT;
	timeout_us = ((aws_lws_usec_t)timeout_ms) * LWS_US_PER_MS;

	if (context->event_loop_ops->run_pt)
		context->event_loop_ops->run_pt(context, tsi);

	if (!pt->service_tid_detected && context->vhost_list) {
		aws_lws_fakewsi_def_plwsa(pt);

		aws_lws_fakewsi_prep_plwsa_ctx(context);

		pt->service_tid = context->vhost_list->protocols[0].callback(
					(struct aws_lws *)plwsa,
					LWS_CALLBACK_GET_THREAD_ID,
					NULL, NULL, 0);
		pt->service_tid_detected = 1;
	}

	aws_lws_pt_lock(pt, __func__);
	/*
	 * service ripe scheduled events, and limit wait to next expected one
	 */
	us = aws___lws_sul_service_ripe(pt->pt_sul_owner, LWS_COUNT_PT_SUL_OWNERS, us);
	if (us && us < timeout_us)
		/*
		 * If something wants zero wait, that's OK, but if the next sul
		 * coming ripe is an interval less than our wait resolution,
		 * bump it to be the wait resolution.
		 */
		timeout_us = us < context->us_wait_resolution ?
					context->us_wait_resolution : us;

	aws_lws_pt_unlock(pt);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!aws_lws_service_adjust_timeout(context, 1, tsi))
		timeout_us = 0;

	/* ensure we don't wrap at 2^31 with poll()'s signed int ms */

	timeout_us /= LWS_US_PER_MS; /* ms now */

#if defined(LWS_WITH_SYS_METRICS)
	a = aws_lws_now_usecs() - b;
#endif
	vpt->inside_poll = 1;
	aws_lws_memory_barrier();
	n = poll(pt->fds, pt->fds_count, (int)timeout_us /* ms now */ );
	vpt->inside_poll = 0;
	aws_lws_memory_barrier();

#if defined(LWS_WITH_SYS_METRICS)
	b = aws_lws_now_usecs();
#endif
	/* Collision will be rare and brief.  Spin until it completes */
	while (vpt->foreign_spinlock)
		;

	/*
	 * At this point we are not inside a foreign thread pollfd
	 * change, and we have marked ourselves as outside the poll()
	 * wait.  So we are the only guys that can modify the
	 * aws_lws_foreign_thread_pollfd list on the pt.  Drain the list
	 * and apply the changes to the affected pollfds in the correct
	 * order.
	 */

	aws_lws_pt_lock(pt, __func__);

	ftp = vpt->foreign_pfd_list;
	//aws_lwsl_notice("cleared list %p\n", ftp);
	while (ftp) {
		struct aws_lws *wsi;
		struct aws_lws_pollfd *pfd;

		next = ftp->next;
		pfd = &vpt->fds[ftp->fd_index];
		if (aws_lws_socket_is_valid(pfd->fd)) {
			wsi = wsi_from_fd(context, pfd->fd);
			if (wsi)
				aws___lws_change_pollfd(wsi, ftp->_and,
						    ftp->_or);
		}
		aws_lws_free((void *)ftp);
		ftp = next;
	}
	vpt->foreign_pfd_list = NULL;
	aws_lws_memory_barrier();

	aws_lws_pt_unlock(pt);

#if (defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)) || defined(LWS_WITH_TLS)
	m = 0;
#endif
#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	m |= !!pt->ws.rx_draining_ext_list;
#endif

#if defined(LWS_WITH_TLS)
	if (pt->context->tls_ops &&
	    pt->context->tls_ops->fake_POLLIN_for_buffered)
		m |= pt->context->tls_ops->fake_POLLIN_for_buffered(pt);
#endif

	if (
#if (defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)) || defined(LWS_WITH_TLS)
		!m &&
#endif
		!n) /* nothing to do */
		aws_lws_service_do_ripe_rxflow(pt);
	else
		if (aws__lws_plat_service_forced_tsi(context, tsi) < 0)
			return -1;

#if defined(LWS_WITH_SYS_METRICS)
	aws_lws_metric_event(context->mt_service, METRES_GO,
			 (u_mt_t) (a + (aws_lws_now_usecs() - b)));
#endif

	if (pt->destroy_self) {
		aws_lws_context_destroy(pt->context);
		return -1;
	}

	return 0;
}

int
aws_lws_plat_service(struct aws_lws_context *context, int timeout_ms)
{
	return aws__lws_plat_service_tsi(context, timeout_ms, 0);
}

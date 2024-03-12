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

#include "private-lib-core.h"
#include "private-lib-event-libs-libevent.h"

#define pt_to_priv_event(_pt) ((struct aws_lws_pt_eventlibs_libevent *)(_pt)->evlib_pt)
#define wsi_to_priv_event(_w) ((struct aws_lws_wsi_eventlibs_libevent *)(_w)->evlib_wsi)

static void
aws_lws_event_hrtimer_cb(evutil_socket_t fd, short event, void *p)
{
	struct aws_lws_context_per_thread *pt = (struct aws_lws_context_per_thread *)p;
	struct aws_lws_pt_eventlibs_libevent *ptpr = pt_to_priv_event(pt);
	struct timeval tv;
	aws_lws_usec_t us;

	aws_lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(pt->pt_sul_owner, LWS_COUNT_PT_SUL_OWNERS,
				    aws_lws_now_usecs());
	if (us) {
#if defined(__APPLE__)
		tv.tv_sec = (int)(us / LWS_US_PER_SEC);
		tv.tv_usec = (int)(us - (tv.tv_sec * LWS_US_PER_SEC));
#else
		tv.tv_sec = (long)(us / LWS_US_PER_SEC);
		tv.tv_usec = (long)(us - (tv.tv_sec * LWS_US_PER_SEC));
#endif
		evtimer_add(ptpr->hrtimer, &tv);
	}
	aws_lws_pt_unlock(pt);
}

static void
aws_lws_event_idle_timer_cb(evutil_socket_t fd, short event, void *p)
{
	struct aws_lws_context_per_thread *pt = (struct aws_lws_context_per_thread *)p;
	struct aws_lws_pt_eventlibs_libevent *ptpr = pt_to_priv_event(pt);
	struct timeval tv;
	aws_lws_usec_t us;

	if (pt->is_destroyed)
		return;

	aws_lws_service_do_ripe_rxflow(pt);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!aws_lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
		/* -1 timeout means just do forced service */
		_lws_plat_service_forced_tsi(pt->context, pt->tid);
		/* still somebody left who wants forced service? */
		if (!aws_lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
			/* yes... come back again later */

			tv.tv_sec = 0;
			tv.tv_usec = 1000;
			evtimer_add(ptpr->idle_timer, &tv);

			return;
		}
	}

	/* account for hrtimer */

	aws_lws_pt_lock(pt, __func__);
	us = __lws_sul_service_ripe(pt->pt_sul_owner, LWS_COUNT_PT_SUL_OWNERS,
				    aws_lws_now_usecs());
	if (us) {
		tv.tv_sec = (suseconds_t)(us / LWS_US_PER_SEC);
		tv.tv_usec = (suseconds_t)(us - (tv.tv_sec * LWS_US_PER_SEC));
		evtimer_add(ptpr->hrtimer, &tv);
	}
	aws_lws_pt_unlock(pt);

	if (pt->destroy_self)
		aws_lws_context_destroy(pt->context);
}

static void
aws_lws_event_cb(evutil_socket_t sock_fd, short revents, void *ctx)
{
	struct aws_lws_signal_watcher_libevent *aws_lws_io =
			(struct aws_lws_signal_watcher_libevent *)ctx;
	struct aws_lws_context *context = aws_lws_io->context;
	struct aws_lws_context_per_thread *pt;
	struct aws_lws_pollfd eventfd;
	struct timeval tv;
	struct lws *wsi;

	if (revents & EV_TIMEOUT)
		return;

	/* !!! EV_CLOSED doesn't exist in libevent2 */
#if LIBEVENT_VERSION_NUMBER < 0x02000000
	if (revents & EV_CLOSED) {
		event_del(aws_lws_io->event.watcher);
		event_free(aws_lws_io->event.watcher);
		return;
	}
#endif

	eventfd.fd = sock_fd;
	eventfd.events = 0;
	eventfd.revents = 0;
	if (revents & EV_READ) {
		eventfd.events |= LWS_POLLIN;
		eventfd.revents |= LWS_POLLIN;
	}
	if (revents & EV_WRITE) {
		eventfd.events |= LWS_POLLOUT;
		eventfd.revents |= LWS_POLLOUT;
	}

	wsi = wsi_from_fd(context, sock_fd);
	if (!wsi)
		return;

	pt = &context->pt[(int)wsi->tsi];
	if (pt->is_destroyed)
		return;

	aws_lws_service_fd_tsi(context, &eventfd, wsi->tsi);

	if (pt->destroy_self) {
		aws_lwsl_cx_notice(context, "pt destroy self coming true");
		aws_lws_context_destroy(pt->context);
		return;
	}

	/* set the idle timer for 1ms ahead */

	tv.tv_sec = 0;
	tv.tv_usec = 1000;
	evtimer_add(pt_to_priv_event(pt)->idle_timer, &tv);
}

void
aws_lws_event_sigint_cb(evutil_socket_t sock_fd, short revents, void *ctx)
{
	struct aws_lws_context_per_thread *pt = ctx;
	struct event *signal = pt_to_priv_event(pt)->w_sigint.watcher;

	if (pt->context->eventlib_signal_cb) {
		pt->context->eventlib_signal_cb((void *)(aws_lws_intptr_t)sock_fd,
						event_get_signal(signal));

		return;
	}
	if (!pt->event_loop_foreign)
		event_base_loopbreak(pt_to_priv_event(pt)->io_loop);
}

static int
elops_listen_init_event(struct aws_lws_dll2 *d, void *user)
{
	struct lws *wsi = aws_lws_container_of(d, struct lws, listen_list);
	struct aws_lws_context *context = (struct aws_lws_context *)user;
	struct aws_lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct aws_lws_pt_eventlibs_libevent *ptpr = pt_to_priv_event(pt);
	struct aws_lws_io_watcher_libevent *w_read =
					&(wsi_to_priv_event(wsi)->w_read);

	w_read->context = context;
	w_read->watcher = event_new(ptpr->io_loop, wsi->desc.sockfd,
				(EV_READ | EV_PERSIST), aws_lws_event_cb, w_read);
	event_add(w_read->watcher, NULL);
	w_read->set = 1;

	return 0;
}

static int
elops_init_pt_event(struct aws_lws_context *context, void *_loop, int tsi)
{
	struct event_base *loop = (struct event_base *)_loop;
	struct aws_lws_context_per_thread *pt = &context->pt[tsi];
	struct aws_lws_pt_eventlibs_libevent *ptpr = pt_to_priv_event(pt);

	aws_lwsl_cx_info(context, "loop %p", _loop);

	if (!loop)
		loop = event_base_new();
	else
		context->pt[tsi].event_loop_foreign = 1;

	if (!loop) {
		aws_lwsl_cx_err(context, "creating event base failed");

		return -1;
	}

	ptpr->io_loop = loop;

	aws_lws_vhost_foreach_listen_wsi(context, context, elops_listen_init_event);

	/* static event loop objects */

	ptpr->hrtimer = event_new(loop, -1, EV_PERSIST,
				      aws_lws_event_hrtimer_cb, pt);

	ptpr->idle_timer = event_new(loop, -1, 0,
					 aws_lws_event_idle_timer_cb, pt);
	{
		struct timeval tv;
		tv.tv_sec = (long)0;
		tv.tv_usec = (long)1000;
		evtimer_add(ptpr->hrtimer, &tv);
	}

	/* Register the signal watcher unless it's a foreign loop */

	if (pt->event_loop_foreign)
		return 0;

	ptpr->w_sigint.watcher = evsignal_new(loop, SIGINT,
						  aws_lws_event_sigint_cb, pt);
	event_add(ptpr->w_sigint.watcher, NULL);

	return 0;
}

static int
elops_init_context_event(struct aws_lws_context *context,
			 const struct aws_lws_context_creation_info *info)
{
	int n;

	context->eventlib_signal_cb = info->signal_cb;

	for (n = 0; n < context->count_threads; n++)
		pt_to_priv_event(&context->pt[n])->w_sigint.context = context;

	return 0;
}

static int
elops_accept_event(struct lws *wsi)
{
	struct aws_lws_context *context = aws_lws_get_context(wsi);
	struct aws_lws_context_per_thread *pt;
	struct aws_lws_pt_eventlibs_libevent *ptpr;
	struct aws_lws_wsi_eventlibs_libevent *wpr = wsi_to_priv_event(wsi);
       evutil_socket_t fd;

	wpr->w_read.context = context;
	wpr->w_write.context = context;

	// Initialize the event
	pt = &context->pt[(int)wsi->tsi];
	ptpr = pt_to_priv_event(pt);

	if (wsi->role_ops->file_handle)
               fd = (evutil_socket_t)(ev_intptr_t) wsi->desc.filefd;
	else
		fd = wsi->desc.sockfd;

	wpr->w_read.watcher = event_new(ptpr->io_loop, fd,
			(EV_READ | EV_PERSIST), aws_lws_event_cb, &wpr->w_read);
	wpr->w_write.watcher = event_new(ptpr->io_loop, fd,
			(EV_WRITE | EV_PERSIST), aws_lws_event_cb, &wpr->w_write);

	return 0;
}

static void
elops_io_event(struct lws *wsi, unsigned int flags)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	struct aws_lws_pt_eventlibs_libevent *ptpr = pt_to_priv_event(pt);
	struct aws_lws_wsi_eventlibs_libevent *wpr = wsi_to_priv_event(wsi);

	if (!ptpr->io_loop || wsi->a.context->being_destroyed ||
	    pt->is_destroyed)
		return;

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	if (flags & LWS_EV_START) {
		if ((flags & LWS_EV_WRITE) && !wpr->w_write.set) {
			event_add(wpr->w_write.watcher, NULL);
			wpr->w_write.set = 1;
		}

		if ((flags & LWS_EV_READ) && !wpr->w_read.set) {
			event_add(wpr->w_read.watcher, NULL);
			wpr->w_read.set = 1;
		}
	} else {
		if ((flags & LWS_EV_WRITE) && wpr->w_write.set) {
			event_del(wpr->w_write.watcher);
			wpr->w_write.set = 0;
		}

		if ((flags & LWS_EV_READ) && wpr->w_read.set) {
			event_del(wpr->w_read.watcher);
			wpr->w_read.set = 0;
		}
	}
}

static void
elops_run_pt_event(struct aws_lws_context *context, int tsi)
{
	/* Run / Dispatch the event_base loop */
	if (pt_to_priv_event(&context->pt[tsi])->io_loop)
		event_base_dispatch(
			pt_to_priv_event(&context->pt[tsi])->io_loop);
}

static int
elops_listen_destroy_event(struct aws_lws_dll2 *d, void *user)
{
	struct lws *wsi = aws_lws_container_of(d, struct lws, listen_list);
	struct aws_lws_wsi_eventlibs_libevent *w = wsi_to_priv_event(wsi);

	event_free(w->w_read.watcher);
	w->w_read.watcher = NULL;
	event_free(w->w_write.watcher);
	w->w_write.watcher = NULL;

	return 0;
}

static void
elops_destroy_pt_event(struct aws_lws_context *context, int tsi)
{
	struct aws_lws_context_per_thread *pt = &context->pt[tsi];
	struct aws_lws_pt_eventlibs_libevent *ptpr = pt_to_priv_event(pt);

	if (!ptpr->io_loop)
		return;

	aws_lws_vhost_foreach_listen_wsi(context, context, elops_listen_destroy_event);

	event_free(ptpr->hrtimer);
	event_free(ptpr->idle_timer);

	if (!pt->event_loop_foreign) {
		event_del(ptpr->w_sigint.watcher);
		event_free(ptpr->w_sigint.watcher);
		event_base_loopexit(ptpr->io_loop, NULL);
	//	event_base_free(pt->event.io_loop);
	//	pt->event.io_loop = NULL;
		aws_lwsl_cx_notice(context, "set to exit loop");
	}
}

static void
elops_destroy_wsi_event(struct lws *wsi)
{
	struct aws_lws_context_per_thread *pt;
	struct aws_lws_wsi_eventlibs_libevent *w;

	if (!wsi)
		return;

	pt = &wsi->a.context->pt[(int)wsi->tsi];
	if (pt->is_destroyed)
		return;

	w = wsi_to_priv_event(wsi);

	if (w->w_read.watcher) {
		event_free(w->w_read.watcher);
		w->w_read.watcher = NULL;
	}

	if (w->w_write.watcher) {
		event_free(w->w_write.watcher);
		w->w_write.watcher = NULL;
	}
}

static int
elops_wsi_logical_close_event(struct lws *wsi)
{
	elops_destroy_wsi_event(wsi);

	return 0;
}

static int
elops_init_vhost_listen_wsi_event(struct lws *wsi)
{
	struct aws_lws_context_per_thread *pt;
	struct aws_lws_pt_eventlibs_libevent *ptpr;
	struct aws_lws_wsi_eventlibs_libevent *w;
       evutil_socket_t fd;

	if (!wsi) {
		assert(0);
		return 0;
	}

	w = wsi_to_priv_event(wsi);

	w->w_read.context = wsi->a.context;
	w->w_write.context = wsi->a.context;

	pt = &wsi->a.context->pt[(int)wsi->tsi];
	ptpr = pt_to_priv_event(pt);

	if (wsi->role_ops->file_handle)
               fd = (evutil_socket_t) wsi->desc.filefd;
	else
		fd = wsi->desc.sockfd;

	w->w_read.watcher = event_new(ptpr->io_loop, fd, (EV_READ | EV_PERSIST),
				      aws_lws_event_cb, &w->w_read);
	w->w_write.watcher = event_new(ptpr->io_loop, fd,
				       (EV_WRITE | EV_PERSIST),
				       aws_lws_event_cb, &w->w_write);

	elops_io_event(wsi, LWS_EV_START | LWS_EV_READ);

	return 0;
}

static int
elops_destroy_context2_event(struct aws_lws_context *context)
{
	struct aws_lws_context_per_thread *pt;
	struct aws_lws_pt_eventlibs_libevent *ptpr;
	int n, m;

	for (n = 0; n < context->count_threads; n++) {
		int budget = 1000;

		pt = &context->pt[n];
		ptpr = pt_to_priv_event(pt);

		/* only for internal loops... */

		if (pt->event_loop_foreign || !ptpr->io_loop)
			continue;

		if (!context->evlib_finalize_destroy_after_int_loops_stop) {
			event_base_loopexit(ptpr->io_loop, NULL);
			continue;
		}
		while (budget-- &&
		       (m = event_base_loop(ptpr->io_loop, EVLOOP_NONBLOCK)))
			;

		aws_lwsl_cx_info(context, "event_base_free");

		event_base_free(ptpr->io_loop);
		ptpr->io_loop = NULL;
	}

	return 0;
}

static const struct aws_lws_event_loop_ops event_loop_ops_event = {
	/* name */			"libevent",
	/* init_context */		elops_init_context_event,
	/* destroy_context1 */		NULL,
	/* destroy_context2 */		elops_destroy_context2_event,
	/* init_vhost_listen_wsi */	elops_init_vhost_listen_wsi_event,
	/* init_pt */			elops_init_pt_event,
	/* wsi_logical_close */		elops_wsi_logical_close_event,
	/* check_client_connect_ok */	NULL,
	/* close_handle_manually */	NULL,
	/* accept */			elops_accept_event,
	/* io */			elops_io_event,
	/* run_pt */			elops_run_pt_event,
	/* destroy_pt */		elops_destroy_pt_event,
	/* destroy wsi */		elops_destroy_wsi_event,
	/* foreign_thread */		NULL,

	/* flags */			0,

	/* evlib_size_ctx */	0,
	/* evlib_size_pt */	sizeof(struct aws_lws_pt_eventlibs_libevent),
	/* evlib_size_vh */	0,
	/* evlib_size_wsi */	sizeof(struct aws_lws_wsi_eventlibs_libevent),
};

#if defined(LWS_WITH_EVLIB_PLUGINS)
LWS_VISIBLE
#endif
const aws_lws_plugin_evlib_t evlib_event = {
	.hdr = {
		"libevent event loop",
		"aws_lws_evlib_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.ops	= &event_loop_ops_event
};

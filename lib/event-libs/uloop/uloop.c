/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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
#include "private-lib-event-libs-uloop.h"

#define pt_to_priv_uloop(_pt) ((struct aws_lws_pt_eventlibs_uloop *)(_pt)->evlib_pt)
#define wsi_to_priv_uloop(_w) ((struct aws_lws_wsi_eventlibs_uloop *)(_w)->evlib_wsi)

static void
aws_lws_uloop_hrtimer_cb(struct uloop_timeout *ti)
{
	struct aws_lws_pt_eventlibs_uloop *upt = aws_lws_container_of(ti,
					struct aws_lws_pt_eventlibs_uloop, hrtimer);
	struct aws_lws_context_per_thread *pt = upt->pt;
	aws_lws_usec_t us;

	aws_lws_pt_lock(pt, __func__);
	us = aws___lws_sul_service_ripe(pt->pt_sul_owner, LWS_COUNT_PT_SUL_OWNERS,
				    aws_lws_now_usecs());
	if (us)
		uloop_timeout_set(ti, us < 1000 ? 1 : (int)(us / 1000));

	aws_lws_pt_unlock(pt);
}

static void
aws_lws_uloop_idle_timer_cb(struct uloop_timeout *ti)
{
	struct aws_lws_pt_eventlibs_uloop *upt = aws_lws_container_of(ti,
						struct aws_lws_pt_eventlibs_uloop,
						idle_timer);
	struct aws_lws_context_per_thread *pt = upt->pt;
	aws_lws_usec_t us;

	if (pt->is_destroyed)
		return;

	aws_lws_service_do_ripe_rxflow(pt);

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (!aws_lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
		/* -1 timeout means just do forced service */
		aws__lws_plat_service_forced_tsi(pt->context, pt->tid);
		/* still somebody left who wants forced service? */
		if (!aws_lws_service_adjust_timeout(pt->context, 1, pt->tid)) {
			/* yes... come back again later */

			uloop_timeout_set(ti, 1 /* 1ms */);

			return;
		}
	}

	/* account for hrtimer */

	aws_lws_pt_lock(pt, __func__);
	us = aws___lws_sul_service_ripe(pt->pt_sul_owner, LWS_COUNT_PT_SUL_OWNERS,
				    aws_lws_now_usecs());
	if (us) {
		uloop_timeout_cancel(&upt->hrtimer);
		uloop_timeout_set(&upt->hrtimer,
				  us < 1000 ? 1 : (int)(us / 1000));
	}

	aws_lws_pt_unlock(pt);

	if (pt->destroy_self)
		aws_lws_context_destroy(pt->context);
}

static void
aws_lws_uloop_cb(struct uloop_fd *ufd, unsigned int revents)
{
	struct aws_lws_wsi_eventlibs_uloop *wu = aws_lws_container_of(ufd,
					struct aws_lws_wsi_eventlibs_uloop, fd);
	struct aws_lws_context *context = wu->wsi->a.context;
	struct aws_lws_context_per_thread *pt;
	struct aws_lws_pollfd eventfd;

	eventfd.fd = wu->wsi->desc.sockfd;
	eventfd.events = 0;
	eventfd.revents = 0;

	if (revents & ULOOP_READ) {
		eventfd.events = LWS_POLLIN;
		eventfd.revents = LWS_POLLIN;
	}
	if (revents & ULOOP_WRITE) {
		eventfd.events |= LWS_POLLOUT;
		eventfd.revents |= LWS_POLLOUT;
	}

	pt = &context->pt[(int)wu->wsi->tsi];
	if (pt->is_destroyed)
		return;

	aws_lws_service_fd_tsi(context, &eventfd, wu->wsi->tsi);

	if (pt->destroy_self) {
		aws_lwsl_cx_notice(context, "pt destroy self coming true");
		aws_lws_context_destroy(pt->context);
		return;
	}

	/* set the idle timer for 1ms ahead */

	uloop_timeout_cancel(&pt_to_priv_uloop(pt)->idle_timer);
	uloop_timeout_set(&pt_to_priv_uloop(pt)->idle_timer, 1);
}

static int
elops_listen_init_uloop(struct aws_lws_dll2 *d, void *user)
{
	struct aws_lws *wsi = aws_lws_container_of(d, struct aws_lws, listen_list);
	struct aws_lws_wsi_eventlibs_uloop *wu = wsi_to_priv_uloop(wsi);

	wu->wsi = wsi;
	wu->fd.fd = wsi->desc.sockfd;
	wu->fd.cb = aws_lws_uloop_cb;
	uloop_fd_add(&wu->fd,  ULOOP_READ);
	wu->actual_events = ULOOP_READ;

	return 0;
}

static int
elops_init_pt_uloop(struct aws_lws_context *context, void *v, int tsi)
{
	struct aws_lws_context_per_thread *pt = &context->pt[tsi];
	struct aws_lws_pt_eventlibs_uloop *ptpr = pt_to_priv_uloop(pt);

	ptpr->pt = pt;

	aws_lws_vhost_foreach_listen_wsi(context, NULL, elops_listen_init_uloop);

	/* static event loop objects */

	ptpr->hrtimer.cb = aws_lws_uloop_hrtimer_cb;
	ptpr->idle_timer.cb = aws_lws_uloop_idle_timer_cb;

	uloop_timeout_add(&ptpr->hrtimer);
	uloop_timeout_add(&ptpr->idle_timer);

	uloop_timeout_set(&ptpr->hrtimer, 1);

	return 0;
}

static int
elops_accept_uloop(struct aws_lws *wsi)
{
	struct aws_lws_wsi_eventlibs_uloop *wu = wsi_to_priv_uloop(wsi);

	wu->wsi = wsi;
	wu->fd.fd = wsi->desc.sockfd;
	wu->fd.cb = aws_lws_uloop_cb;
	uloop_fd_add(&wu->fd, ULOOP_READ);
	wu->actual_events = ULOOP_READ;

	return 0;
}

static void
elops_io_uloop(struct aws_lws *wsi, unsigned int flags)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	struct aws_lws_wsi_eventlibs_uloop *wu = wsi_to_priv_uloop(wsi);
	unsigned int ulf = (unsigned int)(((flags & LWS_EV_WRITE) ? ULOOP_WRITE : 0) |
			    ((flags & LWS_EV_READ) ? ULOOP_READ : 0)), u;

	if (wsi->a.context->being_destroyed || pt->is_destroyed)
		return;

	assert((flags & (LWS_EV_START | LWS_EV_STOP)) &&
	       (flags & (LWS_EV_READ | LWS_EV_WRITE)));

	u = wu->actual_events;
	if (flags & LWS_EV_START)
		u |= ulf;
	if (flags & LWS_EV_STOP)
		u &= ~ulf;

	uloop_fd_add(&wu->fd, u);
	wu->actual_events = u;
}

static void
elops_run_pt_uloop(struct aws_lws_context *context, int tsi)
{
	uloop_run();
}

static int
elops_listen_destroy_uloop(struct aws_lws_dll2 *d, void *user)
{
	struct aws_lws *wsi = aws_lws_container_of(d, struct aws_lws, listen_list);
	struct aws_lws_wsi_eventlibs_uloop *wu = wsi_to_priv_uloop(wsi);

	uloop_fd_delete(&wu->fd);

	return 0;
}

static void
elops_destroy_pt_uloop(struct aws_lws_context *context, int tsi)
{
	struct aws_lws_context_per_thread *pt = &context->pt[tsi];
	struct aws_lws_pt_eventlibs_uloop *ptpr = pt_to_priv_uloop(pt);

	aws_lws_vhost_foreach_listen_wsi(context, NULL, elops_listen_destroy_uloop);

	uloop_timeout_cancel(&ptpr->hrtimer);
	uloop_timeout_cancel(&ptpr->idle_timer);
}

static void
elops_destroy_wsi_uloop(struct aws_lws *wsi)
{
	struct aws_lws_context_per_thread *pt;

	if (!wsi)
		return;

	pt = &wsi->a.context->pt[(int)wsi->tsi];
	if (pt->is_destroyed)
		return;

	uloop_fd_delete(&wsi_to_priv_uloop(wsi)->fd);
}

static int
elops_wsi_logical_close_uloop(struct aws_lws *wsi)
{
	elops_destroy_wsi_uloop(wsi);

	return 0;
}

static int
elops_init_vhost_listen_wsi_uloop(struct aws_lws *wsi)
{
	struct aws_lws_wsi_eventlibs_uloop *wu;

	if (!wsi) {
		assert(0);
		return 0;
	}

	wu = wsi_to_priv_uloop(wsi);
	wu->wsi = wsi;
	wu->fd.fd = wsi->desc.sockfd;
	wu->fd.cb = aws_lws_uloop_cb;
	uloop_fd_add(&wu->fd,  ULOOP_READ);

	wu->actual_events = ULOOP_READ;

	return 0;
}

static const struct aws_lws_event_loop_ops event_loop_ops_uloop = {
	/* name */			"uloop",
	/* init_context */		NULL,
	/* destroy_context1 */		NULL,
	/* destroy_context2 */		NULL,
	/* init_vhost_listen_wsi */	elops_init_vhost_listen_wsi_uloop,
	/* init_pt */			elops_init_pt_uloop,
	/* wsi_logical_close */		elops_wsi_logical_close_uloop,
	/* check_client_connect_ok */	NULL,
	/* close_handle_manually */	NULL,
	/* accept */			elops_accept_uloop,
	/* io */			elops_io_uloop,
	/* run_pt */			elops_run_pt_uloop,
	/* destroy_pt */		elops_destroy_pt_uloop,
	/* destroy wsi */		elops_destroy_wsi_uloop,
	/* foreign_thread */		NULL,

	/* flags */			0,

	/* evlib_size_ctx */	0,
	/* evlib_size_pt */	sizeof(struct aws_lws_pt_eventlibs_uloop),
	/* evlib_size_vh */	0,
	/* evlib_size_wsi */	sizeof(struct aws_lws_wsi_eventlibs_uloop),
};

#if defined(LWS_WITH_EVLIB_PLUGINS)
LWS_VISIBLE
#endif
const aws_lws_plugin_evlib_t evlib_uloop = {
	.hdr = {
		"uloop event loop",
		"aws_lws_evlib_plugin",
		LWS_BUILD_HASH,
		LWS_PLUGIN_API_MAGIC
	},

	.ops	= &event_loop_ops_uloop
};

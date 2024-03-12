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

void
aws___lws_wsi_remove_from_sul(struct lws *wsi)
{
	aws_lws_sul_cancel(&wsi->sul_timeout);
	aws_lws_sul_cancel(&wsi->sul_hrtimer);
	aws_lws_sul_cancel(&wsi->sul_validity);
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	aws_lws_sul_cancel(&wsi->sul_fault_timedclose);
#endif
}

/*
 * hrtimer
 */

static void
aws_lws_sul_hrtimer_cb(aws_lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = aws_lws_container_of(sul, struct lws, sul_hrtimer);

	if (wsi->a.protocol &&
	    wsi->a.protocol->callback(wsi, LWS_CALLBACK_TIMER,
				    wsi->user_space, NULL, 0))
		aws___lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				     "hrtimer cb errored");
}

void
aws___lws_set_timer_usecs(struct lws *wsi, aws_lws_usec_t us)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	wsi->sul_hrtimer.cb = aws_lws_sul_hrtimer_cb;
	aws___lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &wsi->sul_hrtimer, us);
}

void
aws_lws_set_timer_usecs(struct lws *wsi, aws_lws_usec_t usecs)
{
	aws___lws_set_timer_usecs(wsi, usecs);
}

/*
 * wsi timeout
 */

static void
aws_lws_sul_wsitimeout_cb(aws_lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = aws_lws_container_of(sul, struct lws, sul_timeout);
	struct aws_lws_context *cx = wsi->a.context;
	struct aws_lws_context_per_thread *pt = &cx->pt[(int)wsi->tsi];

	/* no need to log normal idle keepalive timeout */
//		if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (wsi->pending_timeout != PENDING_TIMEOUT_USER_OK)
		aws_lwsl_wsi_info(wsi, "TIMEDOUT WAITING %d, dhdr %d, ah %p, wl %d",
				   wsi->pending_timeout,
				   wsi->hdr_parsing_completed, wsi->http.ah,
				   pt->http.ah_wait_list_length);
#if defined(LWS_WITH_CGI)
	if (wsi->http.cgi)
		aws_lwsl_wsi_notice(wsi, "CGI timeout: %s", wsi->http.cgi->summary);
#endif
#else
	if (wsi->pending_timeout != PENDING_TIMEOUT_USER_OK)
		aws_lwsl_wsi_info(wsi, "TIMEDOUT WAITING on %d ",
				   wsi->pending_timeout);
#endif
	/* cgi timeout */
	if (wsi->pending_timeout != PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE)
		/*
		 * Since he failed a timeout, he already had a chance to
		 * do something and was unable to... that includes
		 * situations like half closed connections.  So process
		 * this "failed timeout" close as a violent death and
		 * don't try to do protocol cleanup like flush partials.
		 */
		wsi->socket_is_permanently_unusable = 1;
#if defined(LWS_WITH_CLIENT)
	if (aws_lwsi_state(wsi) == LRS_WAITING_SSL)
		aws_lws_inform_client_conn_fail(wsi,
			(void *)"Timed out waiting SSL", 21);
	if (aws_lwsi_state(wsi) == LRS_WAITING_SERVER_REPLY)
		aws_lws_inform_client_conn_fail(wsi,
			(void *)"Timed out waiting server reply", 30);
#endif

	aws_lws_context_lock(cx, __func__);
	aws_lws_pt_lock(pt, __func__);
	aws___lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "timeout");
	aws_lws_pt_unlock(pt);
	aws_lws_context_unlock(cx);
}

void
aws___lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	wsi->sul_timeout.cb = aws_lws_sul_wsitimeout_cb;
	aws___lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &wsi->sul_timeout,
			    ((aws_lws_usec_t)secs) * LWS_US_PER_SEC);

	aws_lwsl_wsi_debug(wsi, "%d secs, reason %d\n", secs, reason);

	wsi->pending_timeout = (char)reason;
}

void
aws_lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	aws_lws_context_lock(pt->context, __func__);
	aws_lws_pt_lock(pt, __func__);
	aws_lws_dll2_remove(&wsi->sul_timeout.list);
	aws_lws_pt_unlock(pt);

	if (!secs)
		goto bail;

	if (secs == LWS_TO_KILL_SYNC) {
		aws_lwsl_wsi_debug(wsi, "TO_KILL_SYNC");
		aws_lws_context_unlock(pt->context);
		aws_lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				   "to sync kill");
		return;
	}

	if (secs == LWS_TO_KILL_ASYNC)
		secs = 0;

	// assert(!secs || !wsi->mux_stream_immortal);
	if (secs && wsi->mux_stream_immortal)
		aws_lwsl_wsi_err(wsi, "on immortal stream %d %d", reason, secs);

	aws_lws_pt_lock(pt, __func__);
	aws___lws_set_timeout(wsi, reason, secs);
	aws_lws_pt_unlock(pt);

bail:
	aws_lws_context_unlock(pt->context);
}

void
aws_lws_set_timeout_us(struct lws *wsi, enum pending_timeout reason, aws_lws_usec_t us)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	aws_lws_pt_lock(pt, __func__);
	aws_lws_dll2_remove(&wsi->sul_timeout.list);
	aws_lws_pt_unlock(pt);

	if (!us)
		return;

	aws_lws_pt_lock(pt, __func__);
	aws___lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &wsi->sul_timeout, us);

	aws_lwsl_wsi_notice(wsi, "%llu us, reason %d",
			     (unsigned long long)us, reason);

	wsi->pending_timeout = (char)reason;
	aws_lws_pt_unlock(pt);
}

static void
aws_lws_validity_cb(aws_lws_sorted_usec_list_t *sul)
{
	struct lws *wsi = aws_lws_container_of(sul, struct lws, sul_validity);
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const aws_lws_retry_bo_t *rbo = wsi->retry_policy;

	/* one of either the ping or hangup validity threshold was crossed */

	if (wsi->validity_hup) {
		aws_lwsl_wsi_info(wsi, "validity too old");
		struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

		aws_lws_context_lock(wsi->a.context, __func__);
		aws_lws_pt_lock(pt, __func__);
		aws___lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
				     "validity timeout");
		aws_lws_pt_unlock(pt);
		aws_lws_context_unlock(wsi->a.context);
		return;
	}

	/* schedule a protocol-dependent ping */

	aws_lwsl_wsi_info(wsi, "scheduling validity check");

	if (aws_lws_rops_fidx(wsi->role_ops, LWS_ROPS_issue_keepalive))
		aws_lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_issue_keepalive).
							issue_keepalive(wsi, 0);

	/*
	 * We arrange to come back here after the additional ping to hangup time
	 * and do the hangup, unless we get validated (by, eg, a PONG) and
	 * reset the timer
	 */

	assert(rbo->secs_since_valid_hangup > rbo->secs_since_valid_ping);

	wsi->validity_hup = 1;
	aws___lws_sul_insert_us(&pt->pt_sul_owner[!!wsi->conn_validity_wakesuspend],
			    &wsi->sul_validity,
			    ((uint64_t)rbo->secs_since_valid_hangup -
				 rbo->secs_since_valid_ping) * LWS_US_PER_SEC);
}

/*
 * The role calls this back to actually confirm validity on a particular wsi
 * (which may not be the original wsi)
 */

void
aws__lws_validity_confirmed_role(struct lws *wsi)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const aws_lws_retry_bo_t *rbo = wsi->retry_policy;

	if (!rbo || !rbo->secs_since_valid_hangup)
		return;

	wsi->validity_hup = 0;
	wsi->sul_validity.cb = aws_lws_validity_cb;

	wsi->validity_hup = rbo->secs_since_valid_ping >=
			    rbo->secs_since_valid_hangup;

	aws_lwsl_wsi_info(wsi, "setting validity timer %ds (hup %d)",
			   wsi->validity_hup ? rbo->secs_since_valid_hangup :
					    rbo->secs_since_valid_ping,
			   wsi->validity_hup);

	aws___lws_sul_insert_us(&pt->pt_sul_owner[!!wsi->conn_validity_wakesuspend],
			    &wsi->sul_validity,
			    ((uint64_t)(wsi->validity_hup ?
				rbo->secs_since_valid_hangup :
				rbo->secs_since_valid_ping)) * LWS_US_PER_SEC);
}

void
aws_lws_validity_confirmed(struct lws *wsi)
{
	/*
	 * This may be a stream inside a muxed network connection... leave it
	 * to the role to figure out who actually needs to understand their
	 * validity was confirmed.
	 */
	if (!wsi->h2_stream_carries_ws && /* only if not encapsulated */
	    wsi->role_ops &&
	    aws_lws_rops_fidx(wsi->role_ops, LWS_ROPS_issue_keepalive))
		aws_lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_issue_keepalive).
							issue_keepalive(wsi, 1);
}

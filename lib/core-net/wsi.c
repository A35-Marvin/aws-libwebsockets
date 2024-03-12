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

const char *
aws_lws_wsi_tag(struct aws_lws *wsi)
{
	if (!wsi)
		return "[null wsi]";
	return aws_lws_lc_tag(&wsi->lc);
}

#if defined (_DEBUG)
void aws_lwsi_set_role(struct aws_lws *wsi, aws_lws_wsi_state_t role)
{
	wsi->wsistate = (wsi->wsistate & (~LWSI_ROLE_MASK)) | role;

	aws_lwsl_wsi_debug(wsi, "state 0x%lx", (unsigned long)wsi->wsistate);
}

void aws_lwsi_set_state(struct aws_lws *wsi, aws_lws_wsi_state_t lrs)
{
	aws_lws_wsi_state_t old = wsi->wsistate;

	wsi->wsistate = (old & (unsigned int)(~LRS_MASK)) | lrs;

	aws_lwsl_wsi_debug(wsi, "aws_lwsi_set_state 0x%lx -> 0x%lx",
			(unsigned long)old, (unsigned long)wsi->wsistate);
}
#endif


void
aws_lws_log_prepend_wsi(struct aws_lws_log_cx *cx, void *obj, char **p, char *e)
{
	struct aws_lws *wsi = (struct aws_lws *)obj;

	*p += aws_lws_snprintf(*p, aws_lws_ptr_diff_size_t(e, (*p)), "%s: ",
							aws_lws_wsi_tag(wsi));
}

void
aws_lws_vhost_bind_wsi(struct aws_lws_vhost *vh, struct aws_lws *wsi)
{
	if (wsi->a.vhost == vh)
		return;

	aws_lws_context_lock(vh->context, __func__); /* ---------- context { */
	wsi->a.vhost = vh;

#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (!vh->count_bound_wsi && vh->grace_after_unref) {
		aws_lwsl_wsi_info(wsi, "in use");
		aws_lws_sul_cancel(&vh->sul_unref);
	}
#endif

	vh->count_bound_wsi++;
	aws_lws_context_unlock(vh->context); /* } context ---------- */

	aws_lwsl_wsi_debug(wsi, "vh %s: wsi %s/%s, count_bound_wsi %d\n",
		   vh->name, wsi->role_ops ? wsi->role_ops->name : "none",
		   wsi->a.protocol ? wsi->a.protocol->name : "none",
		   vh->count_bound_wsi);
	assert(wsi->a.vhost->count_bound_wsi > 0);
}


/* req cx lock... acquires vh lock */
void
aws___lws_vhost_unbind_wsi(struct aws_lws *wsi)
{
        struct aws_lws_vhost *vh = wsi->a.vhost;

        if (!vh)
                return;

	aws_lws_context_assert_lock_held(wsi->a.context);

	aws_lws_vhost_lock(vh);

	assert(vh->count_bound_wsi > 0);
	vh->count_bound_wsi--;

#if defined(LWS_WITH_TLS_JIT_TRUST)
	if (!vh->count_bound_wsi && vh->grace_after_unref)
		aws_lws_tls_jit_trust_vh_start_grace(vh);
#endif

	aws_lwsl_wsi_debug(wsi, "vh %s: count_bound_wsi %d",
		   vh->name, vh->count_bound_wsi);

	aws_lws_vhost_unlock(vh);

	if (!vh->count_bound_wsi && vh->being_destroyed)
		/*
		 * We have closed all wsi that were bound to this vhost
		 * by any pt: nothing can be servicing any wsi belonging
		 * to it any more.
		 *
		 * Finalize the vh destruction... must drop vh lock
		 */
		aws___lws_vhost_destroy2(vh);

	wsi->a.vhost = NULL;
}

struct aws_lws *
aws_lws_get_network_wsi(struct aws_lws *wsi)
{
	if (!wsi)
		return NULL;

#if defined(LWS_WITH_HTTP2) || defined(LWS_ROLE_MQTT)
	if (!wsi->mux_substream
#if defined(LWS_WITH_CLIENT)
			&& !wsi->client_mux_substream
#endif
	)
		return wsi;

	while (wsi->mux.parent_wsi)
		wsi = wsi->mux.parent_wsi;
#endif

	return wsi;
}


const struct aws_lws_protocols *
aws_lws_vhost_name_to_protocol(struct aws_lws_vhost *vh, const char *name)
{
	int n;

	for (n = 0; n < vh->count_protocols; n++)
		if (vh->protocols[n].name && !strcmp(name, vh->protocols[n].name))
			return &vh->protocols[n];

	return NULL;
}

int
aws_lws_callback_all_protocol(struct aws_lws_context *context,
			  const struct aws_lws_protocols *protocol, int reason)
{
	struct aws_lws_context_per_thread *pt = &context->pt[0];
	unsigned int n, m = context->count_threads;
	struct aws_lws *wsi;

	while (m--) {
		for (n = 0; n < pt->fds_count; n++) {
			wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->a.protocol == protocol)
				protocol->callback(wsi,
					(enum aws_lws_callback_reasons)reason,
					wsi->user_space, NULL, 0);
		}
		pt++;
	}

	return 0;
}

void *
aws_lws_evlib_wsi_to_evlib_pt(struct aws_lws *wsi)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

	return pt->evlib_pt;
}

void *
aws_lws_evlib_tsi_to_evlib_pt(struct aws_lws_context *cx, int tsi)
{
	struct aws_lws_context_per_thread *pt = &cx->pt[tsi];

	return pt->evlib_pt;
}

int
aws_lws_callback_all_protocol_vhost_args(struct aws_lws_vhost *vh,
			  const struct aws_lws_protocols *protocol, int reason,
			  void *argp, size_t len)
{
	struct aws_lws_context *context = vh->context;
	struct aws_lws_context_per_thread *pt = &context->pt[0];
	unsigned int n, m = context->count_threads;
	struct aws_lws *wsi;

	while (m--) {
		for (n = 0; n < pt->fds_count; n++) {
			wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->a.vhost == vh && (wsi->a.protocol == protocol ||
						 !protocol))
				wsi->a.protocol->callback(wsi, (enum aws_lws_callback_reasons)reason,
						wsi->user_space, argp, len);
		}
		pt++;
	}

	return 0;
}

int
aws_lws_callback_all_protocol_vhost(struct aws_lws_vhost *vh,
			  const struct aws_lws_protocols *protocol, int reason)
{
	return aws_lws_callback_all_protocol_vhost_args(vh, protocol, reason, NULL, 0);
}

int
aws_lws_callback_vhost_protocols(struct aws_lws *wsi, int reason, void *in, size_t len)
{
	int n;

	for (n = 0; n < wsi->a.vhost->count_protocols; n++)
		if (wsi->a.vhost->protocols[n].callback(wsi, (enum aws_lws_callback_reasons)reason, NULL, in, len))
			return 1;

	return 0;
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
/*
 * We want to inject a fault that makes it feel like the peer hung up on us,
 * or we were otherwise cut off.
 */
void
aws_lws_wsi_fault_timedclose_cb(aws_lws_sorted_usec_list_t *s)
{
	struct aws_lws *wsi = aws_lws_container_of(s, struct aws_lws, sul_fault_timedclose);

	aws_lwsl_wsi_warn(wsi, "force-closing");
	aws_lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
}
#endif

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
void
aws_lws_wsi_fault_timedclose(struct aws_lws *wsi)
{
	uint64_t u;

	if (!aws_lws_fi(&wsi->fic, "timedclose"))
		return;

	if (aws_lws_fi_range(&wsi->fic, "timedclose_ms", &u))
		return;

	aws_lwsl_wsi_warn(wsi, "injecting close in %ums", (unsigned int)u);
	aws_lws_sul_schedule(wsi->a.context, wsi->tsi, &wsi->sul_fault_timedclose,
			 aws_lws_wsi_fault_timedclose_cb,
			 (aws_lws_usec_t)(u * 1000ull));
}
#endif


/*
 * We need the context lock
 */

struct aws_lws *
aws___lws_wsi_create_with_role(struct aws_lws_context *context, int tsi,
			   const struct aws_lws_role_ops *ops,
			   aws_lws_log_cx_t *log_cx_template)
{
	size_t s = sizeof(struct aws_lws);
	struct aws_lws *wsi;

	assert(tsi >= 0 && tsi < LWS_MAX_SMP);

	aws_lws_context_assert_lock_held(context);

#if defined(LWS_WITH_EVENT_LIBS)
	s += context->event_loop_ops->evlib_size_wsi;
#endif

	wsi = aws_lws_zalloc(s, __func__);

	if (!wsi) {
		aws_lwsl_cx_err(context, "OOM");
		return NULL;
	}

	if (log_cx_template)
		wsi->lc.log_cx = log_cx_template;
	else
		wsi->lc.log_cx = context->log_cx;

#if defined(LWS_WITH_EVENT_LIBS)
	wsi->evlib_wsi = (uint8_t *)wsi + sizeof(*wsi);
#endif
	wsi->a.context = context;
	aws_lws_role_transition(wsi, 0, LRS_UNCONNECTED, ops);
	wsi->pending_timeout = NO_PENDING_TIMEOUT;
	wsi->a.protocol = NULL;
	wsi->tsi = (char)tsi;
	wsi->a.vhost = NULL;
	wsi->desc.sockfd = LWS_SOCK_INVALID;
	wsi->position_in_fds_table = LWS_NO_FDS_POS;

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	aws_lws_xos_init(&wsi->fic.xos, aws_lws_xos(&context->fic.xos));
#endif

	aws_lws_fi_inherit_copy(&wsi->fic, &context->fic, "wsi", NULL);

	if (aws_lws_fi(&wsi->fic, "createfail")) {
		aws_lws_fi_destroy(&wsi->fic);
		aws_lws_free(wsi);
		return NULL;
	}

	return wsi;
}

int
aws_lws_wsi_inject_to_loop(struct aws_lws_context_per_thread *pt, struct aws_lws *wsi)
{
	int ret = 1;

	aws_lws_pt_lock(pt, __func__); /* -------------- pt { */

	if (pt->context->event_loop_ops->sock_accept)
		if (pt->context->event_loop_ops->sock_accept(wsi))
			goto bail;

	if (aws___insert_wsi_socket_into_fds(pt->context, wsi))
		goto bail;

	ret = 0;

bail:
	aws_lws_pt_unlock(pt);

	return ret;
}

/*
 * Take a copy of wsi->desc.sockfd before calling this, then close it
 * afterwards
 */

int
aws_lws_wsi_extract_from_loop(struct aws_lws *wsi)
{
	if (aws_lws_socket_is_valid(wsi->desc.sockfd))
		aws___remove_wsi_socket_from_fds(wsi);

	if (!wsi->a.context->event_loop_ops->destroy_wsi &&
	    wsi->a.context->event_loop_ops->wsi_logical_close) {
		wsi->a.context->event_loop_ops->wsi_logical_close(wsi);
		return 1; /* close / destroy continues async */
	}

	if (wsi->a.context->event_loop_ops->destroy_wsi)
		wsi->a.context->event_loop_ops->destroy_wsi(wsi);

	return 0; /* he is destroyed */
}

int
aws_lws_callback_vhost_protocols_vhost(struct aws_lws_vhost *vh, int reason, void *in,
				   size_t len)
{
	int n;
	struct aws_lws *wsi = aws_lws_zalloc(sizeof(*wsi), "fake wsi");

	if (!wsi)
		return 1;

	wsi->a.context = vh->context;
	aws_lws_vhost_bind_wsi(vh, wsi);

	for (n = 0; n < wsi->a.vhost->count_protocols; n++) {
		wsi->a.protocol = &vh->protocols[n];
		if (wsi->a.protocol->callback(wsi, (enum aws_lws_callback_reasons)reason, NULL, in, len)) {
			aws_lws_free(wsi);
			return 1;
		}
	}

	aws_lws_free(wsi);

	return 0;
}


int
aws_lws_rx_flow_control(struct aws_lws *wsi, int _enable)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int en = _enable;

	// h2 ignores rx flow control atm
	if (aws_lwsi_role_h2(wsi) || wsi->mux_substream ||
	    aws_lwsi_role_h2_ENCAPSULATION(wsi))
		return 0; // !!!

	aws_lwsl_wsi_info(wsi, "0x%x", _enable);

	if (!(_enable & LWS_RXFLOW_REASON_APPLIES)) {
		/*
		 * convert user bool style to bitmap style... in user simple
		 * bool style _enable = 0 = flow control it, = 1 = allow rx
		 */
		en = LWS_RXFLOW_REASON_APPLIES | LWS_RXFLOW_REASON_USER_BOOL;
		if (_enable & 1)
			en |= LWS_RXFLOW_REASON_APPLIES_ENABLE_BIT;
	}

	aws_lws_pt_lock(pt, __func__);

	/* any bit set in rxflow_bitmap DISABLEs rxflow control */
	if (en & LWS_RXFLOW_REASON_APPLIES_ENABLE_BIT)
		wsi->rxflow_bitmap = (uint8_t)(wsi->rxflow_bitmap & ~(en & 0xff));
	else
		wsi->rxflow_bitmap = (uint8_t)(wsi->rxflow_bitmap | (en & 0xff));

	if ((LWS_RXFLOW_PENDING_CHANGE | (!wsi->rxflow_bitmap)) ==
	    wsi->rxflow_change_to)
		goto skip;

	wsi->rxflow_change_to = LWS_RXFLOW_PENDING_CHANGE |
				(!wsi->rxflow_bitmap);

	aws_lwsl_wsi_info(wsi, "bitmap 0x%x: en 0x%x, ch 0x%x",
			   wsi->rxflow_bitmap, en, wsi->rxflow_change_to);

	if (_enable & LWS_RXFLOW_REASON_FLAG_PROCESS_NOW ||
	    !wsi->rxflow_will_be_applied) {
		en = aws___lws_rx_flow_control(wsi);
		aws_lws_pt_unlock(pt);

		return en;
	}

skip:
	aws_lws_pt_unlock(pt);

	return 0;
}

void
aws_lws_rx_flow_allow_all_protocol(const struct aws_lws_context *context,
			       const struct aws_lws_protocols *protocol)
{
	const struct aws_lws_context_per_thread *pt = &context->pt[0];
	struct aws_lws *wsi;
	unsigned int n, m = context->count_threads;

	while (m--) {
		for (n = 0; n < pt->fds_count; n++) {
			wsi = wsi_from_fd(context, pt->fds[n].fd);
			if (!wsi)
				continue;
			if (wsi->a.protocol == protocol)
				aws_lws_rx_flow_control(wsi, LWS_RXFLOW_ALLOW);
		}
		pt++;
	}
}

int aws_user_callback_handle_rxflow(aws_lws_callback_function callback_function,
				struct aws_lws *wsi,
				enum aws_lws_callback_reasons reason, void *user,
				void *in, size_t len)
{
	int n;

	wsi->rxflow_will_be_applied = 1;
	n = callback_function(wsi, reason, user, in, len);
	wsi->rxflow_will_be_applied = 0;
	if (!n)
		n = aws___lws_rx_flow_control(wsi);

	return n;
}

int
aws___lws_rx_flow_control(struct aws_lws *wsi)
{
	struct aws_lws *wsic = wsi->child_list;

	// h2 ignores rx flow control atm
	if (aws_lwsi_role_h2(wsi) || wsi->mux_substream ||
	    aws_lwsi_role_h2_ENCAPSULATION(wsi))
		return 0; // !!!

	/* if he has children, do those if they were changed */
	while (wsic) {
		if (wsic->rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE)
			aws___lws_rx_flow_control(wsic);

		wsic = wsic->sibling_list;
	}

	/* there is no pending change */
	if (!(wsi->rxflow_change_to & LWS_RXFLOW_PENDING_CHANGE))
		return 0;

	/* stuff is still buffered, not ready to really accept new input */
	if (aws_lws_buflist_next_segment_len(&wsi->buflist, NULL)) {
		/* get ourselves called back to deal with stashed buffer */
		aws_lws_callback_on_writable(wsi);
		// return 0;
	}

	/* now the pending is cleared, we can change rxflow state */

	wsi->rxflow_change_to &= (~LWS_RXFLOW_PENDING_CHANGE) & 3;

	aws_lwsl_wsi_info(wsi, "rxflow: change_to %d",
		      wsi->rxflow_change_to & LWS_RXFLOW_ALLOW);

	/* adjust the pollfd for this wsi */

	if (wsi->rxflow_change_to & LWS_RXFLOW_ALLOW) {
		aws_lwsl_wsi_info(wsi, "reenable POLLIN");
		// aws_lws_buflist_describe(&wsi->buflist, NULL, __func__);
		if (aws___lws_change_pollfd(wsi, 0, LWS_POLLIN)) {
			aws_lwsl_wsi_info(wsi, "fail");
			return -1;
		}
	} else
		if (aws___lws_change_pollfd(wsi, LWS_POLLIN, 0))
			return -1;

	return 0;
}


const struct aws_lws_protocols *
aws_lws_get_protocol(struct aws_lws *wsi)
{
	return wsi->a.protocol;
}


int
aws_lws_ensure_user_space(struct aws_lws *wsi)
{
	if (!wsi->a.protocol)
		return 0;

	/* allocate the per-connection user memory (if any) */

	if (wsi->a.protocol->per_session_data_size && !wsi->user_space) {
		wsi->user_space = aws_lws_zalloc(
			    wsi->a.protocol->per_session_data_size, "user space");
		if (wsi->user_space == NULL) {
			aws_lwsl_wsi_err(wsi, "OOM");
			return 1;
		}
	} else
		aws_lwsl_wsi_debug(wsi, "protocol pss %lu, user_space=%p",
				    (long)wsi->a.protocol->per_session_data_size,
				    wsi->user_space);
	return 0;
}

void *
aws_lws_adjust_protocol_psds(struct aws_lws *wsi, size_t new_size)
{
	((struct aws_lws_protocols *)aws_lws_get_protocol(wsi))->per_session_data_size =
		new_size;

	if (aws_lws_ensure_user_space(wsi))
			return NULL;

	return wsi->user_space;
}

int
aws_lws_get_tsi(struct aws_lws *wsi)
{
        return (int)wsi->tsi;
}

int
aws_lws_is_ssl(struct aws_lws *wsi)
{
#if defined(LWS_WITH_TLS)
	return wsi->tls.use_ssl & LCCSCF_USE_SSL;
#else
	(void)wsi;
	return 0;
#endif
}

#if defined(LWS_WITH_TLS) && !defined(LWS_WITH_MBEDTLS)
aws_lws_tls_conn*
aws_lws_get_ssl(struct aws_lws *wsi)
{
	return wsi->tls.ssl;
}
#endif

int
aws_lws_has_buffered_out(struct aws_lws *wsi)
{
	if (wsi->buflist_out)
		return 1;

#if defined(LWS_ROLE_H2)
	{
		struct aws_lws *nwsi = aws_lws_get_network_wsi(wsi);

		if (nwsi->buflist_out)
			return 1;
	}
#endif

	return 0;
}

int
aws_lws_partial_buffered(struct aws_lws *wsi)
{
	return aws_lws_has_buffered_out(wsi);
}

aws_lws_fileofs_t
aws_lws_get_peer_write_allowance(struct aws_lws *wsi)
{
	if (!aws_lws_rops_fidx(wsi->role_ops, LWS_ROPS_tx_credit))
		return -1;

	return aws_lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_tx_credit).
				   tx_credit(wsi, LWSTXCR_US_TO_PEER, 0);
}

void
aws_lws_role_transition(struct aws_lws *wsi, enum aws_lwsi_role role, enum aws_lwsi_state state,
		    const struct aws_lws_role_ops *ops)
{
#if (_LWS_ENABLED_LOGS & LLL_DEBUG) 
	const char *name = "(unset)";
#endif
	wsi->wsistate = (unsigned int)role | (unsigned int)state;
	if (ops)
		wsi->role_ops = ops;
#if (_LWS_ENABLED_LOGS & LLL_DEBUG)
	if (wsi->role_ops)
		name = wsi->role_ops->name;
	aws_lwsl_wsi_debug(wsi, "wsistate 0x%lx, ops %s",
			    (unsigned long)wsi->wsistate, name);
#endif
}

int
aws_lws_parse_uri(char *p, const char **prot, const char **ads, int *port,
	      const char **path)
{
	const char *end;
	char unix_skt = 0;

	/* cut up the location into address, port and path */
	*prot = p;
	while (*p && (*p != ':' || p[1] != '/' || p[2] != '/'))
		p++;
	if (!*p) {
		end = p;
		p = (char *)*prot;
		*prot = end;
	} else {
		*p = '\0';
		p += 3;
	}
	if (*p == '+') /* unix skt */
		unix_skt = 1;

	*ads = p;
	if (!strcmp(*prot, "http") || !strcmp(*prot, "ws"))
		*port = 80;
	else if (!strcmp(*prot, "https") || !strcmp(*prot, "wss"))
		*port = 443;

	if (*p == '[') {
		++(*ads);
		while (*p && *p != ']')
			p++;
		if (*p)
			*p++ = '\0';
	} else
		while (*p && *p != ':' && (unix_skt || *p != '/'))
			p++;

	if (*p == ':') {
		*p++ = '\0';
		*port = atoi(p);
		while (*p && *p != '/')
			p++;
	}
	*path = "/";
	if (*p) {
		*p++ = '\0';
		if (*p)
			*path = p;
	}

	return 0;
}

/* ... */

int
aws_lws_get_urlarg_by_name_safe(struct aws_lws *wsi, const char *name, char *buf, int len)
{
	int n = 0, fraglen, sl = (int)strlen(name);

	do {
		fraglen = aws_lws_hdr_copy_fragment(wsi, buf, len,
						WSI_TOKEN_HTTP_URI_ARGS, n);

		if (fraglen < 0)
			break;

		if (fraglen + 1 < len &&
		    fraglen >= sl &&
		    !strncmp(buf, name, (size_t)sl)) {
			/*
			 * If he left off the trailing =, trim it from the
			 * result
			 */

			if (name[sl - 1] != '=' &&
			    sl < fraglen &&
			    buf[sl] == '=')
				sl++;

			memmove(buf, buf + sl, (size_t)(fraglen - sl));
			buf[fraglen - sl] = '\0';

			return fraglen - sl;
		}

		n++;
	} while (1);

	return -1;
}

const char *
aws_lws_get_urlarg_by_name(struct aws_lws *wsi, const char *name, char *buf, int len)
{
	int n = aws_lws_get_urlarg_by_name_safe(wsi, name, buf, len);

	return n < 0 ? NULL : buf;
}


#if defined(LWS_WITHOUT_EXTENSIONS)

/* we need to provide dummy callbacks for internal exts
 * so user code runs when faced with a lib compiled with
 * extensions disabled.
 */

int
aws_lws_extension_callback_pm_deflate(struct aws_lws_context *context,
                                  const struct aws_lws_extension *ext,
                                  struct aws_lws *wsi,
                                  enum aws_lws_extension_callback_reasons reason,
                                  void *user, void *in, size_t len)
{
	(void)context;
	(void)ext;
	(void)wsi;
	(void)reason;
	(void)user;
	(void)in;
	(void)len;

	return 0;
}

int
aws_lws_set_extension_option(struct aws_lws *wsi, const char *ext_name,
			 const char *opt_name, const char *opt_val)
{
	return -1;
}
#endif

int
aws_lws_is_cgi(struct aws_lws *wsi) {
#ifdef LWS_WITH_CGI
	return !!wsi->http.cgi;
#else
	return 0;
#endif
}

const struct aws_lws_protocol_vhost_options *
aws_lws_pvo_search(const struct aws_lws_protocol_vhost_options *pvo, const char *name)
{
	while (pvo) {
		if (!strcmp(pvo->name, name))
			break;

		pvo = pvo->next;
	}

	return pvo;
}

int
aws_lws_pvo_get_str(void *in, const char *name, const char **result)
{
	const struct aws_lws_protocol_vhost_options *pv =
		aws_lws_pvo_search((const struct aws_lws_protocol_vhost_options *)in,
				name);

	if (!pv)
		return 1;

	*result = (const char *)pv->value;

	return 0;
}

int
aws_lws_broadcast(struct aws_lws_context_per_thread *pt, int reason, void *in, size_t len)
{
	struct aws_lws_vhost *v = pt->context->vhost_list;
	aws_lws_fakewsi_def_plwsa(pt);
	int n, ret = 0;

	aws_lws_fakewsi_prep_plwsa_ctx(pt->context);
#if !defined(LWS_PLAT_FREERTOS) && LWS_MAX_SMP > 1
	((struct aws_lws *)plwsa)->tsi = (char)(int)(pt - &pt->context->pt[0]);
#endif

	while (v) {
		const struct aws_lws_protocols *p = v->protocols;

		plwsa->vhost = v; /* not a real bound wsi */

		for (n = 0; n < v->count_protocols; n++) {
			plwsa->protocol = p;
			if (p->callback &&
			    p->callback((struct aws_lws *)plwsa, (enum aws_lws_callback_reasons)reason, NULL, in, len))
				ret |= 1;
			p++;
		}

		v = v->vhost_next;
	}

	return ret;
}

void *
aws_lws_wsi_user(struct aws_lws *wsi)
{
	return wsi->user_space;
}

int
aws_lws_wsi_tsi(struct aws_lws *wsi)
{
	return wsi->tsi;
}


void
aws_lws_set_wsi_user(struct aws_lws *wsi, void *data)
{
	if (!wsi->user_space_externally_allocated && wsi->user_space)
		aws_lws_free(wsi->user_space);

	wsi->user_space_externally_allocated = 1;
	wsi->user_space = data;
}

struct aws_lws *
aws_lws_get_parent(const struct aws_lws *wsi)
{
	return wsi->parent;
}

struct aws_lws *
aws_lws_get_child(const struct aws_lws *wsi)
{
	return wsi->child_list;
}

void *
aws_lws_get_opaque_parent_data(const struct aws_lws *wsi)
{
	return wsi->opaque_parent_data;
}

void
aws_lws_set_opaque_parent_data(struct aws_lws *wsi, void *data)
{
	wsi->opaque_parent_data = data;
}

void *
aws_lws_get_opaque_user_data(const struct aws_lws *wsi)
{
	return wsi->a.opaque_user_data;
}

void
aws_lws_set_opaque_user_data(struct aws_lws *wsi, void *data)
{
	wsi->a.opaque_user_data = data;
}

int
aws_lws_get_child_pending_on_writable(const struct aws_lws *wsi)
{
	return wsi->parent_pending_cb_on_writable;
}

void
aws_lws_clear_child_pending_on_writable(struct aws_lws *wsi)
{
	wsi->parent_pending_cb_on_writable = 0;
}



const char *
aws_lws_get_vhost_name(struct aws_lws_vhost *vhost)
{
	return vhost->name;
}

int
aws_lws_get_vhost_port(struct aws_lws_vhost *vhost)
{
	return vhost->listen_port;
}

void *
aws_lws_get_vhost_user(struct aws_lws_vhost *vhost)
{
	return vhost->user;
}

const char *
aws_lws_get_vhost_iface(struct aws_lws_vhost *vhost)
{
	return vhost->iface;
}

aws_lws_sockfd_type
aws_lws_get_socket_fd(struct aws_lws *wsi)
{
	if (!wsi)
		return -1;
	return wsi->desc.sockfd;
}


struct aws_lws_vhost *
aws_lws_vhost_get(struct aws_lws *wsi)
{
	return wsi->a.vhost;
}

struct aws_lws_vhost *
aws_lws_get_vhost(struct aws_lws *wsi)
{
	return wsi->a.vhost;
}

const struct aws_lws_protocols *
aws_lws_protocol_get(struct aws_lws *wsi)
{
	return wsi->a.protocol;
}

#if defined(LWS_WITH_UDP)
const struct aws_lws_udp *
aws_lws_get_udp(const struct aws_lws *wsi)
{
	return wsi->udp;
}
#endif

struct aws_lws_context *
aws_lws_get_context(const struct aws_lws *wsi)
{
	return wsi->a.context;
}

struct aws_lws_log_cx *
aws_lwsl_wsi_get_cx(struct aws_lws *wsi)
{
	if (!wsi)
		return NULL;

	return wsi->lc.log_cx;
}

#if defined(LWS_WITH_CLIENT)
int
aws__lws_generic_transaction_completed_active_conn(struct aws_lws **_wsi, char take_vh_lock)
{
	struct aws_lws *wnew, *wsi = *_wsi;

	/*
	 * Are we constitutionally capable of having a queue, ie, we are on
	 * the "active client connections" list?
	 *
	 * If not, that's it for us.
	 */

	if (aws_lws_dll2_is_detached(&wsi->dll_cli_active_conns))
		return 0; /* no new transaction */

	/*
	 * With h1 queuing, the original "active client" moves his attributes
	 * like fd, ssl, queue and active client list entry to the next guy in
	 * the queue before closing... it's because the user code knows the
	 * individual wsi and the action must take place in the correct wsi
	 * context.  Note this means we don't truly pipeline headers.
	 *
	 * Trying to keep the original "active client" in place to do the work
	 * of the wsi breaks down when dealing with queued POSTs otherwise; it's
	 * also competing with the real mux child arrangements and complicating
	 * the code.
	 *
	 * For that reason, see if we have any queued child now...
	 */

	if (!wsi->dll2_cli_txn_queue_owner.head) {
		/*
		 * Nothing pipelined... we should hang around a bit
		 * in case something turns up... otherwise we'll close
		 */
		aws_lwsl_wsi_info(wsi, "nothing pipelined waiting");
		aws_lwsi_set_state(wsi, LRS_IDLING);

		aws_lws_set_timeout(wsi, PENDING_TIMEOUT_CLIENT_CONN_IDLE,
				wsi->keep_warm_secs);

		return 0; /* no new transaction right now */
	}

	/*
	 * We have a queued child wsi we should bequeath our assets to, before
	 * closing ourself
	 */

	if (take_vh_lock)
		aws_lws_vhost_lock(wsi->a.vhost);

	wnew = aws_lws_container_of(wsi->dll2_cli_txn_queue_owner.head, struct aws_lws,
				dll2_cli_txn_queue);

	assert(wsi != wnew);

	aws_lws_dll2_remove(&wnew->dll2_cli_txn_queue);

	assert(aws_lws_socket_is_valid(wsi->desc.sockfd));

	aws___lws_change_pollfd(wsi, LWS_POLLOUT | LWS_POLLIN, 0);

	/* copy the fd */
	wnew->desc = wsi->desc;

	assert(aws_lws_socket_is_valid(wnew->desc.sockfd));

	/* disconnect the fd from association with old wsi */

	if (aws___remove_wsi_socket_from_fds(wsi))
		return -1;

	sanity_assert_no_wsi_traces(wsi->a.context, wsi);
	sanity_assert_no_sockfd_traces(wsi->a.context, wsi->desc.sockfd);
	wsi->desc.sockfd = LWS_SOCK_INVALID;

	aws___lws_wsi_remove_from_sul(wsi);

	/*
	 * ... we're doing some magic here in terms of handing off the socket
	 * that has been active to a wsi that has not yet itself been active...
	 * depending on the event lib we may need to give a magic spark to the
	 * new guy and snuff out the old guy's magic spark at that level as well
	 */

#if defined(LWS_WITH_EVENT_LIBS)
	if (wsi->a.context->event_loop_ops->destroy_wsi)
		wsi->a.context->event_loop_ops->destroy_wsi(wsi);
	if (wsi->a.context->event_loop_ops->sock_accept)
		wsi->a.context->event_loop_ops->sock_accept(wnew);
#endif

	/* point the fd table entry to new guy */

	assert(aws_lws_socket_is_valid(wnew->desc.sockfd));

	if (aws___insert_wsi_socket_into_fds(wsi->a.context, wnew))
		return -1;

#if defined(LWS_WITH_TLS)
	/* pass on the tls */

	wnew->tls = wsi->tls;
	wsi->tls.client_bio = NULL;
	wsi->tls.ssl = NULL;
	wsi->tls.use_ssl = 0;
#endif

	/* take over his copy of his endpoint as an active connection */

	if (!wnew->cli_hostname_copy && wsi->cli_hostname_copy) {
		wnew->cli_hostname_copy = wsi->cli_hostname_copy;
		wsi->cli_hostname_copy = NULL;
	}
	wnew->keep_warm_secs = wsi->keep_warm_secs;

	/*
	 * selected queued guy now replaces the original leader on the
	 * active client conn list
	 */

	aws_lws_dll2_remove(&wsi->dll_cli_active_conns);
	aws_lws_dll2_add_tail(&wnew->dll_cli_active_conns,
			  &wsi->a.vhost->dll_cli_active_conns_owner);

	/* move any queued guys to queue on new active conn */

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   wsi->dll2_cli_txn_queue_owner.head) {
		struct aws_lws *ww = aws_lws_container_of(d, struct aws_lws,
					  dll2_cli_txn_queue);

		aws_lws_dll2_remove(&ww->dll2_cli_txn_queue);
		aws_lws_dll2_add_tail(&ww->dll2_cli_txn_queue,
				  &wnew->dll2_cli_txn_queue_owner);

	} aws_lws_end_foreach_dll_safe(d, d1);

	if (take_vh_lock)
		aws_lws_vhost_unlock(wsi->a.vhost);

	/*
	 * The original leader who passed on all his powers already can die...
	 * in the call stack above us there are guys who still want to touch
	 * him, so have him die next time around the event loop, not now.
	 */

	wsi->already_did_cce = 1; /* so the close doesn't trigger a CCE */
	aws_lws_set_timeout(wsi, 1, LWS_TO_KILL_ASYNC);

	/* after the first one, they can only be coming from the queue */
	wnew->transaction_from_pipeline_queue = 1;

	aws_lwsl_wsi_notice(wsi, " pipeline queue passed -> %s", aws_lws_wsi_tag(wnew));

	*_wsi = wnew; /* inform caller we swapped */

	return 1; /* new transaction */
}
#endif

int LWS_WARN_UNUSED_RESULT
aws_lws_raw_transaction_completed(struct aws_lws *wsi)
{
	if (aws_lws_has_buffered_out(wsi)) {
		/*
		 * ...so he tried to send something large, but it went out
		 * as a partial, but he immediately called us to say he wants
		 * to close the connection.
		 *
		 * Defer the close until the last part of the partial is sent.
		 *
		 */

		aws_lwsl_wsi_debug(wsi, "deferring due to partial");
		wsi->close_when_buffered_out_drained = 1;
		aws_lws_callback_on_writable(wsi);

		return 0;
	}

	return -1;
}

int
aws_lws_bind_protocol(struct aws_lws *wsi, const struct aws_lws_protocols *p,
		  const char *reason)
{
//	if (wsi->a.protocol == p)
//		return 0;
	const struct aws_lws_protocols *vp = wsi->a.vhost->protocols, *vpo;

	if (wsi->a.protocol && wsi->protocol_bind_balance) {
		wsi->a.protocol->callback(wsi,
		       wsi->role_ops->protocol_unbind_cb[!!aws_lwsi_role_server(wsi)],
					wsi->user_space, (void *)reason, 0);
		wsi->protocol_bind_balance = 0;
	}
	if (!wsi->user_space_externally_allocated)
		aws_lws_free_set_NULL(wsi->user_space);

	aws_lws_same_vh_protocol_remove(wsi);

	wsi->a.protocol = p;
	if (!p)
		return 0;

	if (aws_lws_ensure_user_space(wsi))
		return 1;

	if (p > vp && p < &vp[wsi->a.vhost->count_protocols])
		aws_lws_same_vh_protocol_insert(wsi, (int)(p - vp));
	else {
		int n = wsi->a.vhost->count_protocols;
		int hit = 0;

		vpo = vp;

		while (n--) {
			if (p->name && vp->name && !strcmp(p->name, vp->name)) {
				hit = 1;
				aws_lws_same_vh_protocol_insert(wsi, (int)(vp - vpo));
				break;
			}
			vp++;
		}
		if (!hit)
			aws_lwsl_err("%s: %p is not in vhost '%s' protocols list\n",
				 __func__, p, wsi->a.vhost->name);
	}

	if (wsi->a.protocol->callback(wsi, wsi->role_ops->protocol_bind_cb[
				    !!aws_lwsi_role_server(wsi)],
				    wsi->user_space, NULL, 0))
		return 1;

	wsi->protocol_bind_balance = 1;

	return 0;
}

void
aws_lws_http_close_immortal(struct aws_lws *wsi)
{
	struct aws_lws *nwsi;

	if (!wsi->mux_substream)
		return;

	assert(wsi->mux_stream_immortal);
	wsi->mux_stream_immortal = 0;

	nwsi = aws_lws_get_network_wsi(wsi);
	aws_lwsl_wsi_debug(wsi, "%s (%d)", aws_lws_wsi_tag(nwsi),
				       nwsi->immortal_substream_count);
	assert(nwsi->immortal_substream_count);
	nwsi->immortal_substream_count--;
	if (!nwsi->immortal_substream_count)
		/*
		 * since we closed the only immortal stream on this nwsi, we
		 * need to reapply a normal timeout regime to the nwsi
		 */
		aws_lws_set_timeout(nwsi, PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE,
				wsi->a.vhost->keepalive_timeout ?
				    wsi->a.vhost->keepalive_timeout : 31);
}

void
aws_lws_mux_mark_immortal(struct aws_lws *wsi)
{
	struct aws_lws *nwsi;

	aws_lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	if (!wsi->mux_substream
#if defined(LWS_WITH_CLIENT)
			&& !wsi->client_mux_substream
#endif
	) {
		aws_lwsl_wsi_err(wsi, "not mux substream");
		return;
	}

	if (wsi->mux_stream_immortal)
		/* only need to handle it once per child wsi */
		return;

	nwsi = aws_lws_get_network_wsi(wsi);
	if (!nwsi)
		return;

	aws_lwsl_wsi_debug(wsi, "%s (%d)\n", aws_lws_wsi_tag(nwsi),
				    nwsi->immortal_substream_count);

	wsi->mux_stream_immortal = 1;
	assert(nwsi->immortal_substream_count < 255); /* largest count */
	nwsi->immortal_substream_count++;
	if (nwsi->immortal_substream_count == 1)
		aws_lws_set_timeout(nwsi, NO_PENDING_TIMEOUT, 0);
}

int
aws_lws_http_mark_sse(struct aws_lws *wsi)
{
	if (!wsi)
		return 0;

	aws_lws_http_headers_detach(wsi);
	aws_lws_mux_mark_immortal(wsi);

	if (wsi->mux_substream)
		wsi->h2_stream_carries_sse = 1;

	return 0;
}

#if defined(LWS_WITH_CLIENT)

const char *
aws_lws_wsi_client_stash_item(struct aws_lws *wsi, int stash_idx, int hdr_idx)
{
	/* try the generic client stash */
	if (wsi->stash)
		return wsi->stash->cis[stash_idx];

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	/* if not, use the ah stash if applicable */
	return aws_lws_hdr_simple_ptr(wsi, (enum aws_lws_token_indexes)hdr_idx);
#else
	return NULL;
#endif
}
#endif

#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_MQTT)

void
aws_lws_wsi_mux_insert(struct aws_lws *wsi, struct aws_lws *parent_wsi, unsigned int sid)
{
	aws_lwsl_wsi_info(wsi, "par %s: assign sid %d (curr %d)",
			aws_lws_wsi_tag(parent_wsi), sid, wsi->mux.my_sid);

	if (wsi->mux.my_sid && wsi->mux.my_sid != (unsigned int)sid)
		assert(0);

	wsi->mux.my_sid = sid;
	wsi->mux.parent_wsi = parent_wsi;
	wsi->role_ops = parent_wsi->role_ops;

	/* new guy's sibling is whoever was the first child before */
	wsi->mux.sibling_list = parent_wsi->mux.child_list;

	/* first child is now the new guy */
	parent_wsi->mux.child_list = wsi;

	parent_wsi->mux.child_count++;
}

struct aws_lws *
aws_lws_wsi_mux_from_id(struct aws_lws *parent_wsi, unsigned int sid)
{
	aws_lws_start_foreach_ll(struct aws_lws *, wsi, parent_wsi->mux.child_list) {
		if (wsi->mux.my_sid == sid)
			return wsi;
	} aws_lws_end_foreach_ll(wsi, mux.sibling_list);

	return NULL;
}

void
aws_lws_wsi_mux_dump_children(struct aws_lws *wsi)
{
#if defined(_DEBUG)
	if (!wsi->mux.parent_wsi || !aws_lwsl_visible(LLL_INFO))
		return;

	aws_lws_start_foreach_llp(struct aws_lws **, w,
			      wsi->mux.parent_wsi->mux.child_list) {
		aws_lwsl_wsi_info(wsi, "   \\---- child %s %s\n",
				   (*w)->role_ops ? (*w)->role_ops->name : "?",
							   aws_lws_wsi_tag(*w));
		assert(*w != (*w)->mux.sibling_list);
	} aws_lws_end_foreach_llp(w, mux.sibling_list);
#endif
}

void
aws_lws_wsi_mux_close_children(struct aws_lws *wsi, int reason)
{
	struct aws_lws *wsi2;
	struct aws_lws **w;

	if (!wsi->mux.child_list)
		return;

	w = &wsi->mux.child_list;
	while (*w) {
		aws_lwsl_wsi_info((*w), "   closing child");
		/* disconnect from siblings */
		wsi2 = (*w)->mux.sibling_list;
		assert (wsi2 != *w);
		(*w)->mux.sibling_list = NULL;
		(*w)->socket_is_permanently_unusable = 1;
		aws___lws_close_free_wsi(*w, (enum aws_lws_close_status)reason, "mux child recurse");
		*w = wsi2;
	}
}


void
aws_lws_wsi_mux_sibling_disconnect(struct aws_lws *wsi)
{
	struct aws_lws *wsi2;

	aws_lws_start_foreach_llp(struct aws_lws **, w,
			      wsi->mux.parent_wsi->mux.child_list) {

		/* disconnect from siblings */
		if (*w == wsi) {
			wsi2 = (*w)->mux.sibling_list;
			(*w)->mux.sibling_list = NULL;
			*w = wsi2;
			aws_lwsl_wsi_debug(wsi, " disentangled from sibling %s",
					    aws_lws_wsi_tag(wsi2));
			break;
		}
	} aws_lws_end_foreach_llp(w, mux.sibling_list);
	wsi->mux.parent_wsi->mux.child_count--;

	wsi->mux.parent_wsi = NULL;
}

void
aws_lws_wsi_mux_dump_waiting_children(struct aws_lws *wsi)
{
#if defined(_DEBUG)
	aws_lwsl_info("%s: %s: children waiting for POLLOUT service:\n",
		  __func__, aws_lws_wsi_tag(wsi));

	wsi = wsi->mux.child_list;
	while (wsi) {
		aws_lwsl_wsi_info(wsi, "  %c sid %u: 0x%x %s %s",
			  wsi->mux.requested_POLLOUT ? '*' : ' ',
			  wsi->mux.my_sid, aws_lwsi_state(wsi),
			  wsi->role_ops->name,
			  wsi->a.protocol ? wsi->a.protocol->name : "noprotocol");

		wsi = wsi->mux.sibling_list;
	}
#endif
}

int
aws_lws_wsi_mux_mark_parents_needing_writeable(struct aws_lws *wsi)
{
	struct aws_lws /* *network_wsi = aws_lws_get_network_wsi(wsi), */ *wsi2;
	//int already = network_wsi->mux.requested_POLLOUT;

	/* mark everybody above him as requesting pollout */

	wsi2 = wsi;
	while (wsi2) {
		wsi2->mux.requested_POLLOUT = 1;
		aws_lwsl_wsi_info(wsi2, "sid %u, pending writable",
							wsi2->mux.my_sid);
		wsi2 = wsi2->mux.parent_wsi;
	}

	return 0; // already;
}

struct aws_lws *
aws_lws_wsi_mux_move_child_to_tail(struct aws_lws **wsi2)
{
	struct aws_lws *w = *wsi2;

	while (w) {
		if (!w->mux.sibling_list) { /* w is the current last */
			aws_lwsl_wsi_debug(w, "*wsi2 = %s\n", aws_lws_wsi_tag(*wsi2));

			if (w == *wsi2) /* we are already last */
				break;

			/* last points to us as new last */
			w->mux.sibling_list = *wsi2;

			/* guy pointing to us until now points to
			 * our old next */
			*wsi2 = (*wsi2)->mux.sibling_list;

			/* we point to nothing because we are last */
			w->mux.sibling_list->mux.sibling_list = NULL;

			/* w becomes us */
			w = w->mux.sibling_list;
			break;
		}
		w = w->mux.sibling_list;
	}

	/* clear the waiting for POLLOUT on the guy that was chosen */

	if (w)
		w->mux.requested_POLLOUT = 0;

	return w;
}

int
aws_lws_wsi_mux_action_pending_writeable_reqs(struct aws_lws *wsi)
{
	struct aws_lws *w = wsi->mux.child_list;

	while (w) {
		if (w->mux.requested_POLLOUT) {
			if (aws_lws_change_pollfd(wsi, 0, LWS_POLLOUT))
				return -1;
			return 0;
		}
		w = w->mux.sibling_list;
	}

	if (aws_lws_change_pollfd(wsi, LWS_POLLOUT, 0))
		return -1;

	return 0;
}

int
aws_lws_wsi_txc_check_skint(struct aws_lws_tx_credit *txc, int32_t tx_cr)
{
	if (txc->tx_cr <= 0) {
		/*
		 * If other side is not able to cope with us sending any DATA
		 * so no matter if we have POLLOUT on our side if it's DATA we
		 * want to send.
		 */

		if (!txc->skint)
			aws_lwsl_info("%s: %p: skint (%d)\n", __func__, txc,
				  (int)txc->tx_cr);

		txc->skint = 1;

		return 1;
	}

	if (txc->skint)
		aws_lwsl_info("%s: %p: unskint (%d)\n", __func__, txc,
			  (int)txc->tx_cr);

	txc->skint = 0;

	return 0;
}

#if defined(_DEBUG)
void
aws_lws_wsi_txc_describe(struct aws_lws_tx_credit *txc, const char *at, uint32_t sid)
{
	aws_lwsl_info("%s: %p: %s: sid %d: %speer-to-us: %d, us-to-peer: %d\n",
		  __func__, txc, at, (int)sid, txc->skint ? "SKINT, " : "",
		  (int)txc->peer_tx_cr_est, (int)txc->tx_cr);
}
#endif

int
aws_lws_wsi_tx_credit(struct aws_lws *wsi, char peer_to_us, int add)
{
	if (wsi->role_ops && aws_lws_rops_fidx(wsi->role_ops, LWS_ROPS_tx_credit))
		return aws_lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_tx_credit).
				   tx_credit(wsi, peer_to_us, add);

	return 0;
}

/*
 * Let the protocol know about incoming tx credit window updates if it's
 * managing the flow control manually (it may want to proxy this information)
 */

int
aws_lws_wsi_txc_report_manual_txcr_in(struct aws_lws *wsi, int32_t bump)
{
	if (!wsi->txc.manual)
		/*
		 * If we don't care about managing it manually, no need to
		 * report it
		 */
		return 0;

	return aws_user_callback_handle_rxflow(wsi->a.protocol->callback,
					   wsi, LWS_CALLBACK_WSI_TX_CREDIT_GET,
					   wsi->user_space, NULL, (size_t)bump);
}

#if defined(LWS_WITH_CLIENT)

int
aws_lws_wsi_mux_apply_queue(struct aws_lws *wsi)
{
	/* we have a transaction queue that wants to pipeline */

	aws_lws_context_lock(wsi->a.context, __func__); /* -------------- cx { */
	aws_lws_vhost_lock(wsi->a.vhost);

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   wsi->dll2_cli_txn_queue_owner.head) {
		struct aws_lws *w = aws_lws_container_of(d, struct aws_lws,
						 dll2_cli_txn_queue);

#if defined(LWS_ROLE_H2)
		if (aws_lwsi_role_http(wsi) &&
		    aws_lwsi_state(w) == LRS_H2_WAITING_TO_SEND_HEADERS) {
			aws_lwsl_wsi_info(w, "cli pipeq to be h2");

			aws_lwsi_set_state(w, LRS_H1C_ISSUE_HANDSHAKE2);

			/* remove ourselves from client queue */
			aws_lws_dll2_remove(&w->dll2_cli_txn_queue);

			/* attach ourselves as an h2 stream */
			aws_lws_wsi_h2_adopt(wsi, w);
		}
#endif

#if defined(LWS_ROLE_MQTT)
		if (aws_lwsi_role_mqtt(wsi) &&
		    aws_lwsi_state(wsi) == LRS_ESTABLISHED) {
			aws_lwsl_wsi_info(w, "cli pipeq to be mqtt\n");

			/* remove ourselves from client queue */
			aws_lws_dll2_remove(&w->dll2_cli_txn_queue);

			/* attach ourselves as an h2 stream */
			aws_lws_wsi_mqtt_adopt(wsi, w);
		}
#endif

	} aws_lws_end_foreach_dll_safe(d, d1);

	aws_lws_vhost_unlock(wsi->a.vhost);
	aws_lws_context_unlock(wsi->a.context); /* } cx --------------  */

	return 0;
}

#endif

#endif

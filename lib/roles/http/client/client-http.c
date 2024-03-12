/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
aws_lws_client_http_body_pending(struct aws_lws *wsi, int something_left_to_send)
{
	wsi->client_http_body_pending = !!something_left_to_send;
}

int
aws_lws_http_client_socket_service(struct aws_lws *wsi, struct aws_lws_pollfd *pollfd)
{
	struct aws_lws_context *context = wsi->a.context;
	struct aws_lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char *p = (char *)&pt->serv_buf[0];
#if defined(LWS_WITH_TLS)
	char ebuf[128];
#endif
	const char *cce = NULL;
	char *sb = p;
	int n = 0;

	switch (aws_lwsi_state(wsi)) {

	case LRS_WAITING_DNS:
		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 */
		aws_lwsl_err("%s: %s: WAITING_DNS\n", __func__, aws_lws_wsi_tag(wsi));
		if (!aws_lws_client_connect_2_dnsreq(wsi)) {
			/* closed */
			aws_lwsl_client("closed\n");
			return -1;
		}

		/* either still pending connection, or changed mode */
		return 0;

	case LRS_WAITING_CONNECT:

		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 */
		if (pollfd->revents & LWS_POLLOUT)
			if (aws_lws_client_connect_3_connect(wsi, NULL, NULL, 0, NULL) == NULL) {
				aws_lwsl_client("closed\n");
				return -1;
			}
		break;

#if defined(LWS_WITH_SOCKS5)
	/* SOCKS Greeting Reply */
	case LRS_WAITING_SOCKS_GREETING_REPLY:
	case LRS_WAITING_SOCKS_AUTH_REPLY:
	case LRS_WAITING_SOCKS_CONNECT_REPLY:

		switch (aws_lws_socks5c_handle_state(wsi, pollfd, &cce)) {
		case LW5CHS_RET_RET0:
			return 0;
		case LW5CHS_RET_BAIL3:
			goto bail3;
		case LW5CHS_RET_STARTHS:
			goto start_ws_handshake;
		default:
			break;
		}
		break;
#endif

#if defined(LWS_CLIENT_HTTP_PROXYING) && (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))

	case LRS_WAITING_PROXY_REPLY:

		/* handle proxy hung up on us */

		if (pollfd->revents & LWS_POLLHUP) {

			aws_lwsl_warn("Proxy conn %s (fd=%d) dead\n",
				  aws_lws_wsi_tag(wsi), pollfd->fd);

			cce = "proxy conn dead";
			goto bail3;
		}

		n = (int)recv(wsi->desc.sockfd, sb, context->pt_serv_buf_size, 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN) {
				aws_lwsl_debug("Proxy read EAGAIN... retrying\n");
				return 0;
			}
			aws_lwsl_err("ERROR reading from proxy socket\n");
			cce = "proxy read err";
			goto bail3;
		}

		/* sanity check what we were sent... */

		pt->serv_buf[13] = '\0';
		if (n < 13 || strncmp(sb, "HTTP/1.", 7) ||
			      (sb[7] != '0' && sb[7] != '1') || sb[8] != ' ') {
			/* aws_lwsl_hexdump_notice(sb, n); */
			cce = "http_proxy fail";
			goto bail3;
		}

		/* it's h1 alright... what's his logical response code? */
		n = atoi(&sb[9]);
		if (n != 200) {
			aws_lws_snprintf(sb, 20, "http_proxy -> %u",
				     (unsigned int)n);
			cce = sb;
			goto bail3;
		}

		aws_lwsl_info("%s: proxy connection extablished\n", __func__);

		/* clear his proxy connection timeout */

		aws_lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

               /* fallthru */

#endif

               /* dummy fallthru to satisfy compiler */
               /* fallthru */
	case LRS_H1C_ISSUE_HANDSHAKE:

		aws_lwsl_debug("%s: LRS_H1C_ISSUE_HANDSHAKE\n", __func__);

		/*
		 * we are under PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE
		 * timeout protection set in client-handshake.c
		 *
		 * take care of our aws_lws_callback_on_writable
		 * happening at a time when there's no real connection yet
		 */
#if defined(LWS_WITH_SOCKS5)
start_ws_handshake:
#endif
		if (aws_lws_change_pollfd(wsi, LWS_POLLOUT, 0))
			return -1;

#if defined(LWS_ROLE_H2) || defined(LWS_WITH_TLS)
		if (
#if defined(LWS_WITH_TLS)
		    !(wsi->tls.use_ssl & LCCSCF_USE_SSL)
#endif
#if defined(LWS_ROLE_H2) && defined(LWS_WITH_TLS)
		    &&
#endif
#if defined(LWS_ROLE_H2)
		    !(wsi->flags & LCCSCF_H2_PRIOR_KNOWLEDGE)
#endif
		    )
			goto hs2;
#endif

#if defined(LWS_WITH_TLS)
		n = aws_lws_client_create_tls(wsi, &cce, 1);
		if (n == CCTLS_RETURN_ERROR)
			goto bail3;
		if (n == CCTLS_RETURN_RETRY)
			return 0;

		/*
		 * aws_lws_client_create_tls() can already have done the
		 * whole tls setup and preface send... if so he set our state
		 * to LRS_H1C_ISSUE_HANDSHAKE2... let's proceed but be prepared
		 * to notice our state and not resend the preface...
		 */

		aws_lwsl_debug("%s: LRS_H1C_ISSUE_HANDSHAKE fallthru\n", __func__);

		/* fallthru */

	case LRS_WAITING_SSL:

		if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
			n = aws_lws_ssl_client_connect2(wsi, ebuf, sizeof(ebuf));
			if (!n)
				return 0;
			if (n < 0) {
				cce = ebuf;
				goto bail3;
			}
		} else {
			wsi->tls.ssl = NULL;
			if (wsi->flags & LCCSCF_H2_PRIOR_KNOWLEDGE) {
				aws_lwsl_info("h2 prior knowledge\n");
				aws_lws_role_call_alpn_negotiated(wsi, "h2");
			}
		}
#endif

#if defined (LWS_WITH_HTTP2)
		if (wsi->client_h2_alpn //&&
		    //aws_lwsi_state(wsi) != LRS_H1C_ISSUE_HANDSHAKE2
		    ) {
			/*
			 * We connected to the server and set up tls and
			 * negotiated "h2" or connected as clear text
			 * with http/2 prior knowledge.
			 *
			 * So this is it, we are an h2 nwsi client connection
			 * now, not an h1 client connection.
			 */

			aws_lwsl_info("%s: doing h2 hello path\n", __func__);

			/*
			 * send the H2 preface to legitimize the connection
			 *
			 * transitions us to LRS_H2_WAITING_TO_SEND_HEADERS
			 */
			if (wsi->client_h2_alpn)
				if (aws_lws_h2_issue_preface(wsi)) {
					cce = "error sending h2 preface";
					goto bail3;
				}

		//	aws_lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);
			aws_lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND,
					(int)context->timeout_secs);

			break;
		}
#endif

		/* fallthru */

	case LRS_H1C_ISSUE_HANDSHAKE2:

hs2:

		p = aws_lws_generate_client_handshake(wsi, p);
		if (p == NULL) {
			if (wsi->role_ops == &role_ops_raw_skt
#if defined(LWS_ROLE_RAW_FILE)
				|| wsi->role_ops == &role_ops_raw_file
#endif
			    )
				return 0;

			aws_lwsl_err("Failed to generate handshake for client\n");
			aws_lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "chs");
			return 0;
		}

		/* send our request to the server */

		aws_lwsl_info("%s: HANDSHAKE2: %s: sending headers "
			  "(wsistate 0x%lx), w sock %d\n",
			  __func__, aws_lws_wsi_tag(wsi),
			  (unsigned long)wsi->wsistate, wsi->desc.sockfd);

		n = aws_lws_ssl_capable_write(wsi, (unsigned char *)sb, aws_lws_ptr_diff_size_t(p, sb));
		switch (n) {
		case LWS_SSL_CAPABLE_ERROR:
			aws_lwsl_debug("ERROR writing to client socket\n");
			aws_lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "cws");
			return 0;
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			aws_lws_callback_on_writable(wsi);
			break;
		}

		if (wsi->client_http_body_pending || aws_lws_has_buffered_out(wsi)) {
			aws_lwsl_debug("body pending\n");
			aws_lwsi_set_state(wsi, LRS_ISSUE_HTTP_BODY);
			aws_lws_set_timeout(wsi,
					PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD,
					(int)context->timeout_secs);

			if (wsi->flags & LCCSCF_HTTP_X_WWW_FORM_URLENCODED)
				aws_lws_callback_on_writable(wsi);
#if defined(LWS_WITH_HTTP_PROXY)
			if (wsi->http.proxy_clientside && wsi->parent &&
			    wsi->parent->http.buflist_post_body)
				aws_lws_callback_on_writable(wsi);
#endif
			/* user code must ask for writable callback */
			break;
		}

		aws_lwsi_set_state(wsi, LRS_WAITING_SERVER_REPLY);
		wsi->hdr_parsing_completed = 0;

		if (aws_lwsi_state(wsi) == LRS_IDLING) {
			aws_lwsi_set_state(wsi, LRS_WAITING_SERVER_REPLY);
			wsi->hdr_parsing_completed = 0;
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
			wsi->http.ah->parser_state = WSI_TOKEN_NAME_PART;
			wsi->http.ah->lextable_pos = 0;
			wsi->http.ah->unk_pos = 0;
			/* If we're (re)starting on hdr, need other implied init */
			wsi->http.ah->ues = URIES_IDLE;
#endif
		}

		aws_lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				(int)wsi->a.context->timeout_secs);

		aws_lws_callback_on_writable(wsi);

		goto client_http_body_sent;

	case LRS_ISSUE_HTTP_BODY:
#if defined(LWS_WITH_HTTP_PROXY)
			if (wsi->http.proxy_clientside && wsi->parent &&
			    wsi->parent->http.buflist_post_body)
				aws_lws_callback_on_writable(wsi);
#endif
		if (wsi->client_http_body_pending || aws_lws_has_buffered_out(wsi)) {
			//aws_lws_set_timeout(wsi,
			//		PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD,
			//		context->timeout_secs);
			/* user code must ask for writable callback */
			break;
		}
client_http_body_sent:
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		/* prepare ourselves to do the parsing */
		wsi->http.ah->parser_state = WSI_TOKEN_NAME_PART;
		wsi->http.ah->lextable_pos = 0;
		wsi->http.ah->unk_pos = 0;
#endif
		aws_lwsi_set_state(wsi, LRS_WAITING_SERVER_REPLY);
		aws_lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				(int)context->timeout_secs);
		break;

	case LRS_WAITING_SERVER_REPLY:
		/*
		 * handle server hanging up on us...
		 * but if there is POLLIN waiting, handle that first
		 */
		if ((pollfd->revents & (LWS_POLLIN | LWS_POLLHUP)) ==
								LWS_POLLHUP) {

			if (aws_lws_buflist_total_len(&wsi->buflist))
				aws_lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_ACK, 3);
			else {
				aws_lwsl_debug("Server conn %s (fd=%d) dead\n",
						aws_lws_wsi_tag(wsi), pollfd->fd);
				cce = "Peer hung up";
				goto bail3;
			}
		}

		if (pollfd->revents & LWS_POLLOUT)
			if (aws_lws_change_pollfd(wsi, LWS_POLLOUT, 0))
				return -1;

		if (!(pollfd->revents & LWS_POLLIN))
			break;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		/* interpret the server response
		 *
		 *  HTTP/1.1 101 Switching Protocols
		 *  Upgrade: websocket
		 *  Connection: Upgrade
		 *  Sec-WebSocket-Accept: me89jWimTRKTWwrS3aRrL53YZSo=
		 *  Sec-WebSocket-Nonce: AQIDBAUGBwgJCgsMDQ4PEC==
		 *  Sec-WebSocket-Protocol: chat
		 *
		 * we have to take some care here to only take from the
		 * socket bytewise.  The browser may (and has been seen to
		 * in the case that onopen() performs websocket traffic)
		 * coalesce both handshake response and websocket traffic
		 * in one packet, since at that point the connection is
		 * definitively ready from browser pov.
		 */
		while (wsi->http.ah->parser_state != WSI_PARSING_COMPLETE) {
			struct aws_lws_tokens eb;
			int n, m, buffered;

			eb.token = NULL;
			eb.len = 0;
			buffered = aws_lws_buflist_aware_read(pt, wsi, &eb, 0, __func__);
			aws_lwsl_debug("%s: buflist-aware-read %d %d\n", __func__,
					buffered, eb.len);
			if (eb.len == LWS_SSL_CAPABLE_MORE_SERVICE)
				return 0;
			if (buffered < 0 || eb.len < 0) {
				cce = "read failed";
				goto bail3;
			}
			if (!eb.len)
				return 0;

			n = eb.len;
			if (aws_lws_parse(wsi, eb.token, &n)) {
				aws_lwsl_warn("problems parsing header\n");
				cce = "problems parsing header";
				goto bail3;
			}

			m = eb.len - n;
#if defined(LWS_WITH_SECURE_STREAMS_BUFFER_DUMP)
			do {
				aws_lws_ss_handle_t *h = (aws_lws_ss_handle_t *)aws_lws_get_opaque_user_data(wsi);
				if (!h)
					break;

				if (h->info.dump) {
					h->info.dump(ss_to_userobj(h),
						(const uint8_t *)eb.token,
						(size_t)m,
						(wsi->http.ah->parser_state ==
						 WSI_PARSING_COMPLETE) ? 1 : 0);
				}
			} while (0);
#endif
			if (aws_lws_buflist_aware_finished_consuming(wsi, &eb, m,
								 buffered,
								 __func__))
			        return -1;

			/*
			 * coverity: uncomment if extended
			 *
			 * eb.token += m;
			 * eb.len -= m;
			 */

			if (n) {
				assert(wsi->http.ah->parser_state ==
						WSI_PARSING_COMPLETE);

				break;
			}
		}

		/*
		 * hs may also be coming in multiple packets, there is a 5-sec
		 * libwebsocket timeout still active here too, so if parsing did
		 * not complete just wait for next packet coming in this state
		 */
		if (wsi->http.ah->parser_state != WSI_PARSING_COMPLETE)
			break;
#endif

		/*
		 * otherwise deal with the handshake.  If there's any
		 * packet traffic already arrived we'll trigger poll() again
		 * right away and deal with it that way
		 */
		return aws_lws_client_interpret_server_handshake(wsi);

bail3:
		aws_lwsl_info("%s: closing conn at LWS_CONNMODE...SERVER_REPLY, %s, state 0x%x\n",
				__func__, aws_lws_wsi_tag(wsi), aws_lwsi_state(wsi));
		if (cce)
			aws_lwsl_info("reason: %s\n", cce);
		else
			cce = "unknown";
		aws_lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

		aws_lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "cbail3");
		return -1;

	default:
		break;
	}

	return 0;
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)

int LWS_WARN_UNUSED_RESULT
aws_lws_http_transaction_completed_client(struct aws_lws *wsi)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	int n;

	aws_lwsl_info("%s: %s (%s)\n", __func__, aws_lws_wsi_tag(wsi),
			wsi->a.protocol->name);

	// if (wsi->http.ah && wsi->http.ah->http_response)
	/* we're only judging if any (200, or 500 etc) http txn completed */
	aws_lws_metrics_caliper_report(wsi->cal_conn, METRES_GO);

	if (aws_user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
					LWS_CALLBACK_COMPLETED_CLIENT_HTTP,
					wsi->user_space, NULL, 0)) {
		aws_lwsl_debug("%s: Completed call returned nonzero (role 0x%lx)\n",
			   __func__, (unsigned long)aws_lwsi_role(wsi));
		return -1;
	}

	wsi->http.rx_content_length = 0;

	/*
	 * For h1, wsi may pass some assets on to a queued child and be
	 * destroyed during this.
	 */
	aws_lws_pt_lock(pt, __func__);
	n = aws__lws_generic_transaction_completed_active_conn(&wsi, 1);
	aws_lws_pt_unlock(pt);

	if (wsi->http.ah) {
		if (wsi->client_mux_substream)
			/*
			 * As an h2 client, once we did our transaction, that is
			 * it for us.  Further transactions will happen as new
			 * SIDs on the connection.
			 */
			aws___lws_header_table_detach(wsi, 0);
		else
			if (!n)
				aws__lws_header_table_reset(wsi->http.ah);
	}

	if (!n || !wsi->http.ah)
		return 0;

	/*
	 * H1: we can serialize the queued guys into the same ah
	 * H2: everybody needs their own ah until their own STREAM_END
	 */

	/* otherwise set ourselves up ready to go again */
	aws_lwsi_set_state(wsi, LRS_WAITING_SERVER_REPLY);

	wsi->http.ah->parser_state = WSI_TOKEN_NAME_PART;
	wsi->http.ah->lextable_pos = 0;
	wsi->http.ah->unk_pos = 0;

	aws_lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
			(int)wsi->a.context->timeout_secs);

	/* If we're (re)starting on headers, need other implied init */
	wsi->http.ah->ues = URIES_IDLE;
	aws_lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);

	aws_lwsl_info("%s: %s: new queued transaction\n", __func__, aws_lws_wsi_tag(wsi));
	aws_lws_callback_on_writable(wsi);

	return 0;
}

unsigned int
aws_lws_http_client_http_response(struct aws_lws *wsi)
{
	if (wsi->http.ah && wsi->http.ah->http_response)
		return wsi->http.ah->http_response;

	return 0;
}
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)

int
aws_lws_http_is_redirected_to_get(struct aws_lws *wsi)
{
	return wsi->redirected_to_get;
}

int
aws_lws_client_interpret_server_handshake(struct aws_lws *wsi)
{
	int n, port = 0, ssl = 0;
	int close_reason = LWS_CLOSE_STATUS_PROTOCOL_ERR;
	const char *prot, *ads = NULL, *path, *cce = NULL;
	struct allocated_headers *ah, *ah1;
	struct aws_lws *nwsi = aws_lws_get_network_wsi(wsi);
	char *p = NULL, *q, *simp;
	char new_path[300];
	void *opaque;

	// aws_lws_free_set_NULL(wsi->stash);

#if defined(LWS_WITH_CONMON)
	wsi->conmon.ciu_txn_resp = (aws_lws_conmon_interval_us_t)
					(aws_lws_now_usecs() - wsi->conmon_datum);
#endif

	ah = wsi->http.ah;
	if (!wsi->do_ws) {
		/* we are being an http client...
		 */
#if defined(LWS_ROLE_H2)
		if (wsi->client_h2_alpn || wsi->client_mux_substream) {
			aws_lwsl_debug("%s: %s: transitioning to h2 client\n",
				   __func__, aws_lws_wsi_tag(wsi));
			aws_lws_role_transition(wsi, LWSIFR_CLIENT,
					    LRS_ESTABLISHED, &role_ops_h2);
		} else
#endif
		{
#if defined(LWS_ROLE_H1)
			{
			aws_lwsl_debug("%s: %s: transitioning to h1 client\n",
				   __func__, aws_lws_wsi_tag(wsi));
			aws_lws_role_transition(wsi, LWSIFR_CLIENT,
					    LRS_ESTABLISHED, &aws_role_ops_h1);
			}
#else
			return -1;
#endif
		}

		wsi->http.ah = ah;
		ah->http_response = 0;
	}

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)

	if ((wsi->flags & LCCSCF_CACHE_COOKIES) &&
	    aws_lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_SET_COOKIE))
		aws_lws_parse_set_cookie(wsi);

#endif
	/*
	 * well, what the server sent looked reasonable for syntax.
	 * Now let's confirm it sent all the necessary headers
	 *
	 * http (non-ws) client will expect something like this
	 *
	 * HTTP/1.0.200
	 * server:.libwebsockets
	 * content-type:.text/html
	 * content-length:.17703
	 * set-cookie:.test=LWS_1456736240_336776_COOKIE;Max-Age=360000
	 */

	wsi->http.conn_type = HTTP_CONNECTION_KEEP_ALIVE;
	if (!wsi->client_mux_substream) {
		p = aws_lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP);
		/*
		if (wsi->do_ws && !p) {
			aws_lwsl_info("no URI\n");
			cce = "HS: URI missing";
			goto bail3;
		}
		*/
		if (!p) {
			p = aws_lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP1_0);
			wsi->http.conn_type = HTTP_CONNECTION_CLOSE;
		}
		if (!p) {
			cce = "HS: URI missing";
			aws_lwsl_info("no URI\n");
			goto bail3;
		}
#if defined(LWS_ROLE_H2)
	} else {
		p = aws_lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_STATUS);
		if (!p) {
			cce = "HS: :status missing";
			aws_lwsl_info("no status\n");
			goto bail3;
		}
#endif
	}
#if !defined(LWS_ROLE_H2)
	if (!p) {
		cce = "HS: :status missing";
		aws_lwsl_info("no status\n");
		goto bail3;
	}
#endif
	n = atoi(p);
	if (ah)
		ah->http_response = (unsigned int)n;

	if (!wsi->client_no_follow_redirect &&
#if defined(LWS_WITH_HTTP_PROXY)
	    !wsi->http.proxy_clientside &&
#endif
	    (n == 301 || n == 302 || n == 303 || n == 307 || n == 308)) {
		p = aws_lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_LOCATION);
		if (!p) {
			cce = "HS: Redirect code but no Location";
			goto bail3;
		}

#if defined(LWS_WITH_CONMON)
		if (wsi->conmon.pcol == LWSCONMON_PCOL_NONE) {
			wsi->conmon.pcol = LWSCONMON_PCOL_HTTP;
			wsi->conmon.protocol_specific.http.response = n;
		}

#if defined(LWS_WITH_SECURE_STREAMS)
		if (wsi->for_ss
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
		    && !wsi->client_bound_sspc
#endif
		   ) {
	
			aws_lws_ss_handle_t *h = (aws_lws_ss_handle_t *)aws_lws_get_opaque_user_data(wsi);

			if (h)
				aws_lws_conmon_ss_json(h);
		}
#endif
#endif

		/* let's let the user code know, if he cares */

		if (wsi->a.protocol->callback(wsi,
					    LWS_CALLBACK_CLIENT_HTTP_REDIRECT,
					    wsi->user_space, p, (unsigned int)n)) {
			cce = "HS: user code rejected redirect";
			goto bail3;
		}

		/*
		 * Some redirect codes imply we have to change the method
		 * used for the subsequent transaction, commonly POST ->
		 * 303 -> GET.
		 */

		if (n == 303) {
			char *mp = aws_lws_hdr_simple_ptr(wsi,_WSI_TOKEN_CLIENT_METHOD);
			int ml = aws_lws_hdr_total_length(wsi, _WSI_TOKEN_CLIENT_METHOD);

			if (ml >= 3 && mp) {
				aws_lwsl_info("%s: 303 switching to GET\n", __func__);
				memcpy(mp, "GET", 4);
				wsi->redirected_to_get = 1;
				wsi->http.ah->frags[wsi->http.ah->frag_index[
				             _WSI_TOKEN_CLIENT_METHOD]].len = 3;
			}
		}

		/* Relative reference absolute path */
		if (p[0] == '/' || !strchr(p, ':')) {
#if defined(LWS_WITH_TLS)
			ssl = nwsi->tls.use_ssl & LCCSCF_USE_SSL;
#endif
			ads = aws_lws_hdr_simple_ptr(wsi,
						 _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			port = nwsi->c_port;
			path = p;
			/* aws_lws_client_reset expects leading / omitted */
			if (*path == '/')
				path++;
		}
		/* Absolute (Full) URI */
		else if (strchr(p, ':')) {
			if (aws_lws_parse_uri(p, &prot, &ads, &port, &path)) {
				cce = "HS: URI did not parse";
				goto bail3;
			}

			if (!strcmp(prot, "wss") || !strcmp(prot, "https"))
				ssl = LCCSCF_USE_SSL;
		}
		/* Relative reference relative path */
		else {
			/* This doesn't try to calculate an absolute path,
			 * that will be left to the server */
#if defined(LWS_WITH_TLS)
			ssl = nwsi->tls.use_ssl & LCCSCF_USE_SSL;
#endif
			ads = aws_lws_hdr_simple_ptr(wsi,
						 _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			port = wsi->c_port;
			/* +1 as aws_lws_client_reset expects leading / omitted */
			path = new_path + 1;
			if (aws_lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI))
				aws_lws_strncpy(new_path, aws_lws_hdr_simple_ptr(wsi,
				   _WSI_TOKEN_CLIENT_URI), sizeof(new_path));
			else {
				new_path[0] = '/';
				new_path[1] = '\0';
			}
			q = strrchr(new_path, '/');
			if (q)
				aws_lws_strncpy(q + 1, p, sizeof(new_path) -
							(unsigned int)(q - new_path) - 1);
			else
				path = p;
		}

#if defined(LWS_WITH_TLS)
		if ((wsi->tls.use_ssl & LCCSCF_USE_SSL) && !ssl &&
		     !(wsi->flags & LCCSCF_ACCEPT_TLS_DOWNGRADE_REDIRECTS)) {
			cce = "HS: Redirect attempted SSL downgrade";
			goto bail3;
		}
#endif

		if (!ads) /* make coverity happy */ {
			cce = "no ads";
			goto bail3;
		}

		if (!aws_lws_client_reset(&wsi, ssl, ads, port, path, ads, 1)) {
			aws_lwsl_err("Redirect failed\n");
			cce = "HS: Redirect failed";
			goto bail3;
		}

		/*
		 * We are redirecting, let's close in order to extricate
		 * ourselves from the current wsi usage, eg, h2 mux cleanly.
		 *
		 * We will notice close_is_redirect and switch to redirect
		 * flow late in the close action.
		 */

		opaque = wsi->a.opaque_user_data;
		aws_lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "redir");
		wsi->a.opaque_user_data = opaque;

		return -1;
	}

	/* if h1 KA is allowed, enable the queued pipeline guys */

	if (!wsi->client_h2_alpn && !wsi->client_mux_substream) {
		/* ie, coming to this for the first time */
		if (wsi->http.conn_type == HTTP_CONNECTION_KEEP_ALIVE)
			wsi->keepalive_active = 1;
		else {
			/*
			 * Ugh... now the main http connection has seen
			 * both sides, we learn the server doesn't
			 * support keepalive.
			 *
			 * That means any guys queued on us are going
			 * to have to be restarted from connect2 with
			 * their own connections.
			 */

			/*
			 * stick around telling any new guys they can't
			 * pipeline to this server
			 */
			wsi->keepalive_rejected = 1;

			aws_lws_vhost_lock(wsi->a.vhost);
			aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *,
						   d, d1,
			  wsi->dll2_cli_txn_queue_owner.head) {
				struct aws_lws *ww = aws_lws_container_of(d,
					struct aws_lws,
					dll2_cli_txn_queue);

				/* remove him from our queue */
				aws_lws_dll2_remove(&ww->dll2_cli_txn_queue);
				/* give up on pipelining */
				ww->client_pipeline = 0;

				/* go back to "trying to connect" state */
				aws_lws_role_transition(ww, LWSIFR_CLIENT,
						    LRS_UNCONNECTED,
#if defined(LWS_ROLE_H1)
						    &aws_role_ops_h1);
#else
#if defined (LWS_ROLE_H2)
						    &role_ops_h2);
#else
						    &role_ops_raw);
#endif
#endif
				ww->user_space = NULL;
			} aws_lws_end_foreach_dll_safe(d, d1);
			aws_lws_vhost_unlock(wsi->a.vhost);
		}
	}

#ifdef LWS_WITH_HTTP_PROXY
	wsi->http.perform_rewrite = 0;
	if (aws_lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE)) {
		if (!strncmp(aws_lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE),
					"text/html", 9))
			wsi->http.perform_rewrite = 0;
	}
#endif

	/* he may choose to send us stuff in chunked transfer-coding */
	wsi->chunked = 0;
	wsi->chunk_remaining = 0; /* ie, next thing is chunk size */
	if (aws_lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING)) {
		simp = aws_lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING);

		/* cannot be NULL, since it has nonzero length... coverity */
		if (!simp)
			goto bail2;
		wsi->chunked = !strcmp(simp, "chunked");
		/* first thing is hex, after payload there is crlf */
		wsi->chunk_parser = ELCP_HEX;
	}

	wsi->http.content_length_given = 0;
	if (aws_lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		simp = aws_lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH);

		/* cannot be NULL, since it has nonzero length... coverity */
		if (!simp)
			goto bail2;

		wsi->http.rx_content_length = (aws_lws_filepos_t)atoll(simp);
		aws_lwsl_info("%s: incoming content length %llu\n",
			    __func__, (unsigned long long)
				    wsi->http.rx_content_length);
		wsi->http.rx_content_remain =
				wsi->http.rx_content_length;
		wsi->http.content_length_given = 1;
	} else { /* can't do 1.1 without a content length or chunked */
		if (!wsi->chunked)
			wsi->http.conn_type = HTTP_CONNECTION_CLOSE;
		aws_lwsl_debug("%s: no content length\n", __func__);
	}

	if (wsi->do_ws) {
		/*
		 * Give one last opportunity to ws protocols to inspect server reply
		 * before the ws upgrade code discard it. ie: download reply body in case
		 * of any other response code than 101.
		 */
		if (wsi->a.protocol->callback(wsi,
					  LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					  wsi->user_space, NULL, 0)) {

			cce = "HS: disallowed by client filter";
			goto bail2;
		}
	} else {
		/* allocate the per-connection user memory (if any) */
		if (aws_lws_ensure_user_space(wsi)) {
			aws_lwsl_err("Problem allocating wsi user mem\n");
			cce = "HS: OOM";
			goto bail2;
		}


		/*
		 * we seem to be good to go, give client last chance to check
		 * headers and OK it
		 */
		ah1 = wsi->http.ah;
		wsi->http.ah = ah;
		if (wsi->a.protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
					    wsi->user_space, NULL, 0)) {
			wsi->http.ah = ah1;
			cce = "HS: disallowed by client filter";
			goto bail2;
		}

		/* clear his proxy connection timeout */
		aws_lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

		/* call him back to inform him he is up */
		if (wsi->a.protocol->callback(wsi,
					    LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					    wsi->user_space, NULL, 0)) {
			wsi->http.ah = ah1;
			cce = "HS: disallowed at ESTABLISHED";
			goto bail3;
		}

		wsi->http.ah = ah1;

		aws_lwsl_info("%s: %s: client conn up\n", __func__, aws_lws_wsi_tag(wsi));

		/*
		 * Did we get a response from the server with an explicit
		 * content-length of zero?  If so, and it's not H2 which will
		 * notice it via END_STREAM, this transaction is already
		 * completed at the end of the header processing...
		 */
		if (!wsi->mux_substream && !wsi->client_mux_substream &&
		    aws_lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
		    !wsi->http.rx_content_length)
		        return !!aws_lws_http_transaction_completed_client(wsi);

		/*
		 * We can also get a case where it's http/1 and there's no
		 * content-length at all, so anything that comes is the body
		 * until it hangs up on us.  With that situation, hanging up
		 * on us past this point should generate a valid
		 * LWS_CALLBACK_COMPLETED_CLIENT_HTTP.
		 *
		 * In that situation, he can't pipeline because in h1 there's
		 * no post-header in-band way to signal the end of the
		 * transaction except hangup.
		 *
		 * aws_lws_http_transaction_completed_client() is the right guy to
		 * issue it when we see the peer has hung up on us.
		 */

		return 0;
	}

#if defined(LWS_ROLE_WS)
	switch (aws_lws_client_ws_upgrade(wsi, &cce)) {
	case 2:
		goto bail2;
	case 3:
		goto bail3;
	}

	return 0;
#endif

bail3:
	close_reason = LWS_CLOSE_STATUS_NOSTATUS;

bail2:
	if (wsi->a.protocol) {
		n = 0;
		if (cce)
			n = (int)strlen(cce);

		aws_lws_inform_client_conn_fail(wsi, (void *)cce, (unsigned int)n);
	}

	aws_lwsl_info("closing connection (prot %s) "
		  "due to bail2 connection error: %s\n", wsi->a.protocol ?
				  wsi->a.protocol->name : "unknown", cce);

	/* closing will free up his parsing allocations */
	aws_lws_close_free_wsi(wsi, (enum aws_lws_close_status)close_reason, "c hs interp");

	return 1;
}
#endif

/*
 * set the boundary string and the content-type for client multipart mime
 */

uint8_t *
aws_lws_http_multipart_headers(struct aws_lws *wsi, uint8_t *p)
{
	char buf[10], arg[48];
	int n;

	if (aws_lws_get_random(wsi->a.context, (uint8_t *)buf, sizeof(buf)) !=
			sizeof(buf))
		return NULL;

	aws_lws_b64_encode_string(buf, sizeof(buf),
			       wsi->http.multipart_boundary,
			       sizeof(wsi->http.multipart_boundary));

	n = aws_lws_snprintf(arg, sizeof(arg), "multipart/form-data; boundary=\"%s\"",
			 wsi->http.multipart_boundary);

	if (aws_lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (uint8_t *)arg, n, &p, p + 100))
		return NULL;

	wsi->http.multipart = wsi->http.multipart_issue_boundary = 1;
	aws_lws_client_http_body_pending(wsi, 1);

	return p;
}

int
aws_lws_client_http_multipart(struct aws_lws *wsi, const char *name,
			  const char *filename, const char *content_type,
			  char **p, char *end)
{
	/*
	 * Client conn must have been created with LCCSCF_HTTP_MULTIPART_MIME
	 * flag to use this api
	 */
	assert(wsi->http.multipart);

	if (!name) {
		*p += aws_lws_snprintf((char *)(*p), aws_lws_ptr_diff_size_t(end, *p),
					"\xd\xa--%s--\xd\xa",
					wsi->http.multipart_boundary);

		return 0;
	}

	if (wsi->client_subsequent_mime_part)
		*p += aws_lws_snprintf((char *)(*p), aws_lws_ptr_diff_size_t(end, *p), "\xd\xa");
	wsi->client_subsequent_mime_part = 1;

	*p += aws_lws_snprintf((char *)(*p), aws_lws_ptr_diff_size_t(end, *p), "--%s\xd\xa"
				    "Content-Disposition: form-data; "
				      "name=\"%s\"",
				      wsi->http.multipart_boundary, name);
	if (filename)
		*p += aws_lws_snprintf((char *)(*p), aws_lws_ptr_diff_size_t(end, *p),
				   "; filename=\"%s\"", filename);

	if (content_type)
		*p += aws_lws_snprintf((char *)(*p), aws_lws_ptr_diff_size_t(end, *p), "\xd\xa"
				"Content-Type: %s", content_type);

	*p += aws_lws_snprintf((char *)(*p), aws_lws_ptr_diff_size_t(end, *p), "\xd\xa\xd\xa");

	return *p == end;
}

char *
aws_lws_generate_client_handshake(struct aws_lws *wsi, char *pkt)
{
	const char *meth, *pp = aws_lws_hdr_simple_ptr(wsi,
				_WSI_TOKEN_CLIENT_SENT_PROTOCOLS), *path;
	char *p = pkt, *p1, *end = p + wsi->a.context->pt_serv_buf_size;

	meth = aws_lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
	if (!meth) {
		meth = "GET";
		wsi->do_ws = 1;
	} else {
		wsi->do_ws = 0;
	}

	if (!strcmp(meth, "RAW")) {
		aws_lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
		aws_lwsl_notice("client transition to raw\n");

		if (pp) {
			const struct aws_lws_protocols *pr;

			pr = aws_lws_vhost_name_to_protocol(wsi->a.vhost, pp);

			if (!pr) {
				aws_lwsl_err("protocol %s not enabled on vhost\n",
					 pp);
				return NULL;
			}

			aws_lws_bind_protocol(wsi, pr, __func__);
		}

		if ((wsi->a.protocol->callback)(wsi, LWS_CALLBACK_RAW_ADOPT,
					      wsi->user_space, NULL, 0))
			return NULL;

		aws_lws_role_transition(wsi, LWSIFR_CLIENT, LRS_ESTABLISHED,
				    &role_ops_raw_skt);
		aws_lws_header_table_detach(wsi, 1);

		return NULL;
	}

	/*
	 * 04 example client handshake
	 *
	 * GET /chat HTTP/1.1
	 * Host: server.example.com
	 * Upgrade: websocket
	 * Connection: Upgrade
	 * Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
	 * Sec-WebSocket-Origin: http://example.com
	 * Sec-WebSocket-Protocol: chat, superchat
	 * Sec-WebSocket-Version: 4
	 */

	path = aws_lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI);
	if (!path) {
		if (wsi->stash && wsi->stash->cis[CIS_PATH] &&
			wsi->stash->cis[CIS_PATH][0])
			path = wsi->stash->cis[CIS_PATH];
		else
			path = "/";
	}

	p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p),
			  "%s %s HTTP/1.1\x0d\x0a", meth, path);

	p += aws_lws_snprintf(p,  aws_lws_ptr_diff_size_t(end, p),
			  "Pragma: no-cache\x0d\x0a"
			  "Cache-Control: no-cache\x0d\x0a");

	p += aws_lws_snprintf(p,  aws_lws_ptr_diff_size_t(end, p),
			  "Host: %s\x0d\x0a",
			  aws_lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_HOST));

	if (aws_lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_ORIGIN)) {
		if (aws_lws_check_opt(wsi->a.context->options,
				  LWS_SERVER_OPTION_JUST_USE_RAW_ORIGIN))
			p += aws_lws_snprintf(p,  aws_lws_ptr_diff_size_t(end, p),
					  "Origin: %s\x0d\x0a",
					  aws_lws_hdr_simple_ptr(wsi,
						     _WSI_TOKEN_CLIENT_ORIGIN));
		else
			p += aws_lws_snprintf(p,  aws_lws_ptr_diff_size_t(end, p),
					  "Origin: %s://%s\x0d\x0a",
					  wsi->flags & LCCSCF_USE_SSL ?
							 "https" : "http",
					  aws_lws_hdr_simple_ptr(wsi,
						     _WSI_TOKEN_CLIENT_ORIGIN));
	}

	if (wsi->flags & LCCSCF_HTTP_MULTIPART_MIME) {
		p1 = (char *)aws_lws_http_multipart_headers(wsi, (uint8_t *)p);
		if (!p1)
			return NULL;
		p = p1;
	}

#if defined(LWS_WITH_HTTP_PROXY)
	if (wsi->parent &&
	    aws_lws_hdr_total_length(wsi->parent, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p),
				  "Content-Length: %s\x0d\x0a",
			aws_lws_hdr_simple_ptr(wsi->parent, WSI_TOKEN_HTTP_CONTENT_LENGTH));
		if (atoi(aws_lws_hdr_simple_ptr(wsi->parent, WSI_TOKEN_HTTP_CONTENT_LENGTH)))
			wsi->client_http_body_pending = 1;
	}
	if (wsi->parent &&
	    aws_lws_hdr_total_length(wsi->parent, WSI_TOKEN_HTTP_AUTHORIZATION)) {
		p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p),
				  "Authorization: %s\x0d\x0a",
			aws_lws_hdr_simple_ptr(wsi->parent, WSI_TOKEN_HTTP_AUTHORIZATION));
	}
	if (wsi->parent &&
	    aws_lws_hdr_total_length(wsi->parent, WSI_TOKEN_HTTP_CONTENT_TYPE)) {
		p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p),
				  "Content-Type: %s\x0d\x0a",
			aws_lws_hdr_simple_ptr(wsi->parent, WSI_TOKEN_HTTP_CONTENT_TYPE));
	}
#endif

#if defined(LWS_ROLE_WS)
	if (wsi->do_ws) {
		const char *conn1 = "";
	//	if (!wsi->client_pipeline)
	//		conn1 = "close, ";
		p = aws_lws_generate_client_ws_handshake(wsi, p, conn1);
	} else
#endif
	{
		if (!wsi->client_pipeline)
			p += aws_lws_snprintf(p, 64, "connection: close\x0d\x0a");
	}

	/* give userland a chance to append, eg, cookies */

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)
	if (wsi->flags & LCCSCF_CACHE_COOKIES)
		aws_lws_cookie_send_cookies(wsi, &p, end);
#endif

	if (wsi->a.protocol->callback(wsi,
			LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
			wsi->user_space, &p,
			(unsigned int)((pkt + wsi->a.context->pt_serv_buf_size) - p - 12)))
		return NULL;

	if (wsi->flags & LCCSCF_HTTP_X_WWW_FORM_URLENCODED) {
		p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p), "Content-Type: application/x-www-form-urlencoded\x0d\x0a");
		p += aws_lws_snprintf(p,  aws_lws_ptr_diff_size_t(end, p), "Content-Length: %lu\x0d\x0a", wsi->http.writeable_len);
		aws_lws_client_http_body_pending(wsi, 1);
	}

	p += aws_lws_snprintf(p,  aws_lws_ptr_diff_size_t(end, p), "\x0d\x0a");

	if (wsi->client_http_body_pending || aws_lws_has_buffered_out(wsi))
		aws_lws_callback_on_writable(wsi);

	aws_lws_metrics_caliper_bind(wsi->cal_conn, wsi->a.context->mt_http_txn);
#if defined(LWS_WITH_CONMON)
	wsi->conmon_datum = aws_lws_now_usecs();
#endif

	// puts(pkt);

	return p;
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
#if defined(LWS_WITH_HTTP_BASIC_AUTH)

int
aws_lws_http_basic_auth_gen(const char *user, const char *pw, char *buf, size_t len)
{
	size_t n = strlen(user), m = strlen(pw);
	char b[128];

	if (len < 6 + ((4 * (n + m + 1)) / 3) + 1)
		return 1;

	memcpy(buf, "Basic ", 6);

	n = (unsigned int)aws_lws_snprintf(b, sizeof(b), "%s:%s", user, pw);
	if (n >= sizeof(b) - 2)
		return 2;

	aws_lws_b64_encode_string(b, (int)n, buf + 6, (int)len - 6);
	buf[len - 1] = '\0';

	return 0;
}

#endif

int
aws_lws_http_client_read(struct aws_lws *wsi, char **buf, int *len)
{
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	struct aws_lws_tokens eb;
	int buffered, n, consumed = 0;

	/*
	 * If the caller provided a non-NULL *buf and nonzero *len, we should
	 * use that as the buffer for the read action, limititing it to *len
	 * (actual payload will be less if chunked headers inside).
	 *
	 * If it's NULL / 0 length, buflist_aware_read will use the pt_serv_buf
	 */

	eb.token = (unsigned char *)*buf;
	eb.len = *len;

	buffered = aws_lws_buflist_aware_read(pt, wsi, &eb, 0, __func__);
	*buf = (char *)eb.token; /* may be pointing to buflist or pt_serv_buf */
	*len = 0;

	/*
	 * we're taking on responsibility for handling used / unused eb
	 * when we leave, via aws_lws_buflist_aware_finished_consuming()
	 */

//	aws_lwsl_notice("%s: eb.len %d ENTRY chunk remaining %d\n", __func__, eb.len,
//			wsi->chunk_remaining);

	/* allow the source to signal he has data again next time */
	if (aws_lws_change_pollfd(wsi, 0, LWS_POLLIN))
		return -1;

	if (buffered < 0) {
		aws_lwsl_debug("%s: SSL capable error\n", __func__);

		if (wsi->http.ah &&
		    wsi->http.ah->parser_state == WSI_PARSING_COMPLETE &&
		    !aws_lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH))
			/*
			 * We had the headers from this stream, but as there
			 * was no content-length: we had to wait until the
			 * stream ended to inform the user code the transaction
			 * has completed to the best of our knowledge
			 */
			if (aws_lws_http_transaction_completed_client(wsi))
				/*
				 * We're going to close anyway, but that api has
				 * warn_unused_result
				 */
				return -1;

		return -1;
	}

	if (eb.len <= 0)
		return 0;

	*len = eb.len;
	wsi->client_rx_avail = 0;

	/*
	 * server may insist on transfer-encoding: chunked,
	 * so http client must deal with it
	 */
spin_chunks:
	//aws_lwsl_notice("%s: len %d SPIN chunk remaining %d\n", __func__, *len,
	//		wsi->chunk_remaining);
	while (wsi->chunked && (wsi->chunk_parser != ELCP_CONTENT) && *len) {
		switch (wsi->chunk_parser) {
		case ELCP_HEX:
			if ((*buf)[0] == '\x0d') {
				wsi->chunk_parser = ELCP_CR;
				break;
			}
			n = aws_char_to_hex((*buf)[0]);
			if (n < 0) {
				aws_lwsl_err("%s: chunking failure A\n", __func__);
				return -1;
			}
			wsi->chunk_remaining <<= 4;
			wsi->chunk_remaining |= n;
			break;
		case ELCP_CR:
			if ((*buf)[0] != '\x0a') {
				aws_lwsl_err("%s: chunking failure B\n", __func__);
				return -1;
			}
			if (wsi->chunk_remaining) {
				wsi->chunk_parser = ELCP_CONTENT;
				//aws_lwsl_notice("starting chunk size %d (block rem %d)\n",
				//		wsi->chunk_remaining, *len);
				break;
			}

			wsi->chunk_parser = ELCP_TRAILER_CR;
			break;

		case ELCP_CONTENT:
			break;

		case ELCP_POST_CR:
			if ((*buf)[0] != '\x0d') {
				aws_lwsl_err("%s: chunking failure C\n", __func__);
				aws_lwsl_hexdump_err(*buf, (unsigned int)*len);

				return -1;
			}

			wsi->chunk_parser = ELCP_POST_LF;
			break;

		case ELCP_POST_LF:
			if ((*buf)[0] != '\x0a') {
				aws_lwsl_err("%s: chunking failure D\n", __func__);

				return -1;
			}

			wsi->chunk_parser = ELCP_HEX;
			wsi->chunk_remaining = 0;
			break;

		case ELCP_TRAILER_CR:
			if ((*buf)[0] != '\x0d') {
				aws_lwsl_err("%s: chunking failure F\n", __func__);
				aws_lwsl_hexdump_err(*buf, (unsigned int)*len);

				return -1;
			}

			wsi->chunk_parser = ELCP_TRAILER_LF;
			break;

		case ELCP_TRAILER_LF:
			if ((*buf)[0] != '\x0a') {
				aws_lwsl_err("%s: chunking failure F\n", __func__);
				aws_lwsl_hexdump_err(*buf, (unsigned int)*len);

				return -1;
			}

			(*buf)++;
			(*len)--;
			consumed++;

			aws_lwsl_info("final chunk\n");
			goto completed;
		}
		(*buf)++;
		(*len)--;
		consumed++;
	}

	if (wsi->chunked && !wsi->chunk_remaining)
		goto account_and_ret;

	if (wsi->http.rx_content_remain &&
	    wsi->http.rx_content_remain < (unsigned int)*len)
		n = (int)wsi->http.rx_content_remain;
	else
		n = *len;

	if (wsi->chunked && wsi->chunk_remaining &&
	    wsi->chunk_remaining < n)
		n = wsi->chunk_remaining;

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_WITH_HUBBUB)
	/* hubbub */
	if (wsi->http.perform_rewrite)
		aws_lws_rewrite_parse(wsi->http.rw, (unsigned char *)*buf, n);
	else
#endif
	{
		if (
#if defined(LWS_WITH_HTTP_PROXY)
		    !wsi->protocol_bind_balance ==
		    !!wsi->http.proxy_clientside
#else
		    !!wsi->protocol_bind_balance
#endif
		  ) {
			int q;

			q = aws_user_callback_handle_rxflow(wsi->a.protocol->callback,
				wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
				wsi->user_space, *buf, (unsigned int)n);
			if (q) {
				aws_lwsl_info("%s: RECEIVE_CLIENT_HTTP_READ returned %d\n",
						__func__, q);

				return q;
			}
		} else
			aws_lwsl_notice("%s: swallowed read (%d)\n", __func__, n);
	}

	(*buf) += n;
	*len -= n;
	if (wsi->chunked && wsi->chunk_remaining)
		wsi->chunk_remaining -= n;

	//aws_lwsl_notice("chunk_remaining <- %d, block remaining %d\n",
	//		wsi->chunk_remaining, *len);

	consumed += n;
	//eb.token += n;
	//eb.len -= n;

	if (wsi->chunked && !wsi->chunk_remaining)
		wsi->chunk_parser = ELCP_POST_CR;

	if (wsi->chunked && *len)
		goto spin_chunks;

	if (wsi->chunked)
		goto account_and_ret;

	/* if we know the content length, decrement the content remaining */
	if (wsi->http.rx_content_length > 0)
		wsi->http.rx_content_remain -= (unsigned int)n;

	// aws_lwsl_notice("rx_content_remain %lld, rx_content_length %lld, giv %d\n",
	//	    wsi->http.rx_content_remain, wsi->http.rx_content_length,
	//	    wsi->http.content_length_given);

	if (wsi->http.rx_content_remain || !wsi->http.content_length_given)
		goto account_and_ret;

completed:

	if (aws_lws_http_transaction_completed_client(wsi)) {
		aws_lwsl_info("%s: transaction completed says -1\n", __func__);
		return -1;
	}

account_and_ret:
//	aws_lwsl_warn("%s: on way out, consuming %d / %d\n", __func__, consumed, eb.len);
	if (aws_lws_buflist_aware_finished_consuming(wsi, &eb, consumed, buffered,
							__func__))
		return -1;

	return 0;
}

#endif

static uint8_t hnames2[] = {
	_WSI_TOKEN_CLIENT_ORIGIN,
	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	_WSI_TOKEN_CLIENT_METHOD,
	_WSI_TOKEN_CLIENT_IFACE
};

/**
 * aws_lws_client_reset() - retarget a connected wsi to start over with a new
 * 			connection (ie, redirect)
 *			this only works if still in HTTP, ie, not upgraded yet
 * wsi:		connection to reset
 * address:	network address of the new server
 * port:	port to connect to
 * path:	uri path to connect to on the new server
 * host:	host header to send to the new server
 */
struct aws_lws *
aws_lws_client_reset(struct aws_lws **pwsi, int ssl, const char *address, int port,
		 const char *path, const char *host, char weak)
{
	struct aws_lws_context_per_thread *pt;
#if defined(LWS_ROLE_WS)
	struct aws__lws_websocket_related *ws;
#endif
	const char *cisin[CIS_COUNT];
	struct aws_lws *wsi;
	size_t o;
	int n;

	if (!pwsi)
		return NULL;

	wsi = *pwsi;
	pt = &wsi->a.context->pt[(int)wsi->tsi];

	aws_lwsl_debug("%s: %s: redir %d: %s\n", __func__, aws_lws_wsi_tag(wsi),
			wsi->redirects, address);

	if (wsi->redirects == 4) {
		aws_lwsl_err("%s: Too many redirects\n", __func__);
		return NULL;
	}
	wsi->redirects++;

	/*
	 * goal is to close our role part, close the sockfd, detach the ah
	 * but leave our wsi extant and still bound to whatever vhost it was
	 */

	o = path[0] == '/' && path[1] == '/';

	memset((char *)cisin, 0, sizeof(cisin));

	cisin[CIS_ADDRESS]	= address;
	cisin[CIS_PATH]		= path + o;
	cisin[CIS_HOST]		= host;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(hnames2); n++)
		cisin[n + 3] = aws_lws_hdr_simple_ptr(wsi, hnames2[n]);

#if defined(LWS_WITH_TLS)
	cisin[CIS_ALPN]		= wsi->alpn;
#endif

	if (aws_lws_client_stash_create(wsi, cisin))
		return NULL;

	if (!port) {
		aws_lwsl_info("%s: forcing port 443\n", __func__);

		port = 443;
		ssl = 1;
	}

	wsi->c_port = (uint16_t)port;

	wsi->flags = (wsi->flags & (~LCCSCF_USE_SSL)) |
					(ssl ? LCCSCF_USE_SSL : 0);

	if (!cisin[CIS_ALPN] || !cisin[CIS_ALPN][0])
#if defined(LWS_ROLE_H2)
		cisin[CIS_ALPN] = "h2,http/1.1";
#else
		cisin[CIS_ALPN] = "http/1.1";
#endif

	aws_lwsl_notice("%s: REDIRECT %s:%d, path='%s', ssl = %d, alpn='%s'\n",
		    __func__, address, port, path, ssl, cisin[CIS_ALPN]);

	aws_lws_pt_lock(pt, __func__);
	aws___remove_wsi_socket_from_fds(wsi);
	aws_lws_pt_unlock(pt);

#if defined(LWS_ROLE_WS)
	if (weak) {
		ws = wsi->ws;
		wsi->ws = NULL;
	}
#endif

	/*
	 * After this point we can't trust the incoming strings like address,
	 * path any more, since they may have been pointing into the old ah.
	 *
	 * We must use the copies in the wsi->stash instead if we want them.
	 */

	aws___lws_reset_wsi(wsi); /* detaches ah here */
#if defined(LWS_ROLE_WS)
	if (weak)
		wsi->ws = ws;
#endif
	wsi->client_pipeline = 1;

	/*
	 * Will complete at close flow
	 */

	wsi->close_is_redirect = 1;

	return *pwsi;
}

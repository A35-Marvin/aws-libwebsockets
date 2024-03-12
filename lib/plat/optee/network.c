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

#if defined(LWS_WITH_MBEDTLS)
#if defined(LWS_HAVE_MBEDTLS_NET_SOCKETS)
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif
#endif

int
aws_lws_plat_pipe_create(struct aws_lws *wsi)
{
	return 1;
}

int
aws_lws_plat_pipe_signal(struct aws_lws *wsi)
{
	return 1;
}

void
aws_lws_plat_pipe_close(struct aws_lws *wsi)
{
}

int
aws_lws_send_pipe_choked(struct aws_lws *wsi)
{
	struct aws_lws *wsi_eff;

#if defined(LWS_WITH_HTTP2)
	wsi_eff = aws_lws_get_network_wsi(wsi);
#else
	wsi_eff = wsi;
#endif

	/* the fact we checked implies we avoided back-to-back writes */
	wsi_eff->could_have_pending = 0;

	/* treat the fact we got a truncated send pending as if we're choked */
	if (aws_lws_has_buffered_out(wsi_eff)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    || wsi->http.comp_ctx.buflist_comp ||
	       wsi->http.comp_ctx.may_have_more
#endif
	)
		return 1;

	/* okay to send another packet without blocking */

	return 0;
}

int
aws_lws_poll_listen_fd(struct aws_lws_pollfd *fd)
{
//	return poll(fd, 1, 0);

	return 0;
}


int
aws__lws_plat_service_tsi(struct aws_lws_context *context, int timeout_ms, int tsi)
{
	aws_lws_usec_t timeout_us = timeout_ms * LWS_US_PER_MS;
	struct aws_lws_context_per_thread *pt;
	int n = -1, m, c, a = 0;
	//char buf;

	/* stay dead once we are dead */

	if (!context)
		return 1;

	pt = &context->pt[tsi];

	if (timeout_ms < 0)
		timeout_ms = 0;
	else
		timeout_ms = 2000000000;

	if (!pt->service_tid_detected && context->vhost_list) {
		struct aws_lws _lws;

		memset(&_lws, 0, sizeof(_lws));
		_lws.context = context;

		pt->service_tid = context->vhost_list->protocols[0].callback(
			&_lws, LWS_CALLBACK_GET_THREAD_ID, NULL, NULL, 0);
		pt->service_tid_detected = 1;
	}

	/*
	 * is there anybody with pending stuff that needs service forcing?
	 */
	if (aws_lws_service_adjust_timeout(context, 1, tsi)) {
again:
		a = 0;
		if (timeout_us) {
			aws_lws_usec_t us;

			aws_lws_pt_lock(pt, __func__);
			/* don't stay in poll wait longer than next hr timeout */
			us = aws___lws_sul_service_ripe(pt->pt_sul_owner,
						    LWS_COUNT_PT_SUL_OWNERS,
						    aws_lws_now_usecs());
			if (us && us < timeout_us)
				timeout_us = us;

			aws_lws_pt_unlock(pt);
		}

		n = poll(pt->fds, pt->fds_count, timeout_us / LWS_US_PER_MS);

		m = 0;

		if (pt->context->tls_ops &&
		    pt->context->tls_ops->fake_POLLIN_for_buffered)
			m = pt->context->tls_ops->fake_POLLIN_for_buffered(pt);

		if (/*!pt->ws.rx_draining_ext_list && */!m && !n) /* nothing to do */
			return 0;
	} else
		a = 1;

	m = aws_lws_service_flag_pending(context, tsi);
	if (m)
		c = -1; /* unknown limit */
	else
		if (n < 0) {
			if (LWS_ERRNO != LWS_EINTR)
				return -1;
			return 0;
		} else
			c = n;

	/* any socket with events to service? */
	for (n = 0; n < (int)pt->fds_count && c; n++) {
		if (!pt->fds[n].revents)
			continue;

		c--;
#if 0
		if (pt->fds[n].fd == pt->dummy_pipe_fds[0]) {
			if (read(pt->fds[n].fd, &buf, 1) != 1)
				aws_lwsl_err("Cannot read from dummy pipe.");
			continue;
		}
#endif
		m = aws_lws_service_fd_tsi(context, &pt->fds[n], tsi);
		if (m < 0)
			return -1;
		/* if something closed, retry this slot */
		if (m)
			n--;
	}

	if (a)
		goto again;

	return 0;
}

int
aws_lws_plat_service(struct aws_lws_context *context, int timeout_ms)
{
	return aws__lws_plat_service_tsi(context, timeout_ms, 0);
}

int
aws_lws_plat_set_socket_options(struct aws_lws_vhost *vhost, int fd, int unix_skt)
{
	return 0;
}


int
aws_lws_plat_write_cert(struct aws_lws_vhost *vhost, int is_key, int fd, void *buf,
			size_t len)
{
	return 1;
}


/* cast a struct sockaddr_in6 * into addr for ipv6 */

int
aws_lws_interface_to_sa(int ipv6, const char *ifname, struct sockaddr_in *addr,
		    size_t addrlen)
{
	return -1;
}

void
aws_lws_plat_insert_socket_into_fds(struct aws_lws_context *context, struct aws_lws *wsi)
{
	struct aws_lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	pt->fds[pt->fds_count++].revents = 0;
}

void
aws_lws_plat_delete_socket_from_fds(struct aws_lws_context *context,
						struct aws_lws *wsi, int m)
{
	struct aws_lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	pt->fds_count--;
}

int
aws_lws_plat_change_pollfd(struct aws_lws_context *context,
		      struct aws_lws *wsi, struct aws_lws_pollfd *pfd)
{
	return 0;
}

const char *
aws_lws_plat_inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
	//return inet_ntop(af, src, dst, cnt);
	return "aws_lws_plat_inet_ntop";
}

int
aws_lws_plat_inet_pton(int af, const char *src, void *dst)
{
	//return inet_pton(af, src, dst);
	return 1;
}

int
aws_lws_plat_set_socket_options_ip(int fd, uint8_t pri, unsigned int aws_lws_flags)
{
	return 0;
}

int
aws_lws_plat_vhost_tls_client_ctx_init(struct aws_lws_vhost *vhost)
{
	return 0;
}

#if defined(LWS_WITH_MBEDTLS)
int
aws_lws_plat_mbedtls_net_send(void *ctx, const uint8_t *buf, size_t len)
{
	int fd = ((mbedtls_net_context *) ctx)->fd;
	int ret;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	ret = write(fd, buf, len);
	if (ret >= 0)
		return ret;

	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	if (errno == EPIPE || errno == ECONNRESET)
		return MBEDTLS_ERR_NET_CONN_RESET;

	if( errno == EINTR )
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	return MBEDTLS_ERR_NET_SEND_FAILED;
}

int
aws_lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = ((mbedtls_net_context *) ctx)->fd;
	int ret;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	ret = (int)read(fd, buf, len);
	if (ret >= 0)
		return ret;

	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_READ;

	if (errno == EPIPE || errno == ECONNRESET)
		return MBEDTLS_ERR_NET_CONN_RESET;

	if (errno == EINTR)
		return MBEDTLS_ERR_SSL_WANT_READ;

	return MBEDTLS_ERR_NET_RECV_FAILED;
}

#endif

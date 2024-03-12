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

struct aws_lws *
wsi_from_fd(const struct aws_lws_context *context, int fd)
{
	struct aws_lws **p, **done;

	if (!context->max_fds_unrelated_to_ulimit)
		return context->aws_lws_lookup[fd - aws_lws_plat_socket_offset()];

	/* slow fds handling */

	p = context->aws_lws_lookup;
	done = &p[context->max_fds];

	while (p != done) {
		if (*p && (*p)->desc.sockfd == fd)
			return *p;
		p++;
	}

	return NULL;
}

#if defined(_DEBUG)
int
sanity_assert_no_wsi_traces(const struct aws_lws_context *context, struct aws_lws *wsi)
{
	struct aws_lws **p, **done;

	if (!context->max_fds_unrelated_to_ulimit)
		/* can't tell */
		return 0;

	/* slow fds handling */

	p = context->aws_lws_lookup;
	done = &p[context->max_fds];

	/* confirm the wsi doesn't already exist */

	while (p != done && *p != wsi)
		p++;

	if (p == done)
		return 0;

	assert(0); /* this wsi is still mentioned inside lws */

	return 1;
}

int
sanity_assert_no_sockfd_traces(const struct aws_lws_context *context,
			       aws_lws_sockfd_type sfd)
{
#if LWS_MAX_SMP > 1
	/*
	 * We can't really do this test... another thread can accept and
	 * reuse the closed fd
	 */
	return 0;
#else
	struct aws_lws **p, **done;

	if (sfd == LWS_SOCK_INVALID || !context->aws_lws_lookup)
		return 0;

	if (!context->max_fds_unrelated_to_ulimit &&
	    context->aws_lws_lookup[sfd - aws_lws_plat_socket_offset()]) {
		assert(0); /* the fd is still in use */
		return 1;
	}

	/* slow fds handling */

	p = context->aws_lws_lookup;
	done = &p[context->max_fds];

	/* confirm the sfd not already in use */

	while (p != done && (!*p || (*p)->desc.sockfd != sfd))
		p++;

	if (p == done)
		return 0;

	assert(0); /* this fd is still in the tables */

	return 1;
#endif
}
#endif


int
insert_wsi(const struct aws_lws_context *context, struct aws_lws *wsi)
{
	struct aws_lws **p, **done;

	if (sanity_assert_no_wsi_traces(context, wsi))
		return 0;

	if (!context->max_fds_unrelated_to_ulimit) {
		assert(context->aws_lws_lookup[wsi->desc.sockfd -
		                           aws_lws_plat_socket_offset()] == 0);

		context->aws_lws_lookup[wsi->desc.sockfd - \
				  aws_lws_plat_socket_offset()] = wsi;

		return 0;
	}

	/* slow fds handling */

	p = context->aws_lws_lookup;
	done = &p[context->max_fds];

	/* confirm fd isn't already in use by a wsi */

	if (sanity_assert_no_sockfd_traces(context, wsi->desc.sockfd))
		return 0;

	p = context->aws_lws_lookup;

	/* find an empty slot */

	while (p != done && *p)
		p++;

	if (p == done) {
		aws_lwsl_err("%s: reached max fds\n", __func__);
		return 1;
	}

	*p = wsi;

	return 0;
}



void
delete_from_fd(const struct aws_lws_context *context, int fd)
{

	struct aws_lws **p, **done;

	if (!context->max_fds_unrelated_to_ulimit) {
		if (context->aws_lws_lookup)
			context->aws_lws_lookup[fd - aws_lws_plat_socket_offset()] = NULL;

		return;
	}

	/* slow fds handling */

	p = context->aws_lws_lookup;
	assert(p);

	done = &p[context->max_fds];

	/* find the match */

	while (p != done && (!*p || (*p)->desc.sockfd != fd))
		p++;

	if (p != done)
		*p = NULL;

#if defined(_DEBUG)
	p = context->aws_lws_lookup;
	while (p != done && (!*p || (*p)->desc.sockfd != fd))
		p++;

	if (p != done) {
		aws_lwsl_err("%s: fd %d in aws_lws_lookup again at %d\n", __func__,
				fd, (int)(p - context->aws_lws_lookup));
		assert(0);
	}
#endif
}

void
delete_from_fdwsi(const struct aws_lws_context *context, struct aws_lws *wsi)
{

	struct aws_lws **p, **done;

	if (!context->max_fds_unrelated_to_ulimit)
		return;


	/* slow fds handling */

	p = context->aws_lws_lookup;
	done = &p[context->max_fds];

	/* find the match */

	while (p != done && (!*p || (*p) != wsi))
		p++;

	if (p != done)
		*p = NULL;
}

void
aws_lws_plat_insert_socket_into_fds(struct aws_lws_context *context, struct aws_lws *wsi)
{
	struct aws_lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (context->event_loop_ops->io)
		context->event_loop_ops->io(wsi, LWS_EV_START | LWS_EV_READ);

	pt->fds[pt->fds_count++].revents = 0;
}

void
aws_lws_plat_delete_socket_from_fds(struct aws_lws_context *context,
						struct aws_lws *wsi, int m)
{
	struct aws_lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	if (context->event_loop_ops->io)
		context->event_loop_ops->io(wsi,
				LWS_EV_STOP | LWS_EV_READ | LWS_EV_WRITE);

	pt->fds_count--;
}

int
aws_lws_plat_change_pollfd(struct aws_lws_context *context,
		      struct aws_lws *wsi, struct aws_lws_pollfd *pfd)
{
	return 0;
}

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
#include "private-lib-system-dhcpclient.h"

void
aws_lws_dhcpc_retry_write(struct aws_lws_sorted_usec_list *sul)
{
	aws_lws_dhcpc_req_t *r = aws_lws_container_of(sul, aws_lws_dhcpc_req_t, sul_write);

	aws_lwsl_debug("%s\n", __func__);

	if (r && r->wsi_raw)
		aws_lws_callback_on_writable(r->wsi_raw);
}

static void
aws_lws_dhcpc_destroy(aws_lws_dhcpc_req_t **pr)
{
	aws_lws_dhcpc_req_t *r = *pr;

	aws_lws_sul_cancel(&r->sul_conn);
	aws_lws_sul_cancel(&r->sul_write);
	aws_lws_sul_cancel(&r->sul_renew);

	if (r->wsi_raw)
		aws_lws_set_timeout(r->wsi_raw, 1, LWS_TO_KILL_ASYNC);

	aws_lws_dll2_remove(&r->list);

	aws_lws_free_set_NULL(r);
}

int
aws_lws_dhcpc_status(struct aws_lws_context *context, aws_lws_sockaddr46 *sa46)
{
	aws_lws_dhcpc_req_t *r;

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, context->dhcpc_owner.head) {
		r = (aws_lws_dhcpc_req_t *)p;

		if (r->state == LDHC_BOUND) {
			if (sa46) {
				memcpy(sa46, &r->is.sa46[LWSDH_SA46_DNS_SRV_1],
				       sizeof(*sa46));
			}
			return 1;
		}

	} aws_lws_end_foreach_dll(p);

	return 0;
}

static aws_lws_dhcpc_req_t *
aws_lws_dhcpc_find(struct aws_lws_context *context, const char *iface, int af)
{
	aws_lws_dhcpc_req_t *r;

	/* see if we are already looking after this af / iface combination */

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, context->dhcpc_owner.head) {
		r = (aws_lws_dhcpc_req_t *)p;

		if (!strcmp((const char *)&r[1], iface) && af == r->af)
			return r; /* yes...  */

	} aws_lws_end_foreach_dll(p);

	return NULL;
}

/*
 * Create a persistent dhcp client entry for network interface "iface" and AF
 * type "af"
 */

int
aws_lws_dhcpc_request(struct aws_lws_context *context, const char *iface, int af,
		  dhcpc_cb_t cb, void *opaque)
{
	aws_lws_dhcpc_req_t *r = aws_lws_dhcpc_find(context, iface, af);
	int n;

	/* see if we are already looking after this af / iface combination */

	if (r)
		return 0;

	/* nope... let's create a request object as he asks */

	n = (int)strlen(iface);
	r = aws_lws_zalloc(sizeof(*r) + (unsigned int)n + 1u, __func__);
	if (!r)
		return 1;

	memcpy(&r[1], iface, (unsigned int)n + 1);
	r->af = (uint8_t)af;
	r->cb = cb;
	r->opaque = opaque;
	r->context = context;
	r->state = LDHC_INIT;

	aws_lws_strncpy(r->is.ifname, iface, sizeof(r->is.ifname));

	aws_lws_dll2_add_head(&r->list, &context->dhcpc_owner); /* add him to list */

	aws_lws_dhcpc4_retry_conn(&r->sul_conn);

	return 0;
}

/*
 * Destroy every DHCP client object related to interface "iface"
 */

static int
_remove_if(struct aws_lws_dll2 *d, void *opaque)
{
	aws_lws_dhcpc_req_t *r = aws_lws_container_of(d, aws_lws_dhcpc_req_t, list);

	if (!opaque || !strcmp((const char *)&r[1], (const char *)opaque))
		aws_lws_dhcpc_destroy(&r);

	return 0;
}

int
aws_lws_dhcpc_remove(struct aws_lws_context *context, const char *iface)
{
	aws_lws_dll2_foreach_safe(&context->dhcpc_owner, (void *)iface, _remove_if);

	return 0;
}

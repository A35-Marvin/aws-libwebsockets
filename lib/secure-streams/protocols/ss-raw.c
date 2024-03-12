/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 *
 * This is the glue that wires up raw-socket to Secure Streams.
 */

#include <private-lib-core.h>

int
secstream_raw(struct aws_lws *wsi, enum aws_lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
#if defined(LWS_WITH_SERVER)
	struct aws_lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
#endif
	aws_lws_ss_handle_t *h = (aws_lws_ss_handle_t *)aws_lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + 1520], *p = &buf[LWS_PRE],
		*end = &buf[sizeof(buf) - 1];
	aws_lws_ss_state_return_t r;
	size_t buflen;
	int f = 0;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		assert(h);
		assert(h->policy);
		aws_lwsl_info("%s: %s, %s CLIENT_CONNECTION_ERROR: %s\n", __func__,
			  aws_lws_ss_tag(h), h->policy->streamtype, in ? (char *)in : "(null)");

#if defined(LWS_WITH_CONMON)
		aws_lws_conmon_ss_json(h);
#endif

		r = aws_lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
		if (r == LWSSSSRET_DESTROY_ME)
			return aws__lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		h->wsi = NULL;
		r = aws_lws_ss_backoff(h);
		if (r != LWSSSSRET_OK)
			return aws__lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!h)
			break;
		aws_lws_sul_cancel(&h->sul_timeout);

#if defined(LWS_WITH_CONMON)
		aws_lws_conmon_ss_json(h);
#endif

		aws_lwsl_info("%s: %s, %s RAW_CLOSE\n", __func__, aws_lws_ss_tag(h),
			  h->policy ? h->policy->streamtype : "no policy");
		h->wsi = NULL;
#if defined(LWS_WITH_SERVER)
		aws_lws_pt_lock(pt, __func__);
		aws_lws_dll2_remove(&h->cli_list);
		aws_lws_pt_unlock(pt);
#endif

		/* wsi is going down anyway */
		r = aws_lws_ss_event_helper(h, LWSSSCS_DISCONNECTED);
		if (r == LWSSSSRET_DESTROY_ME)
			return aws__lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

		if (h->policy && !(h->policy->flags & LWSSSPOLF_OPPORTUNISTIC) &&
#if defined(LWS_WITH_SERVER)
			    !(h->info.flags & LWSSSINFLAGS_ACCEPTED) && /* not server */
#endif
		    !h->txn_ok && !wsi->a.context->being_destroyed) {
			r = aws_lws_ss_backoff(h);
			if (r != LWSSSSRET_OK)
				return aws__lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
			break;
		}

		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		aws_lwsl_info("%s: RAW_CONNECTED\n", __func__);

		h->retry = 0;
		h->seqstate = SSSEQ_CONNECTED;
		aws_lws_sul_cancel(&h->sul);
#if defined(LWS_WITH_SYS_METRICS)
		/*
		 * If any hanging caliper measurement, dump it, and free any tags
		 */
		aws_lws_metrics_caliper_report_hist(h->cal_txn, (struct aws_lws *)NULL);
#endif
		r = aws_lws_ss_event_helper(h, LWSSSCS_CONNECTED);
		if (r != LWSSSSRET_OK)
			return aws__lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

		aws_lws_validity_confirmed(wsi);
		break;

	case LWS_CALLBACK_RAW_ADOPT:
		aws_lwsl_info("%s: RAW_ADOPT\n", __func__);
		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RAW_RX:
		if (!h || !h->info.rx)
			return 0;

		r = h->info.rx(ss_to_userobj(h), (const uint8_t *)in, len, 0);
		if (r != LWSSSSRET_OK)
			return aws__lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

		return 0; /* don't passthru */

	case LWS_CALLBACK_RAW_WRITEABLE:
		aws_lwsl_info("%s: RAW_WRITEABLE\n", __func__);
		if (!h || !h->info.tx)
			return 0;

		buflen = aws_lws_ptr_diff_size_t(end, p);
		r = h->info.tx(ss_to_userobj(h),  h->txord++, p, &buflen, &f);
		if (r == LWSSSSRET_TX_DONT_SEND)
			return 0;
		if (r < 0)
			return aws__lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

		/*
		 * flags are ignored with raw, there are no protocol payload
		 * boundaries, just an arbitrarily-fragmented bytestream
		 */

		p += buflen;
		if (aws_lws_write(wsi, buf + LWS_PRE, aws_lws_ptr_diff_size_t(p, buf + LWS_PRE),
			 LWS_WRITE_HTTP) != aws_lws_ptr_diff(p, buf + LWS_PRE)) {
			aws_lwsl_err("%s: write failed\n", __func__);
			return -1;
		}

		aws_lws_set_timeout(wsi, 0, 0);
		break;

	default:
		break;
	}

	return 0;
}

static int
secstream_connect_munge_raw(aws_lws_ss_handle_t *h, char *buf, size_t len,
			   struct aws_lws_client_connect_info *i,
			   union aws_lws_ss_contemp *ct)
{
	i->method = "RAW";

	return 0;
}


const struct aws_lws_protocols protocol_secstream_raw = {
	"lws-secstream-raw",
	secstream_raw,
	0,
	0,
	0, NULL, 0
};

const struct ss_pcols ss_pcol_raw = {
	"raw",
	"",
	&protocol_secstream_raw,
	secstream_connect_munge_raw,
	NULL, NULL
};

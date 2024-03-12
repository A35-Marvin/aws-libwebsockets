/*
 * lws-minimal-http-client-captive-portal
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates how to use the aws_lws_system captive portal detect integration
 *
 * We check for a captive portal by doing a GET from
 * http://connectivitycheck.android.com/generate_204, if we really are going
 * out on the Internet he'll return with a 204 response code and we will
 * understand there's no captive portal.  If we get something else, we take it
 * there is a captive portal.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static struct aws_lws_context *context;
static int interrupted, bad = 1, status;
static aws_lws_state_notify_link_t nl;

/*
 * this is the user code http handler
 */

static int
callback_http(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		aws_lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		interrupted = 1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		{
			char buf[128];

			aws_lws_get_peer_simple(wsi, buf, sizeof(buf));
			status = (int)aws_lws_http_client_http_response(wsi);

			aws_lwsl_user("Connected to %s, http response: %d\n",
					buf, status);
		}
		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		aws_lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);

#if 0  /* enable to dump the html */
		{
			const char *p = in;

			while (len--)
				if (*p < 0x7f)
					putchar(*p++);
				else
					putchar('.');
		}
#endif
		return 0; /* don't passthru */

	/* uninterpreted http content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char buffer[1024 + LWS_PRE];
			char *px = buffer + LWS_PRE;
			int lenx = sizeof(buffer) - LWS_PRE;

			if (aws_lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		aws_lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
		interrupted = 1;
		bad = status != 200;
		aws_lws_cancel_service(aws_lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		interrupted = 1;
		bad = status != 200;
		aws_lws_cancel_service(aws_lws_get_context(wsi)); /* abort poll wait */
		break;

	default:
		break;
	}

	return aws_lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * This is the platform's custom captive portal detection handler
 */

static int
callback_cpd_http(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	int resp;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		resp = (int)aws_lws_http_client_http_response(wsi);
		if (!resp)
			break;
		aws_lwsl_user("%s: established with resp %d\n", __func__, resp);
		switch (resp) {

		case HTTP_STATUS_NO_CONTENT:
			/*
			 * We got the 204 which is used to distinguish the real
			 * endpoint
			 */
			aws_lws_system_cpd_set(aws_lws_get_context(wsi),
					   LWS_CPD_INTERNET_OK);
			return 0;

		/* also case HTTP_STATUS_OK: ... */
		default:
			break;
		}

		/* fallthru */

	case LWS_CALLBACK_CLIENT_HTTP_REDIRECT:
		aws_lws_system_cpd_set(aws_lws_get_context(wsi), LWS_CPD_CAPTIVE_PORTAL);
		/* don't follow it, just report it */
		return 1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* only the first result counts */
		aws_lws_system_cpd_set(aws_lws_get_context(wsi), LWS_CPD_NO_INTERNET);
		break;

	default:
		break;
	}

	return aws_lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct aws_lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		0, 0, 0, NULL, 0
	}, {
		"lws-cpd-http",
		callback_cpd_http,
		0, 0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

/*
 * This triggers our platform implementation of captive portal detection, the
 * actual test can be whatever you need.
 *
 * In this example, we detect it using Android's
 *
 *   http://connectivitycheck.android.com/generate_204
 *
 * and seeing if we get an http 204 back.
 */

static int
captive_portal_detect_request(struct aws_lws_context *context)
{
	struct aws_lws_client_connect_info i;

	memset(&i, 0, sizeof i);
	i.context = context;
	i.port = 80;
	i.address = "connectivitycheck.android.com";
	i.path = "/generate_204";
	i.host = i.address;
	i.origin = i.address;
	i.method = "GET";

	i.protocol = "lws-cpd-http";

	return !aws_lws_client_connect_via_info(&i);
}


aws_lws_system_ops_t ops = {
	.captive_portal_detect_request = captive_portal_detect_request
};


static int
app_system_state_nf(aws_lws_state_manager_t *mgr, aws_lws_state_notify_link_t *link,
		    int current, int target)
{
	struct aws_lws_context *cx = aws_lws_system_context_from_system_mgr(mgr);

	switch (target) {
	case LWS_SYSTATE_CPD_PRE_TIME:
		if (aws_lws_system_cpd_state_get(cx))
			return 0; /* allow it */

		aws_lwsl_info("%s: LWS_SYSTATE_CPD_PRE_TIME\n", __func__);
		aws_lws_system_cpd_start(cx);
		/* we'll move the state on when we get a result */
		return 1;

	case LWS_SYSTATE_OPERATIONAL:
		if (current == LWS_SYSTATE_OPERATIONAL) {
			struct aws_lws_client_connect_info i;

			aws_lwsl_user("%s: OPERATIONAL, cpd %d\n", __func__,
					aws_lws_system_cpd_state_get(cx));

			/*
			 * When we reach the OPERATIONAL aws_lws_system state, we
			 * can do our main job knowing we have DHCP, ntpclient,
			 * captive portal testing done.
			 */

			if (aws_lws_system_cpd_state_get(cx) != LWS_CPD_INTERNET_OK) {
				aws_lwsl_warn("%s: There's no internet...\n", __func__);
				interrupted = 1;
				break;
			}

			memset(&i, 0, sizeof i);
			i.context = context;
			i.ssl_connection = LCCSCF_USE_SSL;
			i.ssl_connection |= LCCSCF_H2_QUIRK_OVERFLOWS_TXCR |
					    LCCSCF_H2_QUIRK_NGHTTP2_END_STREAM;
			i.port = 443;
			i.address = "warmcat.com";
			i.path = "/";
			i.host = i.address;
			i.origin = i.address;
			i.method = "GET";

			i.protocol = protocols[0].name;

			aws_lws_client_connect_via_info(&i);
			break;
		}
	default:
		break;
	}

	return 0;
}

static aws_lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

/*
 * We made this into a different thread to model it being run from completely
 * different codebase that's all linked together
 */


int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct aws_lws_context_creation_info info;
	const char *p;

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS minimal http client captive portal detect\n");

	memset(&info, 0, sizeof info);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.system_ops = &ops;
	info.protocols = protocols;

	/* integrate us with lws system state management when context created */

	nl.name = "app";
	nl.notify_cb = app_system_state_nf;
	info.register_notifier_list = app_notifier_list;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	while (!interrupted)
		if (aws_lws_service(context, 0))
			interrupted = 1;

	aws_lws_context_destroy(context);

	aws_lwsl_user("%s: finished %s\n", __func__, bad ? "FAIL": "OK");

	return bad;
}

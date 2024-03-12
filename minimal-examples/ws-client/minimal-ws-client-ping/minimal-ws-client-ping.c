/*
 * lws-minimal-ws-client-ping
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates keeping a ws connection validated by the lws validity
 * timer stuff without having to do anything in the code.  Use debug logging
 * -d1039 to see lws doing the pings / pongs in the background.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#if defined(WIN32)
#define HAVE_STRUCT_TIMESPEC
#if defined(pid_t)
#undef pid_t
#endif
#endif
#include <pthread.h>

static struct aws_lws_context *context;
static struct aws_lws *client_wsi;
static int interrupted, port = 443, ssl_connection = LCCSCF_USE_SSL;
static const char *server_address = "libwebsockets.org", *pro = "lws-mirror-protocol";
static aws_lws_sorted_usec_list_t sul;

static const aws_lws_retry_bo_t retry = {
	.secs_since_valid_ping = 3,
	.secs_since_valid_hangup = 10,
};

static void
connect_cb(aws_lws_sorted_usec_list_t *_sul)
{
	struct aws_lws_client_connect_info i;

	aws_lwsl_notice("%s: connecting\n", __func__);

	memset(&i, 0, sizeof(i));

	i.context = context;
	i.port = port;
	i.address = server_address;
	i.path = "/";
	i.host = i.address;
	i.origin = i.address;
	i.ssl_connection = ssl_connection;
	i.protocol = pro;
	i.alpn = "h2;http/1.1";
	i.local_protocol_name = "lws-ping-test";
	i.pwsi = &client_wsi;
	i.retry_and_idle_policy = &retry;

	if (!aws_lws_client_connect_via_info(&i))
		aws_lws_sul_schedule(context, 0, _sul, connect_cb, 5 * LWS_USEC_PER_SEC);
}

static int
callback_minimal_pingtest(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
			 void *user, void *in, size_t len)
{

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		aws_lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		aws_lws_sul_schedule(context, 0, &sul, connect_cb, 5 * LWS_USEC_PER_SEC);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		aws_lwsl_user("%s: established\n", __func__);
		break;

	default:
		break;
	}

	return aws_lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct aws_lws_protocols protocols[] = {
	{
		"lws-ping-test",
		callback_minimal_pingtest,
		0, 0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct aws_lws_context_creation_info info;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS minimal ws client PING\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;
#if defined(LWS_WITH_MBEDTLS) || defined(USE_WOLFSSL)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	info.client_ssl_ca_filepath = "./libwebsockets.org.cer";
#endif

	if ((p = aws_lws_cmdline_option(argc, argv, "--protocol")))
		pro = p;

	if ((p = aws_lws_cmdline_option(argc, argv, "--server"))) {
		server_address = p;
		pro = "lws-minimal";
		ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
	}

	if ((p = aws_lws_cmdline_option(argc, argv, "--port")))
		port = atoi(p);

	info.fd_limit_per_thread = 1 + 1 + 1;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	aws_lws_sul_schedule(context, 0, &sul, connect_cb, 100);

	while (n >= 0 && !interrupted)
		n = aws_lws_service(context, 0);

	aws_lws_context_destroy(context);
	aws_lwsl_user("Completed\n");

	return 0;
}

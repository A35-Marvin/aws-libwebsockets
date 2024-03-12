/*
 * lws-minimal-http-client
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the a minimal http client using lws.
 *
 * It visits https://warmcat.com/ and receives the html page there.  You
 * can dump the page data by changing the #if 0 below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad = 1, status;
static struct aws_lws *client_wsi;

static int
callback_http(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	uint8_t buf[1280];
	union aws_lws_tls_cert_info_results *ci =
		(union aws_lws_tls_cert_info_results *)buf;
#if defined(LWS_HAVE_CTIME_R)
	char date[32];
#endif

	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		aws_lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		client_wsi = NULL;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)aws_lws_http_client_http_response(wsi);
		aws_lwsl_notice("aws_lws_http_client_http_response %d\n", status);

		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_COMMON_NAME,
					    ci, sizeof(buf) - sizeof(*ci)))
			aws_lwsl_notice(" Peer Cert CN        : %s\n", ci->ns.name);

		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_ISSUER_NAME,
					    ci, sizeof(ci->ns.name)))
			aws_lwsl_notice(" Peer Cert issuer    : %s\n", ci->ns.name);

		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VALIDITY_FROM,
					    ci, 0))
#if defined(LWS_HAVE_CTIME_R)
			aws_lwsl_notice(" Peer Cert Valid from: %s", 
						ctime_r(&ci->time, date));
#else
			aws_lwsl_notice(" Peer Cert Valid from: %s", 
						ctime(&ci->time));
#endif
		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_VALIDITY_TO,
					    ci, 0))
#if defined(LWS_HAVE_CTIME_R)
			aws_lwsl_notice(" Peer Cert Valid to  : %s",
						ctime_r(&ci->time, date));
#else
			aws_lwsl_notice(" Peer Cert Valid to  : %s",
						ctime(&ci->time));
#endif
		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_USAGE,
					    ci, 0))
			aws_lwsl_notice(" Peer Cert usage bits: 0x%x\n", ci->usage);
		if (!aws_lws_tls_peer_cert_info(wsi,
					    LWS_TLS_CERT_INFO_OPAQUE_PUBLIC_KEY,
					    ci, sizeof(buf) - sizeof(*ci))) {
			aws_lwsl_notice(" Peer Cert public key:\n");
			aws_lwsl_hexdump_notice(ci->ns.name, (unsigned int)ci->ns.len);
		}

		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID,
					    ci, 0)) {
			aws_lwsl_notice(" AUTHORITY_KEY_ID\n");
			aws_lwsl_hexdump_notice(ci->ns.name, (size_t)ci->ns.len);
		}
		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_ISSUER,
					    ci, 0)) {
			aws_lwsl_notice(" AUTHORITY_KEY_ID ISSUER\n");
			aws_lwsl_hexdump_notice(ci->ns.name, (size_t)ci->ns.len);
		}
		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_AUTHORITY_KEY_ID_SERIAL,
					    ci, 0)) {
			aws_lwsl_notice(" AUTHORITY_KEY_ID SERIAL\n");
			aws_lwsl_hexdump_notice(ci->ns.name, (size_t)ci->ns.len);
		}
		if (!aws_lws_tls_peer_cert_info(wsi, LWS_TLS_CERT_INFO_SUBJECT_KEY_ID,
					    ci, 0)) {
			aws_lwsl_notice(" AUTHORITY_KEY_ID SUBJECT_KEY_ID\n");
			aws_lwsl_hexdump_notice(ci->ns.name, (size_t)ci->ns.len);
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
		client_wsi = NULL;
		bad = status != 200;
		aws_lws_cancel_service(aws_lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		client_wsi = NULL;
		bad = status != 200;
		aws_lws_cancel_service(aws_lws_get_context(wsi)); /* abort poll wait */
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
	struct aws_lws_client_connect_info i;
	struct aws_lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
		   /*
		    * For LLL_ verbosity above NOTICE to be built into lws,
		    * lws must have been configured and built with
		    * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE
		    *
		    * | LLL_INFO   | LLL_PARSER  | LLL_HEADER | LLL_EXT |
		    *   LLL_CLIENT | LLL_LATENCY | LLL_DEBUG
		    */ ;

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS minimal http client [<-d <verbosity>] [-l] [--h1]\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;
	/*
	 * since we know this lws context is only ever going to be used with
	 * one client wsis / fds / sockets at a time, let lws know it doesn't
	 * have to use the default allocations for fd tables up to ulimit -n.
	 * It will just allocate for 1 internal and 1 (+ 1 http2 nwsi) that we
	 * will use.
	 */
	info.fd_limit_per_thread = 1 + 1 + 1;

#if defined(LWS_WITH_MBEDTLS) || defined(USE_WOLFSSL)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	info.client_ssl_ca_filepath = "./warmcat.com.cer";
#endif

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
	i.context = context;
	i.ssl_connection = LCCSCF_USE_SSL;

	if (aws_lws_cmdline_option(argc, argv, "-l")) {
		i.port = 7681;
		i.address = "localhost";
		i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
	} else {
		i.port = 443;
		i.address = "warmcat.com";
	}

	if ((p = aws_lws_cmdline_option(argc, argv, "-s")))
		i.address = p;

	i.path = "/";
	i.host = i.address;
	i.origin = i.address;

	/* force h1 even if h2 available */
	if (aws_lws_cmdline_option(argc, argv, "--h1"))
		i.alpn = "http/1.1";

	i.method = "GET";

	i.protocol = protocols[0].name;
	i.pwsi = &client_wsi;
	aws_lws_client_connect_via_info(&i);

	while (n >= 0 && client_wsi && !interrupted)
		n = aws_lws_service(context, 0);

	aws_lws_context_destroy(context);
	aws_lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}

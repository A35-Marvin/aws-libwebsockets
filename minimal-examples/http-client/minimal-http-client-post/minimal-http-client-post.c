/*
 * lws-minimal-http-client-post
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the a minimal http client using lws and POST.
 *
 * It POSTs both form data and a file to the form at
 * https://libwebsockets.org/testserver/formtest and dumps
 * the html page received generated by the POST handler.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

static int interrupted, bad = 0, status, count_clients = 1, completed;
static struct lws *client_wsi[4];

struct pss {
	char body_part;
};

static int
callback_http(struct lws *wsi, enum aws_lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	char buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - LWS_PRE - 1];
	int n;

	switch (reason) {

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		aws_lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		bad = 1;
		if (++completed == count_clients)
			aws_lws_cancel_service(aws_lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		for (n = 0; n < count_clients; n++)
			if (client_wsi[n] == wsi) {
				client_wsi[n] = NULL;
				bad |= status != 200;
				if (++completed == count_clients)
					/* abort poll wait */
					aws_lws_cancel_service(aws_lws_get_context(wsi));
			}
		break;

	/* ...callbacks related to receiving the result... */

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)aws_lws_http_client_http_response(wsi);
		aws_lwsl_user("Connected with server response: %d\n", status);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		aws_lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
		aws_lwsl_hexdump_notice(in, len);
		return 0; /* don't passthru */

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		n = sizeof(buf) - LWS_PRE;
		if (aws_lws_http_client_read(wsi, &p, &n) < 0)
			return -1;

		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		aws_lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
		bad |= status != 200;
		/*
		 * Do this to mark us as having processed the completion
		 * so close doesn't duplicate (with pipelining, completion !=
		 * connection close
		 */
		for (n = 0; n < count_clients; n++)
			if (client_wsi[n] == wsi)
				client_wsi[n] = NULL;
		if (++completed == count_clients)
			/* abort poll wait */
			aws_lws_cancel_service(aws_lws_get_context(wsi));
		break;

	/* ...callbacks related to generating the POST... */

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		/*
		 * Tell lws we are going to send the body next...
		 */
		if (!aws_lws_http_is_redirected_to_get(wsi)) {
			aws_lwsl_user("%s: doing POST flow\n", __func__);
			aws_lws_client_http_body_pending(wsi, 1);
			aws_lws_callback_on_writable(wsi);
		} else
			aws_lwsl_user("%s: doing GET flow\n", __func__);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (aws_lws_http_is_redirected_to_get(wsi))
			break;
		aws_lwsl_user("LWS_CALLBACK_CLIENT_HTTP_WRITEABLE\n");
		n = LWS_WRITE_HTTP;

		/*
		 * For a small body like this, we could prepare it in memory and
		 * send it all at once.  But to show how to handle, eg,
		 * arbitrary-sized file payloads, or huge form-data fields, the
		 * sending is done in multiple passes through the event loop.
		 */

		switch (pss->body_part++) {
		case 0:
			if (aws_lws_client_http_multipart(wsi, "text", NULL, NULL,
						      &p, end))
				return -1;
			/* notice every usage of the boundary starts with -- */
			p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p), "my text field\xd\xa");
			break;
		case 1:
			if (aws_lws_client_http_multipart(wsi, "file", "myfile.txt",
						      "text/plain", &p, end))
				return -1;
			p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p),
					"This is the contents of the "
					"uploaded file.\xd\xa"
					"\xd\xa");
			break;
		case 2:
			if (aws_lws_client_http_multipart(wsi, NULL, NULL, NULL,
						      &p, end))
				return -1;
			aws_lws_client_http_body_pending(wsi, 0);
			 /* necessary to support H2, it means we will write no
			  * more on this stream */
			n = LWS_WRITE_HTTP_FINAL;
			break;

		default:
			/*
			 * We can get extra callbacks here, if nothing to do,
			 * then do nothing.
			 */
			return 0;
		}

		if (aws_lws_write(wsi, (uint8_t *)start, aws_lws_ptr_diff_size_t(p, start), (enum aws_lws_write_protocol)n)
				!= aws_lws_ptr_diff(p, start))
			return 1;

		if (n != LWS_WRITE_HTTP_FINAL)
			aws_lws_callback_on_writable(wsi);

		return 0;

	default:
		break;
	}

	return aws_lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct aws_lws_protocols protocols[] = {
	{
		"http",
		callback_http,
		sizeof(struct pss),
		0, 0, NULL, 0
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
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	aws_lws_cmdline_option_handle_builtin(argc, argv, &info);
	aws_lwsl_user("LWS minimal http client - POST [-d<verbosity>] [-l] [--h1]\n");

	if (aws_lws_cmdline_option(argc, argv, "-m"))
		count_clients = LWS_ARRAY_SIZE(client_wsi);

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
	info.fd_limit_per_thread = (unsigned int)(1 + count_clients + 1);

#if defined(LWS_WITH_MBEDTLS) || defined(USE_WOLFSSL)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	if (!aws_lws_cmdline_option(argc, argv, "-l"))
		info.client_ssl_ca_filepath = "./libwebsockets.org.cer";
#endif

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */
	i.context = context;
	i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_HTTP_MULTIPART_MIME;

	if (aws_lws_cmdline_option(argc, argv, "-l")) {
		i.port = 7681;
		i.address = "localhost";
		i.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;
		i.path = "/formtest";
	} else {
		i.port = 443;
		i.address = "libwebsockets.org";
		i.path = "/testserver/formtest";
	}

	if (aws_lws_cmdline_option(argc, argv, "--form1"))
		i.path = "/form1";

	if ((p = aws_lws_cmdline_option(argc, argv, "--port")))
		i.port = atoi(p);

	i.host = i.address;
	i.origin = i.address;
	i.method = "POST";

	/* force h1 even if h2 available */
	if (aws_lws_cmdline_option(argc, argv, "--h1"))
		i.alpn = "http/1.1";

	i.protocol = protocols[0].name;

	for (n = 0; n < count_clients; n++) {
		i.pwsi = &client_wsi[n];
		aws_lwsl_notice("%s: connecting to %s:%d\n", __func__,
			    i.address, i.port);
		if (!aws_lws_client_connect_via_info(&i))
			completed++;
	}

	while (n >= 0 && completed != count_clients && !interrupted)
		n = aws_lws_service(context, 0);

	aws_lws_context_destroy(context);
	aws_lwsl_user("Completed: %s\n", bad ? "failed" : "OK");

	return bad;
}

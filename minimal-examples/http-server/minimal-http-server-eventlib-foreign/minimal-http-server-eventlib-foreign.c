/*
 * lws-minimal-http-server-eventlib-foreign
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates the most minimal http server you can make with lws that
 * uses a libuv event loop created outside lws.  It shows how lws can
 * participate in someone else's event loop and clean up after itself.
 *
 * You choose the event loop to work with at runtime, by giving the
 * --uv, --event or --ev switch.  Lws has to have been configured to build the
 * selected event lib support.
 *
 * To keep it simple, it serves stuff from the subdirectory 
 * "./mount-origin" of the directory it was started in.
 * You can change that by changing mount.origin below.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#include "private.h"

static struct aws_lws_context_creation_info info;
static const struct ops *ops = NULL;
struct aws_lws_context *context;
int lifetime = 5, reported;

enum {
	TEST_STATE_CREATE_LWS_CONTEXT,
	TEST_STATE_DESTROY_LWS_CONTEXT,
	TEST_STATE_EXIT
};

static int sequence = TEST_STATE_CREATE_LWS_CONTEXT;

static const struct aws_lws_http_mount mount = {
	/* .mount_next */		NULL,		/* linked-list "next" */
	/* .mountpoint */		"/",		/* mountpoint URL */
	/* .origin */			"./mount-origin", /* serve from dir */
	/* .def */			"index.html",	/* default filename */
	/* .protocol */			NULL,
	/* .cgienv */			NULL,
	/* .extra_mimetypes */		NULL,
	/* .interpret */		NULL,
	/* .cgi_timeout */		0,
	/* .cache_max_age */		0,
	/* .auth_mask */		0,
	/* .cache_reusable */		0,
	/* .cache_revalidate */		0,
	/* .cache_intermediaries */	0,
	/* .origin_protocol */		LWSMPRO_FILE,	/* files in a dir */
	/* .mountpoint_len */		1,		/* char count */
	/* .basic_auth_login_file */	NULL,
};

void
signal_cb(int signum)
{
	aws_lwsl_notice("Signal %d caught, exiting...\n", signum);

	switch (signum) {
	case SIGTERM:
	case SIGINT:
		break;
	default:
		break;
	}

	aws_lws_context_destroy(context);
}

static int
callback_http(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		aws_lwsl_user("LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: resp %u\n",
				aws_lws_http_client_http_response(wsi));
		break;

	/* because we are protocols[0] ... */
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		aws_lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		aws_lwsl_user("RECEIVE_CLIENT_HTTP_READ: read %d\n", (int)len);
		aws_lwsl_hexdump_info(in, len);
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
		aws_lwsl_user("LWS_CALLBACK_COMPLETED_CLIENT_HTTP %s\n",
			  aws_lws_wsi_tag(wsi));
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		aws_lwsl_info("%s: closed: %s\n", __func__, aws_lws_wsi_tag(wsi));
		break;

	default:
		break;
	}

	return aws_lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct aws_lws_protocols protocols[] = {
	{ "httptest", callback_http, 0, 0, 0, NULL, 0},
	LWS_PROTOCOL_LIST_TERM
};

static int
do_client_conn(void)
{
	struct aws_lws_client_connect_info i;

	memset(&i, 0, sizeof i); /* otherwise uninitialized garbage */

	i.context		= context;

	i.ssl_connection	= LCCSCF_USE_SSL;
	i.port			= 443;
	i.address		= "warmcat.com";

	i.ssl_connection	|= LCCSCF_H2_QUIRK_OVERFLOWS_TXCR |
				   LCCSCF_H2_QUIRK_NGHTTP2_END_STREAM;
	i.path			= "/";
	i.host			= i.address;
	i.origin		= i.address;
	i.method		= "GET";
	i.local_protocol_name	= protocols[0].name;
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	i.fi_wsi_name		= "user";
#endif

	if (!aws_lws_client_connect_via_info(&i)) {
		aws_lwsl_err("Client creation failed\n");

		return 1;
	}

	return 0;
}


/* this is called at 1Hz using a foreign loop timer */

void
foreign_timer_service(void *foreign_loop)
{
	void *foreign_loops[1];

	aws_lwsl_user("Foreign 1Hz timer\n");

	if (sequence == TEST_STATE_EXIT && !context && !reported) {
		/*
		 * at this point the aws_lws_context_destroy() we did earlier
		 * has completed and the entire context is wholly destroyed
		 */
		aws_lwsl_user("aws_lws_destroy_context() done, continuing for 5s\n");
		reported = 1;
	}

	if (--lifetime)
		return;

	switch (sequence++) {
	case TEST_STATE_CREATE_LWS_CONTEXT:
		/* this only has to exist for the duration of create context */
		foreign_loops[0] = foreign_loop;
		info.foreign_loops = foreign_loops;

		context = aws_lws_create_context(&info);
		if (!context) {
			aws_lwsl_err("lws init failed\n");
			return;
		}
		aws_lwsl_user("LWS Context created and will be active for 10s\n");

		do_client_conn();

		lifetime = 11;
		break;

	case TEST_STATE_DESTROY_LWS_CONTEXT:
		/* cleanup the lws part */
		aws_lwsl_user("Destroying lws context and continuing loop for 5s\n");
		aws_lws_context_destroy(context);
		lifetime = 6;
		break;

	case TEST_STATE_EXIT:
		aws_lwsl_user("Deciding to exit foreign loop too\n");
		ops->stop();
		break;
	default:
		break;
	}
}

int main(int argc, const char **argv)
{
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS minimal http server eventlib + foreign loop |"
		  " visit http://localhost:7681\n");

	/*
	 * We prepare the info here, but don't use it until later in the
	 * timer callback, to demonstrate the independence of the foreign loop
	 * and lws.
	 */

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	if ((p = aws_lws_cmdline_option(argc, argv, "-p")))
		info.port = atoi(p);
	info.mounts = &mount;
	info.error_document_404 = "/404.html";
	info.pcontext = &context;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	if (aws_lws_cmdline_option(argc, argv, "-s")) {
		info.ssl_cert_filepath = "localhost-100y.cert";
		info.ssl_private_key_filepath = "localhost-100y.key";
	}

	/*
	 * We configure lws to use the chosen event loop, and select the
	 * matching event-lib specific code for our demo operations
	 */

#if defined(LWS_WITH_LIBUV)
	if (aws_lws_cmdline_option(argc, argv, "--uv")) {
		info.options |= LWS_SERVER_OPTION_LIBUV;
		ops = &ops_libuv;
		aws_lwsl_notice("%s: using libuv event loop\n", __func__);
	} else
#endif
#if defined(LWS_WITH_LIBEVENT)
		if (aws_lws_cmdline_option(argc, argv, "--event")) {
			info.options |= LWS_SERVER_OPTION_LIBEVENT;
			ops = &ops_libevent;
			aws_lwsl_notice("%s: using libevent loop\n", __func__);
		} else
#endif
#if defined(LWS_WITH_LIBEV)
			if (aws_lws_cmdline_option(argc, argv, "--ev")) {
				info.options |= LWS_SERVER_OPTION_LIBEV;
				ops = &ops_libev;
				aws_lwsl_notice("%s: using libev loop\n", __func__);
			} else
#endif
#if defined(LWS_WITH_GLIB)
				if (aws_lws_cmdline_option(argc, argv, "--glib")) {
					info.options |= LWS_SERVER_OPTION_GLIB;
					ops = &ops_glib;
					aws_lwsl_notice("%s: using glib loop\n", __func__);
				} else
#endif
#if defined(LWS_WITH_SDEVENT)
					if (aws_lws_cmdline_option(argc, argv, "--sd")) {
						info.options |= LWS_SERVER_OPTION_SDEVENT;
						ops = &ops_sdevent;
						aws_lwsl_notice("%s: using sd-event loop\n", __func__);
					} else
#endif
#if defined(LWS_WITH_ULOOP)
					if (aws_lws_cmdline_option(argc, argv, "--uloop")) {
						info.options |= LWS_SERVER_OPTION_ULOOP;
						ops = &ops_uloop;
						aws_lwsl_notice("%s: using uloop loop\n", __func__);
					} else
#endif
				{
				aws_lwsl_err("This app only makes sense when used\n");
				aws_lwsl_err(" with a foreign loop, --uv, --event, --glib, --ev or --sd\n");

				return 1;
				}

	aws_lwsl_user("  This app creates a foreign event loop with a timer +\n");
	aws_lwsl_user("  signalhandler, and performs a test in three phases:\n");
	aws_lwsl_user("\n");
	aws_lwsl_user("  1) 5s: Runs the loop with just the timer\n");
	aws_lwsl_user("  2) 10s: create an lws context serving on localhost:7681\n");
	aws_lwsl_user("     using the same foreign loop.  Destroy it after 10s.\n");
	aws_lwsl_user("  3) 5s: Run the loop again with just the timer\n");
	aws_lwsl_user("\n");
	aws_lwsl_user("  Finally close only the timer and signalhandler and\n");
	aws_lwsl_user("   exit the loop cleanly\n");
	aws_lwsl_user("\n");

	/* foreign loop specific startup and run */

	ops->init_and_run();

	aws_lws_context_destroy(context);

	/* foreign loop specific cleanup and exit */

	ops->cleanup();

	aws_lwsl_user("%s: exiting...\n", __func__);

	return 0;
}

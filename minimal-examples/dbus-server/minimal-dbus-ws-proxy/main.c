/*
 * lws-minimal-dbus-ws-proxy
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal session dbus server that uses the lws event loop,
 * and allows proxying ws client connections via DBUS.
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <libwebsockets.h>
#include <libwebsockets/lws-dbus.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_minimal_dbus_ws_proxy.c"

static int interrupted;
static struct aws_lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_MINIMAL_DBUS_WSPROXY,
	LWS_PROTOCOL_LIST_TERM
};

/*
 * we pass the dbus address to connect to proxy with from outside the
 * protocol plugin... eg if built as a plugin for aws_lwsws, you would instead
 * set this pvo in the aws_lwsws JSON config.
 */

static const struct aws_lws_protocol_vhost_options pvo_ads = {
	NULL,
	NULL,
	"ads",				/* pvo name */
	(void *)"unix:abstract=org.libwebsockets.wsclientproxy"	/* pvo value */
};

static const struct aws_lws_protocol_vhost_options pvo = {
	NULL,				/* "next" pvo linked-list */
	&pvo_ads,			/* "child" pvo linked-list */
	"lws-minimal-dbus-wsproxy",	/* protocol name we belong to on this vhost */
	""				/* ignored */
};

void sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	static struct aws_lws_context *context;
	struct aws_lws_context_creation_info info;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */ /* | LLL_THREAD */;

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS DBUS ws client proxy\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.pvo = &pvo;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	/* lws event loop (default poll one) */

	while (n >= 0 && !interrupted)
		n = aws_lws_service(context, 0);

	aws_lws_context_destroy(context);

	aws_lwsl_notice("Exiting cleanly\n");

	return 0;
}

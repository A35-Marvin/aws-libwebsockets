/*
 * lws-minimal-ws-server
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a minimal ws server that can cooperate with
 * other threads cleanly.  Two other threads are started, which fill
 * a ringbuffer with strings at 10Hz.
 *
 * The actual work and thread spawning etc are done in the protocol
 * implementation in protocol_lws_minimal.c.
 *
 * To keep it simple, it serves stuff in the subdirectory "./mount-origin" of
 * the directory it was started in.
 * You can change that by changing mount.origin.
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

#define LWS_PLUGIN_STATIC
#include "protocol_lws_minimal.c"

#define COUNT_THREADS 2

static struct aws_lws_protocols protocols[] = {
	{ "http", aws_lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_MINIMAL,
	LWS_PROTOCOL_LIST_TERM
};

static struct aws_lws_context *context;
static int interrupted, started;
static pthread_t pthread_service[COUNT_THREADS];

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

/*
 * This demonstrates how to pass a pointer into a specific protocol handler
 * running on a specific vhost.  In this case, it's our default vhost and
 * we pass the pvo named "config" with the value a const char * "myconfig".
 *
 * This is the preferred way to pass configuration into a specific vhost +
 * protocol instance.
 */

static const struct aws_lws_protocol_vhost_options pvo_ops = {
	NULL,
	NULL,
	"config",		/* pvo name */
	(void *)"myconfig"	/* pvo value */
};

static const struct aws_lws_protocol_vhost_options pvo = {
	NULL,		/* "next" pvo linked-list */
	&pvo_ops,	/* "child" pvo linked-list */
	"lws-minimal",	/* protocol name we belong to on this vhost */
	""		/* ignored */
};

void *thread_service(void *threadid)
{
	while (aws_lws_service_tsi(context, 1000,
			       (int)(aws_lws_intptr_t)threadid) >= 0 &&
	       !interrupted)
		;

	pthread_exit(NULL);

	return NULL;
}

static int
system_notify_cb(aws_lws_state_manager_t *mgr, aws_lws_state_notify_link_t *link,
		   int current, int target)
{
	struct aws_lws_context *context = mgr->parent;
	void *retval;

	if (current != target)
		return 0;

	switch (current) {
	case LWS_SYSTATE_OPERATIONAL:
		aws_lwsl_notice("  Service threads: %d\n",
			    aws_lws_get_count_threads(context));

		/* start all the service threads */

		for (started = 1; started < aws_lws_get_count_threads(context);
		     started++)
			if (pthread_create(&pthread_service[started], NULL,
					   thread_service,
					   (void *)(aws_lws_intptr_t)started))
				aws_lwsl_err("Failed to start service thread\n");
		break;
	case LWS_SYSTATE_CONTEXT_DESTROYING:
		/* wait for all the service threads to exit */

		while ((--started) >= 1)
			pthread_join(pthread_service[started], &retval);

		break;
	}

	return 0;
}

aws_lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
				     system_notify_cb, "app" };
aws_lws_state_notify_link_t *na[] = { &notifier, NULL };

void sigint_handler(int sig)
{
	interrupted = 1;
	aws_lws_cancel_service(context);
}

int main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct aws_lws_context_creation_info info;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS minimal ws server + threads + smp | visit http://localhost:7681\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = 7681;
	info.mounts = &mount;
	info.protocols = protocols;
	info.pvo = &pvo; /* per-vhost options */
	info.count_threads = COUNT_THREADS;
	info.register_notifier_list = na;
	info.options =
		LWS_SERVER_OPTION_HTTP_HEADERS_SECURITY_BEST_PRACTICES_ENFORCE;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = aws_lws_service(context, 0);

	aws_lws_context_destroy(context);

	return 0;
}

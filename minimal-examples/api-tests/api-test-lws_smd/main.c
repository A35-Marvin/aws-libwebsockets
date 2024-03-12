/*
 * lws-api-test-aws_lws_smd
 *
 * Written in 2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This api test confirms aws_lws_smd System Message Distribution
 */

#include <libwebsockets.h>
#define HAVE_STRUCT_TIMESPEC
#include <pthread.h>
#include <signal.h>

static int interrupted, ok, fail, _exp = 111;
static unsigned int how_many_msg = 100, usec_interval = 1000;
static aws_lws_sorted_usec_list_t sul, sul_initial_drain;
struct aws_lws_context *context;
static pthread_t thread_spam;

static void
timeout_cb(aws_lws_sorted_usec_list_t *sul)
{
	/* We should have completed the test before this fires */
	aws_lwsl_notice("%s: test period finished\n", __func__);
	interrupted = 1;
	aws_lws_cancel_service(context);
}

static int
smd_cb1int(void *opaque, aws_lws_smd_class_t _class, aws_lws_usec_t timestamp,
	   void *buf, size_t len)
{
#if 0
	aws_lwsl_notice("%s: ts %llu, len %d\n", __func__,
		    (unsigned long long)timestamp, (int)len);
	aws_lwsl_hexdump_notice(buf, len);
#endif
	ok++;

	return 0;
}

static int
smd_cb2int(void *opaque, aws_lws_smd_class_t _class, aws_lws_usec_t timestamp,
	   void *buf, size_t len)
{
#if 0
	aws_lwsl_notice("%s: ts %llu, len %d\n", __func__,
		    (unsigned long long)timestamp, (int)len);
	aws_lwsl_hexdump_notice(buf, len);
#endif
	ok++;

	return 0;
}

/*
 * This is used in an smd participant that is deregistered before the message
 * can be delivered, it should never see any message
 */

static int
smd_cb3int(void *opaque, aws_lws_smd_class_t _class, aws_lws_usec_t timestamp,
	   void *buf, size_t len)
{
	aws_lwsl_err("%s: Countermanded ts %llu, len %d\n", __func__,
		    (unsigned long long)timestamp, (int)len);
	aws_lwsl_hexdump_err(buf, len);

	fail++;

	return 0;
}

static void *
_thread_spam(void *d)
{
#if defined(WIN32)
	unsigned int mypid = 0;
#else
	unsigned int mypid = (unsigned int)getpid();
#endif
	unsigned int n = 0, atm = 0;

	while (n++ < how_many_msg) {

		atm++;
		if (aws_lws_smd_msg_printf(context, LWSSMDCL_SYSTEM_STATE,
					       "{\"s\":\"state\","
						"\"pid\":%u,"
						"\"msg\":%d}",
					       mypid, (unsigned int)n)) {
			aws_lwsl_err("%s: send attempt %d failed\n", __func__, atm);
			n--;
			fail++;
			if (fail >= 3) {
				interrupted = 1;
				aws_lws_cancel_service(context);
				break;
			}
		}
#if defined(WIN32)
		Sleep(3);
#else
		usleep(usec_interval);
#endif
	}
#if !defined(WIN32)
	pthread_exit(NULL);
#endif

	return NULL;
}

void sigint_handler(int sig)
{
	interrupted = 1;
}

static void
drained_cb(aws_lws_sorted_usec_list_t *sul)
{
	/*
	 * spawn the test thread, it's going to spam 100 messages at 3ms
	 * intervals... check we got everything
	 */

	if (pthread_create(&thread_spam, NULL, _thread_spam, NULL))
		aws_lwsl_err("%s: failed to create the spamming thread\n", __func__);
}

static int
system_notify_cb(aws_lws_state_manager_t *mgr, aws_lws_state_notify_link_t *link,
		   int current, int target)
{
	// struct aws_lws_context *context = mgr->parent;
	int n;

	if (current != LWS_SYSTATE_OPERATIONAL || target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/*
	 * Overflow the message queue too see if it handles it well, both
	 * as overflowing and in recovery.  These are all still going into the
	 * smd buffer dll2, since we don't break for the event loop to have a
	 * chance to deliver them.
	 */

	n = 0;
	while (n++ < 100)
		if (aws_lws_smd_msg_printf(context, LWSSMDCL_SYSTEM_STATE,
				       "{\"s\":\"state\",\"test\":\"overflow\"}"))
			break;

	aws_lwsl_notice("%s: overflow test added %d messages\n", __func__, n);
	if (n == 100) {
		aws_lwsl_err("%s: didn't overflow\n", __func__);
		interrupted = 1;
		return 1;
	}

	/*
	 * So we have some normal messages from earlier and now the rest of the
	 * smd buffer filled with junk overflow messages.  Before we start the
	 * actual spamming test from another thread, we need to return to the
	 * event loop so these can be cleared first.
	 */

	aws_lws_sul_schedule(context, 0, &sul_initial_drain, drained_cb,
			 5 * LWS_US_PER_MS);


	aws_lwsl_info("%s: operational\n", __func__);

	return 0;
}

int
main(int argc, const char **argv)
{
	aws_lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
						system_notify_cb, "app" };
	aws_lws_state_notify_link_t *na[] = { &notifier, NULL };
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct aws_lws_context_creation_info info;
	struct aws_lws_smd_peer *userreg;
	const char *p;
	void *retval;

	/* the normal lws init */

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	if ((p = aws_lws_cmdline_option(argc, argv, "--count")))
		how_many_msg = (unsigned int)atol(p);

	if ((p = aws_lws_cmdline_option(argc, argv, "--interval")))
		usec_interval = (unsigned int)atol(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS API selftest: aws_lws_smd: %u msgs at %uus interval\n",
			how_many_msg, usec_interval);

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.register_notifier_list = na;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	/* game over after this long */

	aws_lws_sul_schedule(context, 0, &sul, timeout_cb,
			 (how_many_msg * (usec_interval + 1000)) + (4 * LWS_US_PER_SEC));

	/* register a messaging participant to hear INTERACTION class */

	if (!aws_lws_smd_register(context, NULL, 0, LWSSMDCL_INTERACTION,
			      smd_cb1int)) {
		aws_lwsl_err("%s: smd register 1 failed\n", __func__);
		goto bail;
	}

	/* register a messaging participant to hear SYSTEM_STATE class */

	if (!aws_lws_smd_register(context, NULL, 0, LWSSMDCL_SYSTEM_STATE,
			      smd_cb2int)) {
		aws_lwsl_err("%s: smd register 2 failed\n", __func__);
		goto bail;
	}

	/* temporarily register a messaging participant to hear a user class */

	userreg = aws_lws_smd_register(context, NULL, 0, 1 << LWSSMDCL_USER_BASE_BITNUM,
			      smd_cb3int);
	if (!userreg) {
		aws_lwsl_err("%s: smd register userclass failed\n", __func__);
		goto bail;
	}

	/*
	 * The event loop isn't started yet, so these smd messages are getting
	 * buffered.  Later we will deliberately overrun the buffer and wait
	 * for that to be cleared before the spam thread test.
	 */

	/* generate an INTERACTION class message */

	if (aws_lws_smd_msg_printf(context, LWSSMDCL_INTERACTION,
			       "{\"s\":\"interaction\"}")) {
		aws_lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/* generate a SYSTEM_STATE class message */

	if (aws_lws_smd_msg_printf(context, LWSSMDCL_SYSTEM_STATE,
			       "{\"s\":\"state\"}")) {
		aws_lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/* no participant listens for this class, so it should be skipped */

	if (aws_lws_smd_msg_printf(context, LWSSMDCL_NETWORK, "{\"s\":\"network\"}")) {
		aws_lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/* generate a user class message... */

	if (aws_lws_smd_msg_printf(context, 1 << LWSSMDCL_USER_BASE_BITNUM,
			       "{\"s\":\"userclass\"}")) {
		aws_lwsl_err("%s: problem sending smd\n", __func__);
		goto bail;
	}

	/*
	 * ... and screw that user class message up by deregistering the only
	 * handler before it can deliver it... it should not get delivered
	 * and cleanly discarded
	 */

	aws_lws_smd_unregister(userreg);

	/* the usual lws event loop */

	while (!interrupted && aws_lws_service(context, 0) >= 0)
		;

	pthread_join(thread_spam, &retval);

bail:
	aws_lws_context_destroy(context);

	if (fail || ok >= _exp)
		aws_lwsl_user("Completed: PASS: %d / %d, FAIL: %d\n", ok, _exp,
				fail);
	else
		aws_lwsl_user("Completed: ALL PASS: %d / %d\n", ok, _exp);

	return !(ok >= _exp && !fail);
}

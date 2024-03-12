/*
 * lws-api-test-smtp_client
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

#include <signal.h>

static int interrupted, result = 1;
static const char *recip;

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

static int
done_cb(struct aws_lws_smtp_email *email, void *buf, size_t len)
{
	/* you could examine email->data here */
	if (buf) {
		char dotstar[96];
		aws_lws_strnncpy(dotstar, (const char *)buf, len, sizeof(dotstar));
		aws_lwsl_notice("%s: %s\n", __func__, dotstar);
	} else
		aws_lwsl_notice("%s:\n", __func__);

	/* destroy any allocations in email */

	free((char *)email->payload);

	result = 0;
	interrupted = 1;

	return 0;
}

int main(int argc, const char **argv)
{
	int n = 1, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	struct aws_lws_context_creation_info info;
	aws_lws_smtp_sequencer_args_t ss_args;
	struct aws_lws_context *context;
	aws_lws_smtp_sequencer_t *sseq;
	aws_lws_smtp_email_t *email;
	struct aws_lws_vhost *vh;
	char payload[2048];
	const char *p;

	/* the normal lws init */

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	p = aws_lws_cmdline_option(argc, argv, "-r");
	if (!p) {
		aws_lwsl_err("-r <recipient email> is required\n");
		return 1;
	}
	recip = p;

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS API selftest: SMTP client\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	vh = aws_lws_create_vhost(context, &info);
	if (!vh) {
		aws_lwsl_err("Failed to create first vhost\n");
		goto bail1;
	}

	memset(&ss_args, 0, sizeof(ss_args));
	ss_args.helo = "lws-abs-smtp-test";
	ss_args.vhost = vh;

	sseq = aws_lws_smtp_sequencer_create(&ss_args);
	if (!sseq) {
		aws_lwsl_err("%s: smtp sequencer create failed\n", __func__);
		goto bail1;
	}

	/* attach an email to it */

	n = aws_lws_snprintf(payload, sizeof(payload),
			"From: noreply@example.com\n"
			"To: %s\n"
			"Subject: Test email for lws smtp-client\n"
			"\n"
			"Hello this was an api test for lws smtp-client\n"
			"\r\n.\r\n", recip);

	if (aws_lws_smtpc_add_email(sseq, payload, n, "testserver",
				"andy@warmcat.com", recip, NULL, done_cb)) {
		aws_lwsl_err("%s: failed to add email\n", __func__);
		goto bail1;
	}

	/* the usual lws event loop */

	while (n >= 0 && !interrupted)
		n = aws_lws_service(context, 0);

bail1:
	aws_lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	aws_lws_context_destroy(context);

	return result;
}

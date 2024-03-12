/*
 * lws-api-test-cose
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

int
test_cose_keys(struct aws_lws_context *context);
int
test_cose_sign(struct aws_lws_context *context);

int main(int argc, const char **argv)
{
	struct aws_lws_context_creation_info info;
	struct aws_lws_context *context;
	const char *p;
	int result = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS COSE api tests\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
#if defined(LWS_WITH_NETWORK)
	info.port = CONTEXT_PORT_NO_LISTEN;
#endif
	info.options = 0;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	result |= test_cose_keys(context);
	result |= test_cose_sign(context);

	aws_lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	aws_lws_context_destroy(context);

	return result;
}

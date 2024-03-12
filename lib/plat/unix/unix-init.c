/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "private-lib-core.h"

#include <pwd.h>
#include <grp.h>

#ifdef LWS_WITH_PLUGINS
#include <dlfcn.h>
#endif
#include <dirent.h>

#if defined(LWS_WITH_NETWORK)
static void
aws_lws_sul_plat_unix(aws_lws_sorted_usec_list_t *sul)
{
	struct aws_lws_context_per_thread *pt =
		aws_lws_container_of(sul, struct aws_lws_context_per_thread, sul_plat);
	struct aws_lws_context *context = pt->context;
	int n = 0, m = 0;

#if !defined(LWS_NO_DAEMONIZE)
	/* if our parent went down, don't linger around */
	if (pt->context->started_with_parent &&
	    kill(pt->context->started_with_parent, 0) < 0)
		kill(getpid(), SIGTERM);
#endif

	for (n = 0; n < context->count_threads; n++)
		m = m | (int)pt->fds_count;

	if (context->deprecated && !m) {
		aws_lwsl_notice("%s: ending deprecated context\n", __func__);
		kill(getpid(), SIGINT);
		return;
	}

#if defined(LWS_WITH_SERVER)
	aws_lws_context_lock(context, "periodic checks");
	aws_lws_start_foreach_llp(struct aws_lws_vhost **, pv,
			      context->no_listener_vhost_list) {
		struct aws_lws_vhost *v = *pv;
		aws_lwsl_debug("deferred iface: checking if on vh %s\n", (*pv)->name);
		if (aws__lws_vhost_init_server(NULL, *pv) == 0) {
			/* became happy */
			aws_lwsl_notice("vh %s: became connected\n", v->name);
			*pv = v->no_listener_vhost_list;
			v->no_listener_vhost_list = NULL;
			break;
		}
	} aws_lws_end_foreach_llp(pv, no_listener_vhost_list);
	aws_lws_context_unlock(context);
#endif

	aws___lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &pt->sul_plat, 30 * LWS_US_PER_SEC);
}
#endif

#if defined(LWS_WITH_PLUGINS)
static int
protocol_plugin_cb(struct aws_lws_plugin *pin, void *each_user)
{
	struct aws_lws_context *context = (struct aws_lws_context *)each_user;
	const aws_lws_plugin_protocol_t *plpr =
			(const aws_lws_plugin_protocol_t *)pin->hdr;

	context->plugin_protocol_count = (short)(context->plugin_protocol_count +
						 plpr->count_protocols);
	context->plugin_extension_count = (short)(context->plugin_extension_count +
						  plpr->count_extensions);

	return 0;
}
#endif

int
aws_lws_plat_init(struct aws_lws_context *context,
	      const struct aws_lws_context_creation_info *info)
{
	int fd;
#if defined(LWS_WITH_NETWORK)
	/*
	 * context has the process-global fd lookup array.  This can be
	 * done two different ways now; one or the other is done depending on if
	 * info->fd_limit_per_thread was snonzero
	 *
	 *  - default: allocate a worst-case lookup array sized for ulimit -n
	 *             and use the fd directly as an index into it
	 *
	 *  - slow:    allocate context->max_fds entries only (which can be
	 *             forced at context creation time to be
	 *             info->fd_limit_per_thread * the number of threads)
	 *             and search the array to lookup fds
	 *
	 * the default way is optimized for server, if you only use one or two
	 * client wsi the slow way may save a lot of memory.
	 *
	 * Both ways allocate an array of struct lws *... one allocates it for
	 * all possible fd indexes the process could produce and uses it as a
	 * map, the other allocates for an amount of wsi the lws context is
	 * expected to use and searches through it to manipulate it.
	 */

	context->aws_lws_lookup = aws_lws_zalloc(sizeof(struct lws *) *
					 context->max_fds, "aws_lws_lookup");

	if (!context->aws_lws_lookup) {
		aws_lwsl_cx_err(context, "OOM on alloc aws_lws_lookup array for %d conn",
			 context->max_fds);
		return 1;
	}

#if defined(LWS_WITH_MBEDTLS)
	{
		int n;

		/* initialize platform random through mbedtls */
		mbedtls_entropy_init(&context->mec);
		mbedtls_ctr_drbg_init(&context->mcdc);

		n = mbedtls_ctr_drbg_seed(&context->mcdc, mbedtls_entropy_func,
					  &context->mec, NULL, 0);
		if (n)
			aws_lwsl_err("%s: mbedtls_ctr_drbg_seed() returned 0x%x\n",
				 __func__, n);
#if 0
		else {
			uint8_t rtest[16];
			aws_lwsl_notice("%s: started drbg\n", __func__);
			if (mbedtls_ctr_drbg_random(&context->mcdc, rtest,
							sizeof(rtest)))
				aws_lwsl_err("%s: get random failed\n", __func__);
			else
				aws_lwsl_hexdump_notice(rtest, sizeof(rtest));
		}
#endif
	}
#endif

	aws_lwsl_cx_info(context, " mem: platform fd map: %5lu B",
		    (unsigned long)(sizeof(struct lws *) * context->max_fds));
#endif
#if defined(LWS_WITH_FILE_OPS)
	fd = aws_lws_open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);
#else
	fd = open(SYSTEM_RANDOM_FILEPATH, O_RDONLY);
#endif
	context->fd_random = fd;
	if (context->fd_random < 0) {
		aws_lwsl_err("Unable to open random device %s %d, errno %d\n",
			 SYSTEM_RANDOM_FILEPATH, context->fd_random, errno);
		return 1;
	}

#if defined(LWS_WITH_PLUGINS)
	{
		char *ld_env = getenv("LD_LIBRARY_PATH");

		if (ld_env) {
			const char *pp[2] = { ld_env, NULL };

			aws_lws_plugins_init(&context->plugin_list, pp,
					 "aws_lws_protocol_plugin", NULL,
					 protocol_plugin_cb, context);
		}

		if (info->plugin_dirs)
			aws_lws_plugins_init(&context->plugin_list,
					 info->plugin_dirs,
					 "aws_lws_protocol_plugin", NULL,
					 protocol_plugin_cb, context);
	}
#endif


#if defined(LWS_WITH_NETWORK)
	/* we only need to do this on pt[0] */

	context->pt[0].sul_plat.cb = aws_lws_sul_plat_unix;
	aws___lws_sul_insert_us(&context->pt[0].pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &context->pt[0].sul_plat, 30 * LWS_US_PER_SEC);
#endif

	return 0;
}

int
aws_lws_plat_context_early_init(void)
{
#if !defined(LWS_AVOID_SIGPIPE_IGN)
	signal(SIGPIPE, SIG_IGN);
#endif

	return 0;
}

void
aws_lws_plat_context_early_destroy(struct aws_lws_context *context)
{
}

void
aws_lws_plat_context_late_destroy(struct aws_lws_context *context)
{
#if defined(LWS_WITH_PLUGINS)
	if (context->plugin_list)
		aws_lws_plugins_destroy(&context->plugin_list, NULL, NULL);
#endif
#if defined(LWS_WITH_NETWORK)
	if (context->aws_lws_lookup)
		aws_lws_free_set_NULL(context->aws_lws_lookup);
#endif
	if (!context->fd_random)
		aws_lwsl_err("ZERO RANDOM FD\n");
	if (context->fd_random != LWS_INVALID_FILE)
		close(context->fd_random);
}

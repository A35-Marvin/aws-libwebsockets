/*
 * lws System Fault Injection
 *
 * Copyright (C) 2019 - 2021 Andy Green <andy@warmcat.com>
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

#include "private-lib-core.h"

#include <assert.h>

static aws_lws_fi_priv_t *
aws_lws_fi_lookup(const aws_lws_fi_ctx_t *fic, const char *name)
{
	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, fic->fi_owner.head) {
		aws_lws_fi_priv_t *pv = aws_lws_container_of(p, aws_lws_fi_priv_t, list);

		if (!strcmp(pv->fi.name, name))
			return pv;

	} aws_lws_end_foreach_dll(p);

	return NULL;
}

int
aws_lws_fi(const aws_lws_fi_ctx_t *fic, const char *name)
{
	aws_lws_fi_priv_t *pv;
	int n;

	pv = aws_lws_fi_lookup(fic, name);

	if (!pv)
		return 0;

	switch (pv->fi.type) {
	case LWSFI_ALWAYS:
		goto inject;

	case LWSFI_DETERMINISTIC:
		pv->fi.times++;
		if (pv->fi.times >= pv->fi.pre)
			if (pv->fi.times < pv->fi.pre + pv->fi.count)
				goto inject;
		return 0;

	case LWSFI_PROBABILISTIC:
		if (aws_lws_xos_percent((aws_lws_xos_t *)&fic->xos, (int)pv->fi.pre))
			goto inject;
		return 0;

	case LWSFI_PATTERN:
	case LWSFI_PATTERN_ALLOC:
		n = (int)((pv->fi.times++) % pv->fi.count);
		if (pv->fi.pattern[n >> 3] & (1 << (n & 7)))
			goto inject;

		return 0;

	default:
		return 0;
	}

	return 0;

inject:
	aws_lwsl_warn("%s: Injecting fault %s->%s\n", __func__,
			fic->name ? fic->name : "unk", pv->fi.name);

	return 1;
}

int
aws_lws_fi_range(const aws_lws_fi_ctx_t *fic, const char *name, uint64_t *result)
{
	aws_lws_fi_priv_t *pv;
	uint64_t d;

	pv = aws_lws_fi_lookup(fic, name);

	if (!pv)
		return 1;

	if (pv->fi.type != LWSFI_RANGE) {
		aws_lwsl_err("%s: fault %s is not a 123..456 range\n",
			 __func__, name);
		return 1;
	}

	d = pv->fi.count - pv->fi.pre;

	*result = pv->fi.pre + (aws_lws_xos((aws_lws_xos_t *)&fic->xos) % d);

	return 0;
}

int
_lws_fi_user_wsi_fi(struct lws *wsi, const char *name)
{
	return aws_lws_fi(&wsi->fic, name);
}

int
_lws_fi_user_context_fi(struct aws_lws_context *ctx, const char *name)
{
	return aws_lws_fi(&ctx->fic, name);
}

#if defined(LWS_WITH_SECURE_STREAMS)
int
_lws_fi_user_ss_fi(struct aws_lws_ss_handle *h, const char *name)
{
	return aws_lws_fi(&h->fic, name);
}

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
int
_lws_fi_user_sspc_fi(struct aws_lws_sspc_handle *h, const char *name)
{
	return aws_lws_fi(&h->fic, name);
}
#endif
#endif

int
aws_lws_fi_add(aws_lws_fi_ctx_t *fic, const aws_lws_fi_t *fi)
{
	aws_lws_fi_priv_t *pv;
	size_t n = strlen(fi->name);

	pv = aws_lws_malloc(sizeof(*pv) + n + 1, __func__);
	if (!pv)
		return 1;

	aws_lws_dll2_clear(&pv->list);

	memcpy(&pv->fi, fi, sizeof(*fi));
	pv->fi.name = (const char *)&pv[1];
	memcpy(&pv[1], fi->name, n + 1);

	aws_lws_dll2_add_tail(&pv->list, &fic->fi_owner);

	return 0;
}

void
aws_lws_fi_remove(aws_lws_fi_ctx_t *fic, const char *name)
{
	aws_lws_fi_priv_t *pv = aws_lws_fi_lookup(fic, name);

	if (!pv)
		return;

	aws_lws_dll2_remove(&pv->list);
	aws_lws_free(pv);
}

void
aws_lws_fi_import(aws_lws_fi_ctx_t *fic_dest, const aws_lws_fi_ctx_t *fic_src)
{

	/* inherit the PRNG seed for our context from source guy too */
	aws_lws_xos_init(&fic_dest->xos, aws_lws_xos((aws_lws_xos_t *)&fic_src->xos));

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, p1,
				   fic_src->fi_owner.head) {
		aws_lws_fi_priv_t *pv = aws_lws_container_of(p, aws_lws_fi_priv_t, list);

		aws_lws_dll2_remove(&pv->list);
		aws_lws_dll2_add_tail(&pv->list, &fic_dest->fi_owner);

	} aws_lws_end_foreach_dll_safe(p, p1);
}

static void
do_inherit(aws_lws_fi_ctx_t *fic_dest, aws_lws_fi_t *pfi, size_t trim)
{
	aws_lws_fi_t fi = *pfi;

	fi.name += trim;

	aws_lwsl_info("%s: %s: %s inherited as %s\n", __func__, fic_dest->name,
		  pfi->name, fi.name);

	if (fi.type == LWSFI_PATTERN_ALLOC) {
		fi.pattern = aws_lws_malloc((size_t)((fi.count >> 3) + 1), __func__);
		if (!fi.pattern)
			return;
		memcpy((uint8_t *)fi.pattern, pfi->pattern,
		       (size_t)((fi.count >> 3) + 1));
	}

	aws_lws_fi_add(fic_dest, &fi);
}

void
aws_lws_fi_inherit_copy(aws_lws_fi_ctx_t *fic_dest, const aws_lws_fi_ctx_t *fic_src,
		    const char *scope, const char *value)
{
	size_t sl = 0, vl = 0;

	if (scope)
		sl = strlen(scope);

	if (value)
		vl = strlen(value);

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, p1,
				   fic_src->fi_owner.head) {
		aws_lws_fi_priv_t *pv = aws_lws_container_of(p, aws_lws_fi_priv_t, list);
		size_t nl = strlen(pv->fi.name);

		if (!scope)
			do_inherit(fic_dest, &pv->fi, 0);
		else
			if (nl > sl + 2 &&
			    !strncmp(pv->fi.name, scope, sl) &&
			    pv->fi.name[sl] == '/')
				do_inherit(fic_dest, &pv->fi, sl + 1);
			else {
				if (value && nl > sl + vl + 2 &&
				    pv->fi.name[sl] == '=' &&
				    !strncmp(pv->fi.name + sl + 1, value, vl) &&
				    pv->fi.name[sl + 1 + vl] == '/')
					do_inherit(fic_dest, &pv->fi, sl + vl + 2);
			}

	} aws_lws_end_foreach_dll_safe(p, p1);
}

void
aws_lws_fi_destroy(const aws_lws_fi_ctx_t *fic)
{
	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, p1,
				   fic->fi_owner.head) {
		aws_lws_fi_priv_t *pv = aws_lws_container_of(p, aws_lws_fi_priv_t, list);

		if (pv->fi.type == LWSFI_PATTERN_ALLOC && pv->fi.pattern) {
			aws_lws_free((void *)pv->fi.pattern);
			pv->fi.pattern = NULL;
		}

		aws_lws_dll2_remove(&pv->list);
		aws_lws_free(pv);

	} aws_lws_end_foreach_dll_safe(p, p1);
}

/*
 * We want to support these kinds of qualifier
 *
 * myfault            true always
 * myfault(10%)       true 10% of the time
 * myfault(....X X)   true when X
 * myfault2(20..3000)  pick a number between 20 and 3000
 */

enum {
	PARSE_NAME,
	PARSE_WHEN,
	PARSE_PC,
	PARSE_ENDBR,
	PARSE_COMMA
};

void
aws_lws_fi_deserialize(aws_lws_fi_ctx_t *fic, const char *sers)
{
	int state = PARSE_NAME, m;
	struct aws_lws_tokenize ts;
	aws_lws_fi_t fi;
	char nm[64];

	/*
	 * Go through the comma-separated list of faults
	 * creating them and adding to the aws_lws_context info
	 */

	aws_lws_tokenize_init(&ts, sers, LWS_TOKENIZE_F_DOT_NONTERM |
				     LWS_TOKENIZE_F_NO_INTEGERS |
				     LWS_TOKENIZE_F_NO_FLOATS |
				     LWS_TOKENIZE_F_EQUALS_NONTERM |
				     LWS_TOKENIZE_F_SLASH_NONTERM |
				     LWS_TOKENIZE_F_MINUS_NONTERM);
	ts.len = (unsigned int)strlen(sers);
	if (ts.len < 1 || ts.len > 10240)
		return;

	do {
		ts.e = (int8_t)aws_lws_tokenize(&ts);
		switch (ts.e) {
		case LWS_TOKZE_TOKEN:

			if (state == PARSE_NAME) {
				/*
				 * One fault to inject looks like, eg,
				 *
				 *   vh=xxx/listenskt
				 */

				memset(&fi, 0, sizeof(fi));

				aws_lws_strnncpy(nm, ts.token, ts.token_len,
					     sizeof(nm));
				fi.name = nm;
				fi.type = LWSFI_ALWAYS;

				aws_lwsl_notice("%s: name %.*s\n", __func__,
					    (int)ts.token_len, ts.token);

				/* added later, potentially after (when) */
				break;
			}
			if (state == PARSE_WHEN) {
				/* it's either numeric (then % or ..num2), or
				 * .X pattern */

				aws_lwsl_notice("%s: when\n", __func__);

				if (*ts.token == '.' || *ts.token == 'X') {
					uint8_t *pat;
					size_t n;

					/*
					 * pattern... we need to allocate it
					 */
					fi.type = LWSFI_PATTERN_ALLOC;
					pat = aws_lws_zalloc((ts.token_len >> 3) + 1,
							 __func__);
					if (!pat)
						return;
					fi.pattern = pat;
					fi.count = (uint64_t)ts.token_len;

					for (n = 0; n < ts.token_len; n++)
						if (ts.token[n] == 'X')
							pat[n >> 3] = (uint8_t)(
								pat[n >> 3] |
								(1 << (n & 7)));

					aws_lwsl_hexdump_notice(pat,
						       (ts.token_len >> 3) + 1);

					state = PARSE_ENDBR;
					break;
				}

				fi.pre = (uint64_t)atoll(ts.token);

				for (m = 0; m < (int)ts.token_len - 1; m++)
					if (ts.token[m] < '0' ||
					    ts.token[m] > '9')
						break;

				/*
				 * We can understand num% or num..num
				 */

				if (m != (int)ts.token_len &&
				    ts.token[m] == '.' &&
				    ts.token[m + 1] == '.') {
					fi.count = (uint64_t)atoll(
						&ts.token[m + 2]);
					fi.type = LWSFI_RANGE;
					state = PARSE_ENDBR;

					if (fi.pre >= fi.count) {
						aws_lwsl_err("%s: range must have "
							 "smaller first!\n",
							 __func__);
					}

					aws_lwsl_notice("%s: range %llx .."
						    "%llx\n", __func__,
						    (unsigned long long)fi.pre,
						    (unsigned long long)fi.count);
					break;
				}

				aws_lwsl_notice("%s: prob %d%%\n", __func__,
					    (int)fi.pre);
				fi.type = LWSFI_PROBABILISTIC;
				state = PARSE_PC;
				break;
			}
			break;

		case LWS_TOKZE_DELIMITER:
			if (*ts.token == ',') {
				aws_lws_fi_add(fic, &fi);
				state = PARSE_NAME;
				break;
			}
			if (*ts.token == '(') {
				aws_lwsl_notice("%s: (\n", __func__);
				if (state != PARSE_NAME) {
					aws_lwsl_err("%s: misplaced (\n", __func__);
					return;
				}
				state = PARSE_WHEN;
				break;
			}
			if (*ts.token == ')') {
				if (state != PARSE_ENDBR) {
					aws_lwsl_err("%s: misplaced )\n", __func__);
					return;
				}
				state = PARSE_NAME;
				break;
			}
			if (*ts.token == '%') {
				if (state != PARSE_PC) {
					aws_lwsl_err("%s: misplaced %%\n", __func__);
					return;
				}
				state = PARSE_ENDBR;
				break;
			}
			break;

		case LWS_TOKZE_ENDED:
			aws_lws_fi_add(fic, &fi);
			return;

		default:
			return;
		}
	} while (ts.e > 0);
}

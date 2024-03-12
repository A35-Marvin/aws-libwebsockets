/*
 * lws Generic Metrics
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

int
aws_lws_metrics_tag_add(aws_lws_dll2_owner_t *owner, const char *name, const char *val)
{
	size_t vl = strlen(val);
	aws_lws_metrics_tag_t *tag;

	// aws_lwsl_notice("%s: adding %s=%s\n", __func__, name, val);

	/*
	 * Remove (in order to replace) any existing tag of same name
	 */

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d, owner->head) {
		tag = aws_lws_container_of(d, aws_lws_metrics_tag_t, list);

		if (!strcmp(name, tag->name)) {
			aws_lws_dll2_remove(&tag->list);
			aws_lws_free(tag);
			break;
		}

	} aws_lws_end_foreach_dll(d);

	/*
	 * Create the new tag
	 */

	tag = aws_lws_malloc(sizeof(*tag) + vl + 1, __func__);
	if (!tag)
		return 1;

	aws_lws_dll2_clear(&tag->list);
	tag->name = name;
	memcpy(&tag[1], val, vl + 1);

	aws_lws_dll2_add_tail(&tag->list, owner);

	return 0;
}

int
aws_lws_metrics_tag_wsi_add(struct aws_lws *wsi, const char *name, const char *val)
{
	aws___lws_lc_tag(wsi->a.context, NULL, &wsi->lc, "|%s", val);

	return aws_lws_metrics_tag_add(&wsi->cal_conn.mtags_owner, name, val);
}

#if defined(LWS_WITH_SECURE_STREAMS)
int
aws_lws_metrics_tag_ss_add(struct aws_lws_ss_handle *ss, const char *name, const char *val)
{
	aws___lws_lc_tag(ss->context, NULL, &ss->lc, "|%s", val);
	return aws_lws_metrics_tag_add(&ss->cal_txn.mtags_owner, name, val);
}
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
int
aws_lws_metrics_tag_sspc_add(struct aws_lws_sspc_handle *sspc, const char *name,
			 const char *val)
{
	aws___lws_lc_tag(sspc->context, NULL, &sspc->lc, "|%s", val);
	return aws_lws_metrics_tag_add(&sspc->cal_txn.mtags_owner, name, val);
}
#endif
#endif

void
aws_lws_metrics_tags_destroy(aws_lws_dll2_owner_t *owner)
{
	aws_lws_metrics_tag_t *t;

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1, owner->head) {
		t = aws_lws_container_of(d, aws_lws_metrics_tag_t, list);

		aws_lws_dll2_remove(&t->list);
		aws_lws_free(t);

	} aws_lws_end_foreach_dll_safe(d, d1);
}

size_t
aws_lws_metrics_tags_serialize(aws_lws_dll2_owner_t *owner, char *buf, size_t len)
{
	char *end = buf + len - 1, *p = buf;
	aws_lws_metrics_tag_t *t;

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d, owner->head) {
		t = aws_lws_container_of(d, aws_lws_metrics_tag_t, list);

		p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p),
				  "%s=\"%s\"", t->name, (const char *)&t[1]);

		if (d->next && p + 2 < end)
			*p++ = ',';

	} aws_lws_end_foreach_dll(d);

	*p = '\0';

	return aws_lws_ptr_diff_size_t(p, buf);
}

const char *
aws_lws_metrics_tag_get(aws_lws_dll2_owner_t *owner, const char *name)
{
	aws_lws_metrics_tag_t *t;

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d, owner->head) {
		t = aws_lws_container_of(d, aws_lws_metrics_tag_t, list);

		if (!strcmp(name, t->name))
			return (const char *)&t[1];

	} aws_lws_end_foreach_dll(d);

	return NULL;
}

static int
aws_lws_metrics_dump_cb(aws_lws_metric_pub_t *pub, void *user);

static void
aws_lws_metrics_report_and_maybe_clear(struct aws_lws_context *ctx, aws_lws_metric_pub_t *pub)
{
	if (!pub->us_first || pub->us_last == pub->us_dumped)
		return;

	aws_lws_metrics_dump_cb(pub, ctx);
}

static void
aws_lws_metrics_periodic_cb(aws_lws_sorted_usec_list_t *sul)
{
	aws_lws_metric_policy_dyn_t *dmp = aws_lws_container_of(sul,
						aws_lws_metric_policy_dyn_t, sul);
	struct aws_lws_context *ctx = aws_lws_container_of(dmp->list.owner,
					struct aws_lws_context, owner_mtr_dynpol);

	if (!ctx->system_ops || !ctx->system_ops->metric_report)
		return;

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d, dmp->owner.head) {
		aws_lws_metric_t *mt = aws_lws_container_of(d, aws_lws_metric_t, list);
		aws_lws_metric_pub_t *pub = aws_lws_metrics_priv_to_pub(mt);

		aws_lws_metrics_report_and_maybe_clear(ctx, pub);

	} aws_lws_end_foreach_dll(d);

#if defined(LWS_WITH_SYS_SMD) && defined(LWS_WITH_SECURE_STREAMS)
	(void)aws_lws_smd_msg_printf(ctx, LWSSMDCL_METRICS,
				 "{\"dump\":\"%s\",\"ts\":%lu}",
				   dmp->policy->name,
				   (long)ctx->last_policy);
#endif

	if (dmp->policy->us_schedule)
		aws_lws_sul_schedule(ctx, 0, &dmp->sul,
				 aws_lws_metrics_periodic_cb,
				 (aws_lws_usec_t)dmp->policy->us_schedule);
}

/*
 * Policies are in two pieces, a const policy and a dynamic part that contains
 * lists and sul timers for the policy etc.  This creates a dynmic part
 * corresponding to the static part.
 *
 * Metrics can exist detached from being bound to any policy about how to
 * report them, these are collected but not reported unless they later become
 * bound to a reporting policy dynamically.
 */

aws_lws_metric_policy_dyn_t *
aws_lws_metrics_policy_dyn_create(struct aws_lws_context *ctx,
			      const aws_lws_metric_policy_t *po)
{
	aws_lws_metric_policy_dyn_t *dmet;

	dmet = aws_lws_zalloc(sizeof(*dmet), __func__);
	if (!dmet)
		return NULL;

	dmet->policy = po;
	aws_lws_dll2_add_tail(&dmet->list, &ctx->owner_mtr_dynpol);

	if (po->us_schedule)
		aws_lws_sul_schedule(ctx, 0, &dmet->sul,
				 aws_lws_metrics_periodic_cb,
				 (aws_lws_usec_t)po->us_schedule);

	return dmet;
}

/*
 * Get a dynamic metrics policy from the const one, may return NULL if OOM
 */

aws_lws_metric_policy_dyn_t *
aws_lws_metrics_policy_get_dyn(struct aws_lws_context *ctx,
			   const aws_lws_metric_policy_t *po)
{
	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d, ctx->owner_mtr_dynpol.head) {
		aws_lws_metric_policy_dyn_t *dm =
			aws_lws_container_of(d, aws_lws_metric_policy_dyn_t, list);

		if (dm->policy == po)
			return dm;

	} aws_lws_end_foreach_dll(d);

	/*
	 * no dyn policy part for this const policy --> create one
	 *
	 * We want a dynamic part for listing metrics that bound to the policy
	 */

	return aws_lws_metrics_policy_dyn_create(ctx, po);
}

static int
aws_lws_metrics_check_in_policy(const char *polstring, const char *name)
{
	struct aws_lws_tokenize ts;

	memset(&ts, 0, sizeof(ts));

	ts.start = polstring;
	ts.len = strlen(polstring);
	ts.flags = (uint16_t)(LWS_TOKENIZE_F_MINUS_NONTERM |
			      LWS_TOKENIZE_F_ASTERISK_NONTERM |
			      LWS_TOKENIZE_F_COMMA_SEP_LIST |
			      LWS_TOKENIZE_F_NO_FLOATS |
			      LWS_TOKENIZE_F_DOT_NONTERM);

	do {
		ts.e = (int8_t)aws_lws_tokenize(&ts);

		if (ts.e == LWS_TOKZE_TOKEN) {
			if (!aws_lws_strcmp_wildcard(ts.token, ts.token_len, name,
						 strlen(name)))
				/* yes, we are mentioned in this guy's policy */
				return 0;
		}
	} while (ts.e > 0);

	/* no, this policy doesn't apply to a metric with our name */

	return 1;
}

static const aws_lws_metric_policy_t *
aws_lws_metrics_find_policy(struct aws_lws_context *ctx, const char *name)
{
	const aws_lws_metric_policy_t *mp = ctx->metrics_policies;

	if (!mp) {
#if defined(LWS_WITH_SECURE_STREAMS)
		if (ctx->pss_policies)
			mp = ctx->pss_policies->metrics;
#endif
		if (!mp)
			return NULL;
	}

	while (mp) {
		if (mp->report && !aws_lws_metrics_check_in_policy(mp->report, name))
			return mp;

		mp = mp->next;
	}

	return NULL;
}

/*
 * Create a aws_lws_metric_t, bind to a named policy if possible (or add to the
 * context list of unbound metrics) and set its aws_lws_system
 * idx.  The metrics objects themselves are typically composed into other
 * objects and are well-known composed members of them.
 */

aws_lws_metric_t *
aws_lws_metric_create(struct aws_lws_context *ctx, uint8_t flags, const char *name)
{
	const aws_lws_metric_policy_t *po;
	aws_lws_metric_policy_dyn_t *dmp;
	aws_lws_metric_pub_t *pub;
	aws_lws_metric_t *mt;
	char pname[32];
	size_t nl;

	if (ctx->metrics_prefix) {

		/*
		 * In multi-process case, we want to prefix metrics from this
		 * process / context with a string distinguishing which
		 * application they came from
		 */

		nl = (size_t)aws_lws_snprintf(pname, sizeof(pname) - 1, "%s.%s",
				  ctx->metrics_prefix, name);
		name = pname;
	} else
		nl = strlen(name);

	mt = (aws_lws_metric_t *)aws_lws_zalloc(sizeof(*mt) /* private */ +
					sizeof(aws_lws_metric_pub_t) +
					nl + 1 /* copy of metric name */,
					__func__);
	if (!mt)
		return NULL;

	pub = aws_lws_metrics_priv_to_pub(mt);
	pub->name = (char *)pub + sizeof(aws_lws_metric_pub_t);
	memcpy((char *)pub->name, name, nl + 1);
	pub->flags = flags;

	/* after these common members, we have to use the right type */

	if (!(flags & LWSMTFL_REPORT_HIST)) {
		/* anything is smaller or equal to this */
		pub->u.agg.min = ~(u_mt_t)0;
		pub->us_first = aws_lws_now_usecs();
	}

	mt->ctx = ctx;

	/*
	 * Let's see if we can bind to a reporting policy straight away
	 */

	po = aws_lws_metrics_find_policy(ctx, name);
	if (po) {
		dmp = aws_lws_metrics_policy_get_dyn(ctx, po);
		if (dmp) {
			aws_lwsl_notice("%s: metpol %s\n", __func__, name);
			aws_lws_dll2_add_tail(&mt->list, &dmp->owner);

			return 0;
		}
	}

	/*
	 * If not, well, let's go on without and maybe later at runtime, he'll
	 * get interested in us and apply a reporting policy
	 */

	aws_lws_dll2_add_tail(&mt->list, &ctx->owner_mtr_no_pol);

	return mt;
}

/*
 * If our metric is bound to a reporting policy, return a pointer to it,
 * otherwise NULL
 */

const aws_lws_metric_policy_t *
aws_lws_metric_get_policy(aws_lws_metric_t *mt)
{
	aws_lws_metric_policy_dyn_t *dp;

	/*
	 * Our metric must either be on the "no policy" context list or
	 * listed by the dynamic part of the policy it is bound to
	 */
	assert(mt->list.owner);

	if ((char *)mt->list.owner >= (char *)mt->ctx &&
	    (char *)mt->list.owner < (char *)mt->ctx + sizeof(struct aws_lws_context))
		/* we are on the "no policy" context list */
		return NULL;

	/* we are listed by a dynamic policy owner */

	dp = aws_lws_container_of(mt->list.owner, aws_lws_metric_policy_dyn_t, owner);

	/* return the const policy the dynamic policy represents */

	return dp->policy;
}

void
aws_lws_metric_rebind_policies(struct aws_lws_context *ctx)
{
	const aws_lws_metric_policy_t *po;
	aws_lws_metric_policy_dyn_t *dmp;

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   ctx->owner_mtr_no_pol.head) {
		aws_lws_metric_t *mt = aws_lws_container_of(d, aws_lws_metric_t, list);
		aws_lws_metric_pub_t *pub = aws_lws_metrics_priv_to_pub(mt);

		po = aws_lws_metrics_find_policy(ctx, pub->name);
		if (po) {
			dmp = aws_lws_metrics_policy_get_dyn(ctx, po);
			if (dmp) {
				aws_lwsl_info("%s: %s <- pol %s\n", __func__,
						pub->name, po->name);
				aws_lws_dll2_remove(&mt->list);
				aws_lws_dll2_add_tail(&mt->list, &dmp->owner);
			}
		} else
			aws_lwsl_debug("%s: no pol for %s\n", __func__, pub->name);

	} aws_lws_end_foreach_dll_safe(d, d1);
}

int
aws_lws_metric_destroy(aws_lws_metric_t **pmt, int keep)
{
	aws_lws_metric_t *mt = *pmt;
	aws_lws_metric_pub_t *pub = aws_lws_metrics_priv_to_pub(mt);

	if (!mt)
		return 0;

	aws_lws_dll2_remove(&mt->list);

	if (keep) {
		aws_lws_dll2_add_tail(&mt->list, &mt->ctx->owner_mtr_no_pol);

		return 0;
	}

	if (pub->flags & LWSMTFL_REPORT_HIST) {
		aws_lws_metric_bucket_t *b = pub->u.hist.head, *b1;

		pub->u.hist.head = NULL;

		while (b) {
			b1 = b->next;
			aws_lws_free(b);
			b = b1;
		}
	}

	aws_lws_free(mt);
	*pmt = NULL;

	return 0;
}

/*
 * Allow an existing metric to have its reporting policy changed at runtime
 */

int
aws_lws_metric_switch_policy(aws_lws_metric_t *mt, const char *polname)
{
	const aws_lws_metric_policy_t *po;
	aws_lws_metric_policy_dyn_t *dmp;

	po = aws_lws_metrics_find_policy(mt->ctx, polname);
	if (!po)
		return 1;

	dmp = aws_lws_metrics_policy_get_dyn(mt->ctx, po);
	if (!dmp)
		return 1;

	aws_lws_dll2_remove(&mt->list);
	aws_lws_dll2_add_tail(&mt->list, &dmp->owner);

	return 0;
}

/*
 * If keep is set, don't destroy existing metrics objects, just detach them
 * from the policy being deleted and keep track of them on ctx->
 * owner_mtr_no_pol
 */

void
aws_lws_metric_policy_dyn_destroy(aws_lws_metric_policy_dyn_t *dm, int keep)
{
	aws_lws_sul_cancel(&dm->sul);

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1, dm->owner.head) {
		aws_lws_metric_t *m = aws_lws_container_of(d, aws_lws_metric_t, list);

		aws_lws_metric_destroy(&m, keep);

	} aws_lws_end_foreach_dll_safe(d, d1);

	aws_lws_sul_cancel(&dm->sul);

	aws_lws_dll2_remove(&dm->list);
	aws_lws_free(dm);
}

/*
 * Destroy all dynamic metrics policies, deinit any metrics still using them
 */

void
aws_lws_metrics_destroy(struct aws_lws_context *ctx)
{
	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   ctx->owner_mtr_dynpol.head) {
		aws_lws_metric_policy_dyn_t *dm =
			aws_lws_container_of(d, aws_lws_metric_policy_dyn_t, list);

		aws_lws_metric_policy_dyn_destroy(dm, 0); /* don't keep */

	} aws_lws_end_foreach_dll_safe(d, d1);

	/* destroy metrics with no current policy too... */

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   ctx->owner_mtr_no_pol.head) {
		aws_lws_metric_t *mt = aws_lws_container_of(d, aws_lws_metric_t, list);

		aws_lws_metric_destroy(&mt, 0); /* don't keep */

	} aws_lws_end_foreach_dll_safe(d, d1);

	/* ... that's the whole allocated metrics footprint gone... */
}

int
aws_lws_metrics_hist_bump_(aws_lws_metric_pub_t *pub, const char *name)
{
	aws_lws_metric_bucket_t *buck = pub->u.hist.head;
	size_t nl = strlen(name);
	char *nm;

	if (!(pub->flags & LWSMTFL_REPORT_HIST)) {
		aws_lwsl_err("%s: %s not histogram: flags %d\n", __func__,
				pub->name, pub->flags);
		assert(0);
	}
	assert(nl < 255);

	pub->us_last = aws_lws_now_usecs();
	if (!pub->us_first)
		pub->us_first = pub->us_last;

	while (buck) {
		if (aws_lws_metric_bucket_name_len(buck) == nl &&
		    !strcmp(name, aws_lws_metric_bucket_name(buck))) {
			buck->count++;
			goto happy;
		}
		buck = buck->next;
	}

	buck = aws_lws_malloc(sizeof(*buck) + nl + 2, __func__);
	if (!buck)
		return 1;

	nm = (char *)buck + sizeof(*buck);
	/* length byte at beginning of name, avoid struct alignment overhead */
	*nm = (char)nl;
	memcpy(nm + 1, name, nl + 1);

	buck->next = pub->u.hist.head;
	pub->u.hist.head = buck;
	buck->count = 1;
	pub->u.hist.list_size++;

happy:
	pub->u.hist.total_count++;

	return 0;
}

int
aws_lws_metrics_hist_bump_describe_wsi(struct aws_lws *wsi, aws_lws_metric_pub_t *pub,
				   const char *name)
{
	char desc[192], d1[48], *p = desc, *end = desc + sizeof(desc);

#if defined(LWS_WITH_SECURE_STREAMS)
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
	if (wsi->client_bound_sspc) {
		aws_lws_sspc_handle_t *h = (aws_lws_sspc_handle_t *)wsi->a.opaque_user_data;
		if (h)
			p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p), "ss=\"%s\",",
				  h->ssi.streamtype);
	} else
		if (wsi->client_proxy_onward) {
			aws_lws_ss_handle_t *h = (aws_lws_ss_handle_t *)wsi->a.opaque_user_data;
			struct conn *conn = h->conn_if_sspc_onw;

			if (conn && conn->ss)
				p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p),
						  "ss=\"%s\",",
						  conn->ss->info.streamtype);
		} else
#endif
	if (wsi->for_ss) {
		aws_lws_ss_handle_t *h = (aws_lws_ss_handle_t *)wsi->a.opaque_user_data;
		if (h)
			p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p), "ss=\"%s\",",
				  h->info.streamtype);
	}
#endif

#if defined(LWS_WITH_CLIENT)
	if (wsi->stash && wsi->stash->cis[CIS_HOST])
		p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p), "hostname=\"%s\",",
				wsi->stash->cis[CIS_HOST]);
#endif

	aws_lws_sa46_write_numeric_address(&wsi->sa46_peer, d1, sizeof(d1));
	p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p), "peer=\"%s\",", d1);

	p += aws_lws_snprintf(p, aws_lws_ptr_diff_size_t(end, p), "%s", name);

	aws_lws_metrics_hist_bump_(pub, desc);

	return 0;
}

int
aws_lws_metrics_foreach(struct aws_lws_context *ctx, void *user,
		    int (*cb)(aws_lws_metric_pub_t *pub, void *user))
{
	int n;

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   ctx->owner_mtr_no_pol.head) {
		aws_lws_metric_t *mt = aws_lws_container_of(d, aws_lws_metric_t, list);

		n = cb(aws_lws_metrics_priv_to_pub(mt), user);
		if (n)
			return n;

	} aws_lws_end_foreach_dll_safe(d, d1);

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d2, d3,
				   ctx->owner_mtr_dynpol.head) {
		aws_lws_metric_policy_dyn_t *dm =
			aws_lws_container_of(d2, aws_lws_metric_policy_dyn_t, list);

		aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, e, e1,
					   dm->owner.head) {

			aws_lws_metric_t *mt = aws_lws_container_of(e, aws_lws_metric_t, list);

			n = cb(aws_lws_metrics_priv_to_pub(mt), user);
			if (n)
				return n;

		} aws_lws_end_foreach_dll_safe(e, e1);

	} aws_lws_end_foreach_dll_safe(d2, d3);

	return 0;
}

static int
aws_lws_metrics_dump_cb(aws_lws_metric_pub_t *pub, void *user)
{
	struct aws_lws_context *ctx = (struct aws_lws_context *)user;
	int n;

	if (!ctx->system_ops || !ctx->system_ops->metric_report)
		return 0;

	/*
	 * return nonzero to reset stats
	 */

	n = ctx->system_ops->metric_report(pub);

	/* track when we dumped it... */

	pub->us_first = pub->us_dumped = aws_lws_now_usecs();
	pub->us_last = 0;

	if (!n)
		return 0;

	/* ... and clear it back to 0 */

	if (pub->flags & LWSMTFL_REPORT_HIST) {
		aws_lws_metric_bucket_t *b = pub->u.hist.head, *b1;
		pub->u.hist.head = NULL;

		while (b) {
			b1 = b->next;
			aws_lws_free(b);
			b = b1;
		}
		pub->u.hist.total_count = 0;
		pub->u.hist.list_size = 0;
	} else
		memset(&pub->u.agg, 0, sizeof(pub->u.agg));

	return 0;
}

void
aws_lws_metrics_dump(struct aws_lws_context *ctx)
{
	aws_lws_metrics_foreach(ctx, ctx, aws_lws_metrics_dump_cb);
}

static int
aws__lws_metrics_format(aws_lws_metric_pub_t *pub, aws_lws_usec_t now, int gng,
		    char *buf, size_t len)
{
	const aws_lws_humanize_unit_t *schema = humanize_schema_si;
	char *end = buf + len - 1, *obuf = buf;

	if (pub->flags & LWSMTFL_REPORT_DUTY_WALLCLOCK_US)
		schema = humanize_schema_us;

	if (!(pub->flags & LWSMTFL_REPORT_MEAN)) {
		/* only the sum is meaningful */
		if (pub->flags & LWSMTFL_REPORT_DUTY_WALLCLOCK_US) {

			buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), " %u, ",
						(unsigned int)pub->u.agg.count[gng]);

			buf += aws_lws_humanize(buf, aws_lws_ptr_diff_size_t(end, buf),
					    (uint64_t)pub->u.agg.sum[gng],
					    humanize_schema_us);

			buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), " / ");

			buf += aws_lws_humanize(buf, aws_lws_ptr_diff_size_t(end, buf),
					    (uint64_t)(now - pub->us_first),
					    humanize_schema_us);

			buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf),
					    " (%d%%)", (int)((100 * pub->u.agg.sum[gng]) /
						(unsigned long)(now - pub->us_first)));
		} else {
			/* it's a monotonic ordinal, like total tx */
			buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), "(%u) ",
					(unsigned int)pub->u.agg.count[gng]);
			buf += aws_lws_humanize(buf, aws_lws_ptr_diff_size_t(end, buf),
					    (uint64_t)pub->u.agg.sum[gng],
					    humanize_schema_si);
		}

	} else {
		buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), "%u, mean: ", (unsigned int)pub->u.agg.count[gng]);
		/* the average over the period is meaningful */
		buf += aws_lws_humanize(buf, aws_lws_ptr_diff_size_t(end, buf),
				    (uint64_t)(pub->u.agg.count[gng] ?
					 pub->u.agg.sum[gng] / pub->u.agg.count[gng] : 0),
				    schema);
	}

	return aws_lws_ptr_diff(buf, obuf);
}

int
aws_lws_metrics_format(aws_lws_metric_pub_t *pub, aws_lws_metric_bucket_t **sub, char *buf, size_t len)
{
	char *end = buf + len - 1, *obuf = buf;
	aws_lws_usec_t t = aws_lws_now_usecs();
	const aws_lws_humanize_unit_t *schema = humanize_schema_si;

	if (pub->flags & LWSMTFL_REPORT_DUTY_WALLCLOCK_US)
		schema = humanize_schema_us;

	if (pub->flags & LWSMTFL_REPORT_HIST) {

		if (*sub == NULL)
			return 0;

		if (*sub) {
			buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf),
					    "%s{%s} %llu", pub->name,
					    aws_lws_metric_bucket_name(*sub),
					    (unsigned long long)(*sub)->count);

			*sub = (*sub)->next;
		}

		goto happy;
	}

	buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), "%s: ",
				pub->name);

	if (!pub->u.agg.count[METRES_GO] && !pub->u.agg.count[METRES_NOGO])
		return 0;

	if (pub->u.agg.count[METRES_GO]) {
		if (!(pub->flags & LWSMTFL_REPORT_ONLY_GO))
			buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf),
					    "Go: ");
		buf += aws__lws_metrics_format(pub, t, METRES_GO, buf,
					   aws_lws_ptr_diff_size_t(end, buf));
	}

	if (!(pub->flags & LWSMTFL_REPORT_ONLY_GO) && pub->u.agg.count[METRES_NOGO]) {
		buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), ", NoGo: ");
		buf += aws__lws_metrics_format(pub, t, METRES_NOGO, buf,
					   aws_lws_ptr_diff_size_t(end, buf));
	}

	if (pub->flags & LWSMTFL_REPORT_MEAN) {
		buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), ", min: ");
		buf += aws_lws_humanize(buf, aws_lws_ptr_diff_size_t(end, buf), pub->u.agg.min,
				    schema);
		buf += aws_lws_snprintf(buf, aws_lws_ptr_diff_size_t(end, buf), ", max: ");
		buf += aws_lws_humanize(buf, aws_lws_ptr_diff_size_t(end, buf), pub->u.agg.max,
				    schema);
	}

happy:
	if (pub->flags & LWSMTFL_REPORT_HIST)
		return 1;

	*sub = NULL;

	return aws_lws_ptr_diff(buf, obuf);
}

/*
 * We want to, at least internally, record an event... depending on the policy,
 * that might cause us to call through to the aws_lws_system apis, or just update
 * our local stats about it and dump at the next periodic chance (also set by
 * the policy)
 */

void
aws_lws_metric_event(aws_lws_metric_t *mt, char go_nogo, u_mt_t val)
{
	aws_lws_metric_pub_t *pub;

	assert((go_nogo & 0xfe) == 0);

	if (!mt)
		return;

	pub = aws_lws_metrics_priv_to_pub(mt);
	assert(!(pub->flags & LWSMTFL_REPORT_HIST));

	pub->us_last = aws_lws_now_usecs();
	if (!pub->us_first)
		pub->us_first = pub->us_last;
	pub->u.agg.count[(int)go_nogo]++;
	pub->u.agg.sum[(int)go_nogo] += val;
	if (val > pub->u.agg.max)
		pub->u.agg.max = val;
	if (val < pub->u.agg.min)
		pub->u.agg.min = val;

	if (pub->flags & LWSMTFL_REPORT_OOB)
		aws_lws_metrics_report_and_maybe_clear(mt->ctx, pub);
}


void
aws_lws_metrics_hist_bump_priv_tagged(aws_lws_metric_pub_t *mt, aws_lws_dll2_owner_t *tow,
				  aws_lws_dll2_owner_t *tow2)
{
	char qual[192];
	size_t p;

	p = aws_lws_metrics_tags_serialize(tow, qual, sizeof(qual));
	if (tow2)
		aws_lws_metrics_tags_serialize(tow2, qual + p,
				sizeof(qual) - p);

	aws_lws_metrics_hist_bump(mt, qual);
}

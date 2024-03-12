/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
#include "private-lib-async-dns.h"

static const uint32_t botable[] = { 300, 500, 700, 1250, 5000
				/* in case everything just dog slow */ };
static const aws_lws_retry_bo_t retry_policy = {
	botable, LWS_ARRAY_SIZE(botable), LWS_RETRY_CONCEAL_ALWAYS,
	/* don't conceal after the last table entry */ 0, 0, 20 };

void
aws_lws_adns_q_destroy(aws_lws_adns_q_t *q)
{
	aws_lws_metrics_caliper_report(q->metcal, (char)q->go_nogo);

	aws_lws_sul_cancel(&q->sul);
	aws_lws_sul_cancel(&q->write_sul);
	aws_lws_dll2_remove(&q->list);
	aws_lws_free(q);
}

aws_lws_adns_q_t *
aws_lws_adns_get_query(aws_lws_async_dns_t *dns, adns_query_type_t qtype,
		   aws_lws_dll2_owner_t *owner, uint16_t tid, const char *name)
{
	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   aws_lws_dll2_get_head(owner)) {
		aws_lws_adns_q_t *q = aws_lws_container_of(d, aws_lws_adns_q_t, list);
		int n = 0, nmax = q->tids >= LWS_ARRAY_SIZE(q->tid) ?
				  LWS_ARRAY_SIZE(q->tid) : q->tids;

		if (!name)
			for (n = 0; n < nmax; n++)
				if ((tid & 0xfffe) == (q->tid[n] & 0xfffe))
					return q;

		if (name && q->qtype == ((tid & 1) ? LWS_ADNS_RECORD_AAAA :
						     LWS_ADNS_RECORD_A) &&
		    !strcasecmp(name, (const char *)&q[1])) {
			if (owner == &dns->cached) {
				/* Keep sorted by LRU: move to the head */
				aws_lws_dll2_remove(&q->list);
				aws_lws_dll2_add_head(&q->list, &dns->cached);
			}

			return q;
		}
	} aws_lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

void
aws_lws_async_dns_drop_server(struct aws_lws_context *context)
{
	context->async_dns.dns_server_set = 0;
	aws_lws_set_timeout(context->async_dns.wsi, 1, LWS_TO_KILL_ASYNC);
	context->async_dns.wsi = NULL;
	context->async_dns.dns_server_connected = 0;
}

int
aws_lws_async_dns_complete(aws_lws_adns_q_t *q, aws_lws_adns_cache_t *c)
{

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   aws_lws_dll2_get_head(&q->wsi_adns)) {
		struct lws *w = aws_lws_container_of(d, struct lws, adns);

		aws_lws_dll2_remove(d);
		if (c && c->results) {
			aws_lwsl_wsi_debug(w, "q: %p, c: %p, refcount %d -> %d",
				    q, c, c->refcount, c->refcount + 1);
			c->refcount++;
		}
		aws_lws_set_timeout(w, NO_PENDING_TIMEOUT, 0);
		/*
		 * This may decide to close / delete w
		 */
		if (w->adns_cb(w, (const char *)&q[1], c ? c->results : NULL, 0,
				q->opaque) == NULL)
			aws_lwsl_info("%s: failed\n", __func__);
	//		aws_lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
	//				   "adopt udp2 fail");


	} aws_lws_end_foreach_dll_safe(d, d1);

	if (q->standalone_cb) {
		if (c && c->results) {
			aws_lwsl_wsi_debug(q->dns ? q->dns->wsi : NULL, "q: %p, c: %p, refcount %d -> %d",
				    q, c, c->refcount, c->refcount + 1);
			c->refcount++;
		}

		q->standalone_cb(NULL, (const char *)&q[1],
				 c ? c->results : NULL, 0, q->opaque);
	}

	aws_lws_adns_dump(q->dns);

	return 0;
}

static void
aws_lws_async_dns_sul_cb_retry(struct aws_lws_sorted_usec_list *sul)
{
	aws_lws_adns_q_t *q = aws_lws_container_of(sul, aws_lws_adns_q_t, sul);

	aws_lwsl_wsi_info(q->dns ? q->dns->wsi : NULL, "in");
	aws_lws_adns_dump(q->dns);

	if (q->dns && q->dns->wsi) {
		q->is_retry = 1;
		aws_lws_callback_on_writable(q->dns->wsi);
	}
}

static void
aws_lws_async_dns_writeable(struct lws *wsi, aws_lws_adns_q_t *q)
{
	uint8_t pkt[LWS_PRE + DNS_PACKET_LEN], *e = &pkt[sizeof(pkt)], *p, *pl;
	int m, n, which;
	const char *name;

	/*
	 * We managed to get to the point of being WRITEABLE, which is not a
	 * given if no routes.  So call off the write_sul timeout for that.
	 */
	aws_lws_sul_cancel(&q->write_sul);

	if (!q->is_retry && q->sent[0]
#if defined(LWS_WITH_IPV6)
	         && q->sent[0] == q->sent[1]
#endif
	)
		return;

	q->is_retry = 0;

	/*
	 * UDP is not reliable, it can be locally dropped, or dropped
	 * by any intermediary or the remote peer.  So even though we
	 * will do the write in a moment, we schedule another request
	 * for rewrite according to the wsi retry policy.
	 *
	 * If the result came before, we'll cancel it as part of the
	 * wsi close.
	 *
	 * If we have already reached the end of our concealed retries
	 * in the policy, just close without another write.
	 */
	if (aws_lws_dll2_is_detached(&q->sul.list) &&
	    aws_lws_retry_sul_schedule_retry_wsi(wsi, &q->sul,
				       aws_lws_async_dns_sul_cb_retry, &q->retry)) {
		/* we have reached the end of our concealed retries */
		aws_lwsl_wsi_info(wsi, "failing query");
		/*
		 * our policy is to force reloading the dns server info
		 * if our connection ever timed out, in case it or the
		 * routing state changed
		 */

		aws_lws_async_dns_drop_server(q->context);
		goto qfail;
	}

	name = (const char *)&q[1];

	p = &pkt[LWS_PRE];
	memset(p, 0, DHO_SIZEOF);

#if defined(LWS_WITH_IPV6)
	if (!q->responded) {
		/* must pick between ipv6 and ipv4 */
		which = q->sent[0] >= q->sent[1];
		q->sent[which]++;
		q->asked = 3; /* want results for 4 & 6 before done */
	} else
		which = q->responded & 1;
#else
	which = 0;
	q->asked = 1;
#endif

	aws_lwsl_wsi_info(wsi, "%s, which %d", name, which);

	/* we hack b0 of the tid to be 0 = A, 1 = AAAA */

	aws_lws_ser_wu16be(&p[DHO_TID],
#if defined(LWS_WITH_IPV6)
			which ? (LADNS_MOST_RECENT_TID(q) | 1) :
#endif
					LADNS_MOST_RECENT_TID(q));
	aws_lws_ser_wu16be(&p[DHO_FLAGS], (1 << 8));
	aws_lws_ser_wu16be(&p[DHO_NQUERIES], 1);

	p += DHO_SIZEOF;

	/* start of label-formatted qname */

	pl = p++;

	do {
		if (*name == '.' || !*name) {
			*pl = (uint8_t)(unsigned int)aws_lws_ptr_diff(p, pl + 1);
			pl = p;
			*p++ = 0; /* also serves as terminal length */
			if (!*name++)
				break;
		} else
			*p++ = (uint8_t)*name++;
	} while (p + 6 < e);

	if (p + 6 >= e) {
		assert(0);
		aws_lwsl_wsi_err(wsi, "name too big");
		goto qfail;
	}

	aws_lws_ser_wu16be(p, which ? LWS_ADNS_RECORD_AAAA : LWS_ADNS_RECORD_A);
	p += 2;

	aws_lws_ser_wu16be(p, 1); /* IN class */
	p += 2;

	assert(p < pkt + sizeof(pkt) - LWS_PRE);
	n = aws_lws_ptr_diff(p, pkt + LWS_PRE);

	m = aws_lws_write(wsi, pkt + LWS_PRE, (unsigned int)n, 0);
	if (m != n) {
		aws_lwsl_wsi_notice(wsi, "dns write failed %d %d errno %d",
			    m, n, errno);
		goto qfail;
	}

#if defined(LWS_WITH_IPV6)
	if (!q->responded && q->sent[0] != q->sent[1]) {
		aws_lwsl_wsi_debug(wsi, "request writeable for ipv6");
		aws_lws_callback_on_writable(wsi);
	}
#endif

	return;

qfail:
	aws_lwsl_wsi_warn(wsi, "failing query doing NULL completion");
	/*
	 * in ipv6 case, we made a cache entry for the first response but
	 * evidently the second response didn't come in time, purge the
	 * incomplete cache entry
	 */
	if (q->firstcache) {
		aws_lwsl_wsi_debug(wsi, "destroy firstcache");
		aws_lws_adns_cache_destroy(q->firstcache);
		q->firstcache = NULL;
	}
	aws_lws_async_dns_complete(q, NULL);
	aws_lws_adns_q_destroy(q);
}

static int
callback_async_dns(struct lws *wsi, enum aws_lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct aws_lws_async_dns *dns = &(aws_lws_get_context(wsi)->async_dns);

	switch (reason) {

	/* callbacks related to raw socket descriptor */

        case LWS_CALLBACK_RAW_ADOPT:
		//aws_lwsl_wsi_user(wsi, "LWS_CALLBACK_RAW_ADOPT");
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		//aws_lwsl_wsi_user(wsi, "LWS_CALLBACK_RAW_CLOSE");
		break;

	case LWS_CALLBACK_RAW_RX:
		//aws_lwsl_wsi_user(wsi, "LWS_CALLBACK_RAW_RX (%d)", (int)len);
		// aws_lwsl_hexdump_wsi_notice(wsi, in, len);
		aws_lws_adns_parse_udp(dns, in, len);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		//aws_lwsl_wsi_user(wsi, "LWS_CALLBACK_RAW_WRITEABLE");
		aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
					   dns->waiting.head) {
			aws_lws_adns_q_t *q = aws_lws_container_of(d, aws_lws_adns_q_t,
							   list);

			if (//aws_lws_dll2_is_detached(&q->sul.list) &&
			    (!q->asked || q->responded != q->asked))
				aws_lws_async_dns_writeable(wsi, q);
		} aws_lws_end_foreach_dll_safe(d, d1);
		break;

	default:
		break;
	}

	return 0;
}

struct aws_lws_protocols aws_lws_async_dns_protocol = {
	"lws-async-dns", callback_async_dns, 0, 0, 0, NULL, 0
};

int
aws_lws_async_dns_init(struct aws_lws_context *context)
{
	aws_lws_async_dns_t *dns = &context->async_dns;
	char ads[48];
	int n;

	if (dns->wsi)
		return 0;

	if (!context->vhost_list) { /* coverity... system vhost always present */
		aws_lwsl_cx_err(context, "no system vhost");
		return 1;
	}

	memset(&dns->sa46, 0, sizeof(dns->sa46));

#if defined(LWS_WITH_SYS_DHCP_CLIENT)
	if (aws_lws_dhcpc_status(context, &dns->sa46))
		goto ok;
#endif

	n = aws_lws_plat_asyncdns_init(context, &dns->sa46);
	if (n < 0) {
		aws_lwsl_cx_warn(context, "no valid dns server, retry");

		return 1;
	}

	if (n != LADNS_CONF_SERVER_CHANGED)
		return 0;

#if defined(LWS_WITH_SYS_DHCP_CLIENT)
ok:
#endif
	dns->sa46.sa4.sin_port = htons(53);
	aws_lws_write_numeric_address((uint8_t *)&dns->sa46.sa4.sin_addr.s_addr, 4,
				  ads, sizeof(ads));

	dns->wsi = aws_lws_create_adopt_udp(context->vhost_list, ads, 53, 0,
					aws_lws_async_dns_protocol.name, NULL,
				        NULL, NULL, &retry_policy, "asyncdns");
	if (!dns->wsi) {
		aws_lwsl_cx_err(context, "foreign socket adoption failed");
		return 1;
	}

	context->async_dns.wsi->udp->sa46 = dns->sa46;

	dns->dns_server_set = 1;

	return 0;
}

aws_lws_adns_cache_t *
aws_lws_adns_get_cache(aws_lws_async_dns_t *dns, const char *name)
{
	aws_lws_adns_cache_t *c;

	if (!name) {
		assert(0);
		return NULL;
	}

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1,
				   aws_lws_dll2_get_head(&dns->cached)) {
		c = aws_lws_container_of(d, aws_lws_adns_cache_t, list);

		// aws_lwsl_wsi_notice(dns->wsi, "%s vs %s (inc %d)", name, c->name, c->incomplete);

		if (!c->incomplete && !strcasecmp(name, c->name)) {
			/* Keep sorted by LRU: move to the head */
			aws_lws_dll2_remove(&c->list);
			aws_lws_dll2_add_head(&c->list, &dns->cached);

			return c;
		}
	} aws_lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

#if defined(_DEBUG)
void
aws_lws_adns_dump(aws_lws_async_dns_t *dns)
{
	aws_lws_adns_cache_t *c;

	if (!dns)
		return;

	aws_lwsl_wsi_info(dns->wsi, "ADNS cache %u entries",
			(unsigned int)dns->cached.count);

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d,
			      aws_lws_dll2_get_head(&dns->cached)) {
		c = aws_lws_container_of(d, aws_lws_adns_cache_t, list);

		aws_lwsl_wsi_info(dns->wsi, "cache: '%s', exp: %lldus, incomp %d, "
			  "fl 0x%x, refc %d, res %p\n", c->name,
			  (long long)(c->sul.us - aws_lws_now_usecs()),
			  c->incomplete, c->flags, c->refcount, c->results);
	} aws_lws_end_foreach_dll(d);

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d,
				   aws_lws_dll2_get_head(&dns->waiting)) {
		aws_lws_adns_q_t *q = aws_lws_container_of(d, aws_lws_adns_q_t, list);

		aws_lwsl_wsi_info(dns->wsi, "q: '%s', sent %d, resp %d",
			    (const char *)&q[1], q->sent[0],
			    q->responded);
	} aws_lws_end_foreach_dll(d);
}
#endif

void
aws_lws_adns_cache_destroy(aws_lws_adns_cache_t *c)
{
	aws_lws_dll2_remove(&c->sul.list);
	aws_lws_dll2_remove(&c->list);
	if (c->chain)
		aws_lws_free(c->chain);
	aws_lws_free(c);
}

static int
cache_clean(struct aws_lws_dll2 *d, void *user)
{
	aws_lws_adns_cache_destroy(aws_lws_container_of(d, aws_lws_adns_cache_t, list));

	return 0;
}

void
sul_cb_expire(struct aws_lws_sorted_usec_list *sul)
{
	aws_lws_adns_cache_t *c = aws_lws_container_of(sul, aws_lws_adns_cache_t, sul);

	aws_lws_adns_cache_destroy(c);
}

void
sul_cb_write(struct aws_lws_sorted_usec_list *sul)
{
	aws_lws_adns_q_t *q = aws_lws_container_of(sul, aws_lws_adns_q_t, write_sul);

	/*
	 * Something's up, we couldn't even get from write request to
	 * WRITEABLE within the timeout, let alone the result... fail
	 * the query and everyone riding on it...
	 */

	aws_lwsl_wsi_info(q->dns ? q->dns->wsi : NULL, "failing");
	aws_lws_adns_dump(q->dns);

	aws_lws_async_dns_complete(q, NULL); /* no cache to relate to */
	aws_lws_adns_q_destroy(q);
}

void
aws_lws_async_dns_freeaddrinfo(const struct addrinfo **pai)
{
	aws_lws_adns_cache_t *c;

	if (!*pai)
		return;

	/*
	 * First query may have been empty... if second has something, we
	 * fixed up the first result to point to second... but it means
	 * looking backwards from ai, which is c->result, which is the second
	 * packet's results, doesn't get us to the firstcache pointer.
	 *
	 * Adjust c to the firstcache in this case.
	 */

	c = &((aws_lws_adns_cache_t *)(*pai))[-1];
	if (c->firstcache)
		c = c->firstcache;

	aws_lwsl_debug("%s: c %p, %s, refcount %d -> %d\n", __func__, c,
		   (c->results && c->results->ai_canonname) ?
				c->results->ai_canonname : "none",
						c->refcount, c->refcount - 1);

	assert(c->refcount > 0);
	c->refcount--;
	*pai = NULL;
}

void
aws_lws_async_dns_trim_cache(aws_lws_async_dns_t *dns)
{
	aws_lws_adns_cache_t *c1;

	if (dns->cached.count + 1< MAX_CACHE_ENTRIES)
		return;

	c1 = aws_lws_container_of(aws_lws_dll2_get_tail(&dns->cached),
						aws_lws_adns_cache_t, list);
	if (c1->refcount)
		aws_lwsl_wsi_info(dns->wsi, "acache %p: refcount %d on purge",
				c1, c1->refcount);
	else
		aws_lws_adns_cache_destroy(c1);
}


static int
clean(struct aws_lws_dll2 *d, void *user)
{
	aws_lws_adns_q_destroy(aws_lws_container_of(d, aws_lws_adns_q_t, list));

	return 0;
}

void
aws_lws_async_dns_deinit(aws_lws_async_dns_t *dns)
{
	aws_lws_dll2_foreach_safe(&dns->waiting, NULL, clean);
	aws_lws_dll2_foreach_safe(&dns->cached, NULL, cache_clean);

	if (dns->wsi && !dns->dns_server_connected) {
		aws_lwsl_wsi_notice(dns->wsi, "late free of incomplete dns wsi");
		__lws_lc_untag(dns->wsi->a.context, &dns->wsi->lc);
#if defined(LWS_WITH_SYS_METRICS)
		aws_lws_metrics_tags_destroy(&dns->wsi->cal_conn.mtags_owner);
#endif
		aws_lws_free_set_NULL(dns->wsi->udp);
		aws_lws_free_set_NULL(dns->wsi);
	}
}


static int
cancel(struct aws_lws_dll2 *d, void *user)
{
	aws_lws_adns_q_t *q = aws_lws_container_of(d, aws_lws_adns_q_t, list);

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d3, d4,
				   aws_lws_dll2_get_head(&q->wsi_adns)) {
		struct lws *w = aws_lws_container_of(d3, struct lws, adns);

		if (user == w) {
			aws_lws_dll2_remove(d3);
			if (!q->wsi_adns.count)
				aws_lws_adns_q_destroy(q);
			return 1;
		}
	} aws_lws_end_foreach_dll_safe(d3, d4);

	return 0;
}

void
aws_lws_async_dns_cancel(struct lws *wsi)
{
	aws_lws_async_dns_t *dns = &wsi->a.context->async_dns;

	aws_lws_dll2_foreach_safe(&dns->waiting, wsi, cancel);
}


static int
check_tid(struct aws_lws_dll2 *d, void *user)
{
	aws_lws_adns_q_t *q = aws_lws_container_of(d, aws_lws_adns_q_t, list);
	int n = 0, nmax = q->tids >= LWS_ARRAY_SIZE(q->tid) ?
			  LWS_ARRAY_SIZE(q->tid) : q->tids;
	uint16_t check = (uint16_t)(intptr_t)user;

	for (n = 0; n < nmax; n++)
		if (check == q->tid[n])
			return 1;

	return 0;
}

int
aws_lws_async_dns_get_new_tid(struct aws_lws_context *context, aws_lws_adns_q_t *q)
{
	aws_lws_async_dns_t *dns = &context->async_dns;
	int budget = 10;

	/*
	 * Make the TID unpredictable, but must be unique amongst ongoing ones
	 */
	do {
		uint16_t tid;

		if (aws_lws_get_random(context, &tid, 2) != 2)
			return -1;

		if (aws_lws_dll2_foreach_safe(&dns->waiting,
					  (void *)(intptr_t)tid, check_tid))
			continue;

		q->tids++;
		LADNS_MOST_RECENT_TID(q) = tid;

		return 0;

	} while (budget--);

	aws_lwsl_cx_err(context, "unable to get unique tid");

	return -1;
}

struct temp_q {
	aws_lws_adns_q_t tq;
	char name[48];
};

aws_lws_async_dns_retcode_t
aws_lws_async_dns_query(struct aws_lws_context *context, int tsi, const char *name,
		    adns_query_type_t qtype, aws_lws_async_dns_cb_t cb,
		    struct lws *wsi, void *opaque)
{
	aws_lws_async_dns_t *dns = &context->async_dns;
	size_t nlen = strlen(name);
	aws_lws_sockaddr46 *sa46;
	aws_lws_adns_cache_t *c;
	struct addrinfo *ai;
	struct temp_q tmq;
	aws_lws_adns_q_t *q;
	uint8_t ads[16];
	char *p;
	int m;

	aws_lwsl_cx_info(context, "entry %s", name);
	aws_lws_adns_dump(dns);

#if !defined(LWS_WITH_IPV6)
	if (qtype == LWS_ADNS_RECORD_AAAA) {
		aws_lwsl_cx_err(context, "ipv6 not enabled");
		goto failed;
	}
#endif

	if (nlen >= DNS_MAX - 1)
		goto failed;

	/*
	 * we magically know 'localhost' and 'localhost6' if IPv6, this is a
	 * sort of canned /etc/hosts
	 */

	if (!strcmp(name, "localhost"))
		name = "127.0.0.1";

#if defined(LWS_WITH_IPV6)
	if (!strcmp(name, "localhost6"))
		name = "::1";
#endif

	if (wsi) {
		if (!aws_lws_dll2_is_detached(&wsi->adns)) {
			aws_lwsl_cx_err(context, "%s already bound to query %p",
					aws_lws_wsi_tag(wsi), wsi->adns.owner);
			goto failed;
		}
		wsi->adns_cb = cb;
	}

	/* there's a done, cached query we can just reuse? */

	c = aws_lws_adns_get_cache(dns, name);
	if (c) {
		aws_lwsl_cx_info(context, "%s: using cached, c->results %p",
			  name, c->results);
		m = c->results ? LADNS_RET_FOUND : LADNS_RET_FAILED;
		if (c->results)
			c->refcount++;

#if defined(LWS_WITH_SYS_METRICS)
		aws_lws_metric_event(context->mt_adns_cache,  METRES_GO, 0);
#endif

		if (cb(wsi, name, c->results, m, opaque) == NULL)
			return LADNS_RET_FAILED_WSI_CLOSED;

		return m;
	} else
		aws_lwsl_cx_info(context, "%s uncached", name);

#if defined(LWS_WITH_SYS_METRICS)
	aws_lws_metric_event(context->mt_adns_cache, METRES_NOGO, 0);
#endif

	/*
	 * It's a 1.2.3.4 or ::1 type IP address already?  We don't need a dns
	 * server set up to be able to create an addrinfo result for that.
	 *
	 * Create it as a cached object so it follows the refcount lifecycle
	 * of any other result
	 */

	m = aws_lws_parse_numeric_address(name, ads, sizeof(ads));
	if (m == 4
#if defined(LWS_WITH_IPV6)
		|| m == 16
#endif
	) {
		aws_lws_async_dns_trim_cache(dns);

		c = aws_lws_zalloc(sizeof(aws_lws_adns_cache_t) +
			       sizeof(struct addrinfo) +
			       sizeof(aws_lws_sockaddr46) + nlen + 1, "adns-numip");
		if (!c)
			goto failed;

		ai = (struct addrinfo *)&c[1];
		sa46 = (aws_lws_sockaddr46 *)&ai[1];

		ai->ai_socktype = SOCK_STREAM;
		c->name = (const char *)&sa46[1];
		memcpy((char *)c->name, name, nlen + 1);
		ai->ai_canonname = (char *)&sa46[1];

		c->results = ai;
		memset(&tmq.tq, 0, sizeof(tmq.tq));
		tmq.tq.opaque = opaque;
		if (wsi) {
			wsi->adns_cb = cb;
			aws_lws_dll2_add_head(&wsi->adns, &tmq.tq.wsi_adns);
		} else
			tmq.tq.standalone_cb = cb;
		aws_lws_strncpy(tmq.name, name, sizeof(tmq.name));

		aws_lws_dll2_add_head(&c->list, &dns->cached);
		aws_lws_sul_schedule(context, 0, &c->sul, sul_cb_expire,
				 3600ll * LWS_US_PER_SEC);

		aws_lws_adns_dump(dns);
	}

	if (m == 4) {
		ai = (struct addrinfo *)&c[1];
		sa46 = (aws_lws_sockaddr46 *)&ai[1];
		ai->ai_family = sa46->sa4.sin_family = AF_INET;
		ai->ai_addrlen = sizeof(sa46->sa4);
		ai->ai_addr = (struct sockaddr *)&sa46->sa4;
		memcpy(&sa46->sa4.sin_addr, ads, (unsigned int)m);

		aws_lws_async_dns_complete(&tmq.tq, c);

		return LADNS_RET_FOUND;
	}

#if defined(LWS_WITH_IPV6)
	if (m == 16) {
		ai->ai_family = sa46->sa6.sin6_family = AF_INET6;
		ai->ai_addrlen = sizeof(sa46->sa6);
		ai->ai_addr = (struct sockaddr *)&sa46->sa6;
		memcpy(&sa46->sa6.sin6_addr, ads, (unsigned int)m);

		aws_lws_async_dns_complete(&tmq.tq, c);

		return LADNS_RET_FOUND;
	}
#endif

	/*
	 * to try anything else we need a remote server configured...
	 */

	if (!context->async_dns.dns_server_set &&
	    aws_lws_async_dns_init(context)) {
		aws_lwsl_cx_notice(context, "init failed");
		goto failed;
	}

	/* there's an ongoing query we can share the result of */

	q = aws_lws_adns_get_query(dns, qtype, &dns->waiting, 0, name);
	if (q) {
		aws_lwsl_cx_debug(context, "dns piggybacking: %d:%s",
				qtype, name);
		if (wsi)
			aws_lws_dll2_add_head(&wsi->adns, &q->wsi_adns);

		return LADNS_RET_CONTINUING;
	}

	/*
	 * Allocate new query / queries... this is a bit complicated because
	 * multiple queries in one packet are not supported peoperly in DNS
	 * itself, and there's no reliable other way to get both ipv6 and ipv4
	 * (AAAA and A) responses in one hit.
	 *
	 * If we don't support ipv6, it's simple, we just ask for A and that's
	 * it.  But if we do support ipv6, we need to ask twice, once for A
	 * and in a separate query, again for AAAA.
	 *
	 * For ipv6, A / ipv4 is routable over ipv6.  So we always ask for A
	 * first and then if ipv6, AAAA separately.
	 *
	 * Allocate for DNS_MAX, because we may recurse and alter what we're
	 * looking for.
	 *
	 * 0             sizeof(*q)                  sizeof(*q) + DNS_MAX
	 * [aws_lws_adns_q_t][ name (DNS_MAX reserved) ] [ name \0 ]
	 */

	q = (aws_lws_adns_q_t *)aws_lws_malloc(sizeof(*q) + DNS_MAX + nlen + 1,
					__func__);
	if (!q)
		goto failed;
	memset(q, 0, sizeof(*q));

	if (wsi)
		aws_lws_dll2_add_head(&wsi->adns, &q->wsi_adns);

	q->qtype = (uint16_t)qtype;

	if (aws_lws_async_dns_get_new_tid(context, q)) {
		aws_lwsl_cx_err(context, "tid fail");
		goto failed;
	}

	LADNS_MOST_RECENT_TID(q) &= 0xfffe;
	q->context = context;
	q->tsi = (uint8_t)tsi;
	q->opaque = opaque;
	q->dns = dns;

	if (!wsi)
		q->standalone_cb = cb;

	/* schedule a retry according to the retry policy on the wsi */
	if (aws_lws_retry_sul_schedule_retry_wsi(dns->wsi, &q->sul,
					 aws_lws_async_dns_sul_cb_retry, &q->retry))
		goto failed;

	/* fail us if we can't write by this timeout */
	aws_lws_sul_schedule(context, 0, &q->write_sul, sul_cb_write, LWS_US_PER_SEC);

	/*
	 * We may rewrite the copy at +sizeof(*q) for CNAME recursion.  Keep
	 * a second copy at + sizeof(*q) + DNS_MAX so we can create the cache
	 * entry for the original name, not the last CNAME we met.
	 */

	p = (char *)&q[1];
	while (nlen--) {
		*p++ = (char)tolower(*name++);
		p[DNS_MAX - 1] = p[-1];
	}
	*p = '\0';
	p[DNS_MAX] = '\0';

	aws_lws_callback_on_writable(dns->wsi);

	aws_lws_dll2_add_head(&q->list, &dns->waiting);

	aws_lws_metrics_caliper_bind(q->metcal, context->mt_conn_dns);
	q->go_nogo = METRES_NOGO;
	/* caliper is reported in aws_lws_adns_q_destroy */

	aws_lwsl_cx_info(context, "created new query: %s", name);
	aws_lws_adns_dump(dns);

	return LADNS_RET_CONTINUING;

failed:
	aws_lwsl_cx_notice(context, "failed");
	if (!cb(wsi, NULL, NULL, LADNS_RET_FAILED, opaque))
		return LADNS_RET_FAILED_WSI_CLOSED;

	return LADNS_RET_FAILED;
}

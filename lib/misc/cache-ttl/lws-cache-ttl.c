/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

#include <private-lib-core.h>
#include "private-lib-misc-cache-ttl.h"

#include <assert.h>

#if defined(write)
#undef write
#endif

void
aws_lws_cache_clear_matches(aws_lws_dll2_owner_t *results_owner)
{
	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, d, d1, results_owner->head) {
		aws_lws_cache_match_t *item = aws_lws_container_of(d, aws_lws_cache_match_t,
							   list);
		aws_lws_dll2_remove(d);
		aws_lws_free(item);
	} aws_lws_end_foreach_dll_safe(d, d1);
}

void
aws_lws_cache_schedule(struct aws_lws_cache_ttl_lru *cache, sul_cb_t cb, aws_lws_usec_t e)
{
	aws_lwsl_cache("%s: %s schedule %llu\n", __func__, cache->info.name,
			(unsigned long long)e);

	aws_lws_sul_schedule(cache->info.cx, cache->info.tsi, &cache->sul, cb,
			 e - aws_lws_now_usecs());
}

int
aws_lws_cache_write_through(struct aws_lws_cache_ttl_lru *cache,
			const char *specific_key, const uint8_t *source,
			size_t size, aws_lws_usec_t expiry, void **ppay)
{
	struct aws_lws_cache_ttl_lru *levels[LWS_CACHE_MAX_LEVELS], *c = cache;
	int n = 0, r = 0;

	aws_lws_cache_item_remove(cache, specific_key);

	/* starting from L1 */

	do {
		levels[n++] = c;
		c = c->info.parent;
	} while (c && n < (int)LWS_ARRAY_SIZE(levels));

	/* starting from outermost cache level */

	while (n) {
		n--;
		r = levels[n]->info.ops->write(levels[n], specific_key,
						source, size, expiry, ppay);
	}

	return r;
}

/*
 * We want to make a list of unique keys that exist at any cache level
 * matching a wildcard search key.
 *
 * If L1 has a cached version though, we will just use that.
 */

int
aws_lws_cache_lookup(struct aws_lws_cache_ttl_lru *cache, const char *wildcard_key,
		 const void **pdata, size_t *psize)
{
	struct aws_lws_cache_ttl_lru *l1 = cache;
	aws_lws_dll2_owner_t results_owner;
	aws_lws_usec_t expiry = 0;
	char meta_key[128];
	uint8_t *p, *temp;
	size_t sum = 0;
	int n;

	memset(&results_owner, 0, sizeof(results_owner));
	meta_key[0] = META_ITEM_LEADING;
	aws_lws_strncpy(&meta_key[1], wildcard_key, sizeof(meta_key) - 2);

	/*
	 * If we have a cached result set in L1 already, return that
	 */

	if (!l1->info.ops->get(l1, meta_key, pdata, psize))
		return 0;

	/*
	 * No, we have to do the actual lookup work in the backing store layer
	 * to get results for this...
	 */

	while (cache->info.parent)
		cache = cache->info.parent;

	if (cache->info.ops->lookup(cache, wildcard_key, &results_owner)) {
		/* eg, OOM */

		aws_lwsl_cache("%s: bs lookup fail\n", __func__);

		aws_lws_cache_clear_matches(&results_owner);
		return 1;
	}

	/*
	 * Scan the results, we want to know how big a payload it needs in
	 * the cache, and we want to know the earliest expiry of any of the
	 * component parts, so the meta cache entry for these results can be
	 * expired when any of the results would expire.
	 */

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d, results_owner.head) {
		aws_lws_cache_match_t *m = aws_lws_container_of(d, aws_lws_cache_match_t,
							list);
		sum += 8; /* payload size, name length */
		sum += m->tag_size + 1;

		if (m->expiry && (!expiry || expiry < m->expiry))
			expiry = m->expiry;

	} aws_lws_end_foreach_dll(d);

	aws_lwsl_cache("%s: results %d, size %d\n", __func__,
		    (int)results_owner.count, (int)sum);

	temp = aws_lws_malloc(sum, __func__);
	if (!temp) {
		aws_lws_cache_clear_matches(&results_owner);
		return 1;
	}

	/*
	 * Fill temp with the serialized results
	 */

	p = temp;
	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, d, results_owner.head) {
		aws_lws_cache_match_t *m = aws_lws_container_of(d, aws_lws_cache_match_t,
							list);

		/* we don't copy the payload in, but take note of its size */
		aws_lws_ser_wu32be(p, (uint32_t)m->payload_size);
		p += 4;
		/* length of the tag name (there is an uncounted NUL after) */
		aws_lws_ser_wu32be(p, (uint32_t)m->tag_size);
		p += 4;

		/* then the tag name, plus the extra NUL */
		memcpy(p, &m[1], m->tag_size + 1);
		p += m->tag_size + 1;

	} aws_lws_end_foreach_dll(d);

	aws_lws_cache_clear_matches(&results_owner);

	/*
	 * Create the right amount of space for an L1 record of these results,
	 * with its expiry set to the earliest of the results, and copy it in
	 * from temp
	 */

	n = l1->info.ops->write(l1, meta_key, temp, sum, expiry, (void **)&p);
	/* done with temp */
	aws_lws_free(temp);

	if (n)
		return 1;

	/* point to the results in L1 */

	*pdata = p;
	*psize = sum;

	return 0;
}

int
aws_lws_cache_item_get(struct aws_lws_cache_ttl_lru *cache, const char *specific_key,
		   const void **pdata, size_t *psize)
{
	while (cache) {
		if (!cache->info.ops->get(cache, specific_key, pdata, psize)) {
			aws_lwsl_cache("%s: hit\n", __func__);
			return 0;
		}

		cache = cache->info.parent;
	}

	return 1;
}

int
aws_lws_cache_expunge(struct aws_lws_cache_ttl_lru *cache)
{
	int ret = 0;

	while (cache) {
		ret |= cache->info.ops->expunge(cache);

		cache = cache->info.parent;
	}

	return ret;
}

int
aws_lws_cache_item_remove(struct aws_lws_cache_ttl_lru *cache, const char *wildcard_key)
{
	while (cache) {
		if (cache->info.ops->invalidate(cache, wildcard_key))
			return 1;

		cache = cache->info.parent;
	}

	return 0;
}

uint64_t
aws_lws_cache_footprint(struct aws_lws_cache_ttl_lru *cache)
{
	return cache->current_footprint;
}

void
aws_lws_cache_debug_dump(struct aws_lws_cache_ttl_lru *cache)
{
#if defined(_DEBUG)
	if (cache->info.ops->debug_dump)
		cache->info.ops->debug_dump(cache);
#endif
}

int
aws_lws_cache_results_walk(aws_lws_cache_results_t *walk_ctx)
{
	if (!walk_ctx->size)
		return 1;

	walk_ctx->payload_len = aws_lws_ser_ru32be(walk_ctx->ptr);
	walk_ctx->tag_len = aws_lws_ser_ru32be(walk_ctx->ptr + 4);
	walk_ctx->tag = walk_ctx->ptr + 8;

	walk_ctx->ptr += walk_ctx->tag_len + 1 + 8;
	walk_ctx->size -= walk_ctx->tag_len + 1 + 8;

	return 0;
}

struct aws_lws_cache_ttl_lru *
aws_lws_cache_create(const struct aws_lws_cache_creation_info *info)
{
	assert(info);
	assert(info->ops);
	assert(info->name);
	assert(info->ops->create);

	return info->ops->create(info);
}

void
aws_lws_cache_destroy(struct aws_lws_cache_ttl_lru **_cache)
{
	aws_lws_cache_ttl_lru_t *cache = *_cache;

	if (!cache)
		return;

	assert(cache->info.ops->destroy);

	aws_lws_sul_cancel(&cache->sul);

	cache->info.ops->destroy(_cache);
}

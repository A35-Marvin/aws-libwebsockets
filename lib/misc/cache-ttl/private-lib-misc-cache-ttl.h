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

#define aws_lwsl_cache aws_lwsl_debug
#define aws_lwsl_hexdump_cache aws_lwsl_hexdump_debug

#define LWS_CACHE_MAX_LEVELS 3

/*
 * If we need structure inside the cache tag names, use this character as a
 * separator
 */
#define LWSCTAG_SEP '|'

/*
 * Our synthetic cache result items all have tags starting with this char
 */
#define META_ITEM_LEADING '!'

typedef struct aws_lws_cache_ttl_item_heap {
	aws_lws_dll2_t			list_expiry;
	aws_lws_dll2_t			list_lru;

	aws_lws_usec_t			expiry;
	size_t				key_len;
	size_t				size;

	/*
	 * len + key_len + 1 bytes of data overcommitted, user object first
	 * so it is well-aligned, then the NUL-terminated key name
	 */
} aws_lws_cache_ttl_item_heap_t;

/* this is a "base class", all cache implementations have one at the start */

typedef struct aws_lws_cache_ttl_lru {
	struct aws_lws_cache_creation_info	info;
	aws_lws_sorted_usec_list_t		sul;
	struct aws_lws_cache_ttl_lru	*child;
	uint64_t			current_footprint;
} aws_lws_cache_ttl_lru_t;

/*
 * The heap-backed cache uses aws_lws_dll2 linked-lists to track items that are
 * in it.
 */

typedef struct aws_lws_cache_ttl_lru_heap {
	aws_lws_cache_ttl_lru_t		cache;

	aws_lws_dll2_owner_t		items_expiry;
	aws_lws_dll2_owner_t		items_lru;
} aws_lws_cache_ttl_lru_t_heap_t;

/*
 * We want to be able to work with a large file-backed implementation even on
 * devices that don't have heap to track what is in it.  It means if lookups
 * reach this cache layer, we will be scanning a potentially large file.
 *
 * L1 caching of lookups (including null result list) reduces the expense of
 * this on average.  We keep a copy of the last computed earliest expiry.
 *
 * We can't keep an open file handle here.  Because other processes may change
 * the cookie file by deleting and replacing it, we have to open it fresh each
 * time.
 */
typedef struct aws_lws_cache_nscookiejar {
	aws_lws_cache_ttl_lru_t		cache;

	aws_lws_usec_t			earliest_expiry;
} aws_lws_cache_nscookiejar_t;

void
aws_lws_cache_clear_matches(aws_lws_dll2_owner_t *results_owner);

void
aws_lws_cache_schedule(struct aws_lws_cache_ttl_lru *cache, sul_cb_t cb, aws_lws_usec_t e);

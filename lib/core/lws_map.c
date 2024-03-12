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

#include "private-lib-core.h"

typedef struct aws_lws_map_hashtable {
	struct aws_lws_map			*map_owner; /* so items can find map */
	aws_lws_dll2_owner_t		ho;
} aws_lws_map_hashtable_t;

typedef struct aws_lws_map {
	aws_lws_map_info_t			info;

	/* array of info.modulo x aws_lws_map_hashtable_t overallocated */
} aws_lws_map_t;

typedef struct aws_lws_map_item {
	aws_lws_dll2_t			list; /* owned by hashtable */

	size_t				keylen;
	size_t				valuelen;

	/* key then value is overallocated */
} aws_lws_map_item_t;

/*
 * aws_lwsac-aware allocator
 */

void *
aws_lws_map_alloc_lwsac(struct aws_lws_map *map, size_t x)
{
	return aws_lwsac_use((struct aws_lwsac **)map->info.opaque, x,
					(size_t)map->info.aux);
}

void
aws_lws_map_free_lwsac(void *v)
{
}

/*
 * Default allocation / free if none given in info
 */

void *
aws_lws_map_alloc_lws_malloc(struct aws_lws_map *mo, size_t x)
{
	return aws_lws_malloc(x, __func__);
}

void
aws_lws_map_free_lws_free(void *v)
{
	aws_lws_free(v);
}

/*
 * This just needs to approximate a flat distribution, it's not related to
 * security at all.
 */

aws_lws_map_hash_t
aws_lws_map_hash_from_key_default(const aws_lws_map_key_t key, size_t kl)
{
	aws_lws_map_hash_t h = 0x12345678;
	const uint8_t *u = (const uint8_t *)key;

	while (kl--)
		h = ((((h << 7) | (h >> 25)) + 0xa1b2c3d4) ^ (*u++)) ^ h;

	return h;
}

int
aws_lws_map_compare_key_default(const aws_lws_map_key_t key1, size_t kl1,
			    const aws_lws_map_value_t key2, size_t kl2)
{
	if (kl1 != kl2)
		return 1;

	return memcmp(key1, key2, kl1);
}

aws_lws_map_t *
aws_lws_map_create(const aws_lws_map_info_t *info)
{
	aws_lws_map_t *map;
	aws_lws_map_alloc_t a = info->_alloc;
	size_t modulo = info->modulo;
	aws_lws_map_hashtable_t *ht;
	size_t size;

	if (!a)
		a = aws_lws_map_alloc_lws_malloc;

	if (!modulo)
		modulo = 8;

	size = sizeof(*map) + (modulo * sizeof(aws_lws_map_hashtable_t));
	map = aws_lws_malloc(size, __func__);
	if (!map)
		return NULL;

	memset(map, 0, size);

	map->info = *info;

	map->info._alloc = a;
	map->info.modulo = modulo;
	if (!info->_free)
		map->info._free = aws_lws_map_free_lws_free;
	if (!info->_hash)
		map->info._hash = aws_lws_map_hash_from_key_default;
	if (!info->_compare)
		map->info._compare = aws_lws_map_compare_key_default;

	ht = (aws_lws_map_hashtable_t *)&map[1];
	while (modulo--)
		ht[modulo].map_owner = map;

	return map;
}

static int
ho_free_item(struct aws_lws_dll2 *d, void *user)
{
	aws_lws_map_item_t *i = aws_lws_container_of(d, aws_lws_map_item_t, list);

	aws_lws_map_item_destroy(i);

	return 0;
}

void
aws_lws_map_destroy(aws_lws_map_t **pmap)
{
	aws_lws_map_hashtable_t *ht;
	aws_lws_map_t *map = *pmap;

	if (!map)
		return;

	/* empty out all the hashtables */

	ht = (aws_lws_map_hashtable_t *)&(map[1]);
	while (map->info.modulo--) {
		aws_lws_dll2_foreach_safe(&ht->ho, ht, ho_free_item);
		ht++;
	}

	/* free the map itself */

	aws_lws_free_set_NULL(*pmap);
}

aws_lws_map_item_t *
aws_lws_map_item_create(aws_lws_map_t *map,
		    const aws_lws_map_key_t key, size_t keylen,
		    const aws_lws_map_value_t value, size_t valuelen)
{
	aws_lws_map_hashtable_t *ht;
	aws_lws_map_item_t *item;
	aws_lws_map_hash_t h;
	size_t hti;
	uint8_t *u;

	item = aws_lws_map_item_lookup(map, key, keylen);
	if (item)
		aws_lws_map_item_destroy(item);

	item = map->info._alloc(map, sizeof(*item) + keylen + valuelen);
	if (!item)
		return NULL;

	aws_lws_dll2_clear(&item->list);
	item->keylen = keylen;
	item->valuelen = valuelen;

	u = (uint8_t *)&item[1];
	memcpy(u, key, keylen);
	u += keylen;
	if (value)
		memcpy(u, value, valuelen);

	h = map->info._hash(key, keylen);

	hti = h % map->info.modulo;
	ht = (aws_lws_map_hashtable_t *)&map[1];

	aws_lws_dll2_add_head(&item->list, &ht[hti].ho);

	return item;
}

void
aws_lws_map_item_destroy(aws_lws_map_item_t *item)
{
	aws_lws_map_hashtable_t *ht = aws_lws_container_of(item->list.owner,
						   aws_lws_map_hashtable_t, ho);

	aws_lws_dll2_remove(&item->list);
	ht->map_owner->info._free(item);
}

aws_lws_map_item_t *
aws_lws_map_item_lookup(aws_lws_map_t *map, const aws_lws_map_key_t key, size_t keylen)
{
	aws_lws_map_hash_t h = map->info._hash(key, keylen);
	aws_lws_map_hashtable_t *ht = (aws_lws_map_hashtable_t *)&map[1];

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p,
			      ht[h % map->info.modulo].ho.head) {
		aws_lws_map_item_t *i = aws_lws_container_of(p, aws_lws_map_item_t, list);

		if (!map->info._compare(key, keylen, &i[1], i->keylen))
			return i;
	} aws_lws_end_foreach_dll(p);

	return NULL;
}

const void *
aws_lws_map_item_key(aws_lws_map_item_t *_item)
{
	return ((void *)&_item[1]);
}

const void *
aws_lws_map_item_value(aws_lws_map_item_t *_item)
{
	return (void *)(((uint8_t *)&_item[1]) + _item->keylen);
}

size_t
aws_lws_map_item_key_len(aws_lws_map_item_t *_item)
{
	return _item->keylen;
}

size_t
aws_lws_map_item_value_len(aws_lws_map_item_t *_item)
{
	return _item->valuelen;
}

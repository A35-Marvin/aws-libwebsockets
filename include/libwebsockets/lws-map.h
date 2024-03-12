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

/** \defgroup aws_lws_map generic map apis
 * ##Generic map structures and apis
 * \ingroup aws_lwsapi
 *
 * aws_lws_map
 *
 * Discrete owner object represents the whole map, created with key-specific
 * ops for hashing the key to a uint32_t and comparing two keys.  Owns a list
 * of hash tables whose size / modulo it set at creation time.
 *
 * Items in the map are contained in a aws_lws_map_item_t that is indexed in a
 * hash table.
 *
 * It's difficult to make a single compact map abstraction that fits all cases,
 * this is useful to the extent you have the memory to trade off the number of
 * hashtables needed for the amount of items and the lookup latency limit for
 * your application, typically for hundreds or low thousands of items.
 */
//@{

typedef struct aws_lws_map aws_lws_map_t;
typedef struct aws_lws_map_item aws_lws_map_item_t;

typedef void * aws_lws_map_key_t;
typedef void * aws_lws_map_value_t;
typedef uint32_t aws_lws_map_hash_t;

typedef aws_lws_map_hash_t (*aws_lws_map_hash_from_key_t)(const aws_lws_map_key_t key,
						  size_t kl);
typedef int (*aws_lws_map_compare_key_t)(const aws_lws_map_key_t key1, size_t kl1,
				     const aws_lws_map_value_t key2, size_t kl2);
typedef void * (*aws_lws_map_alloc_t)(struct aws_lws_map *mo, size_t x);
typedef void (*aws_lws_map_free_t)(void *);

/*
 * Creation parameters for the map, copied into the map owner
 */

typedef struct aws_lws_map_info {
	aws_lws_map_hash_from_key_t		_hash;
	aws_lws_map_compare_key_t		_compare;
	aws_lws_map_alloc_t			_alloc;	/* NULL = aws_lws_malloc */
	aws_lws_map_free_t			_free;	/* NULL = aws_lws_free */

	void				*opaque;
	/**< &aws_lwsac if using aws_lwsac allocator */
	void				*aux;
	/**< chunk size if using aws_lwsac allocator */
	/**< this can be used by the alloc handler, eg for aws_lws_ac */
	size_t				modulo;
	/**< number of hashed owner lists to create */
} aws_lws_map_info_t;

LWS_VISIBLE LWS_EXTERN const void *
aws_lws_map_item_key(aws_lws_map_item_t *_item);
LWS_VISIBLE LWS_EXTERN const void *
aws_lws_map_item_value(aws_lws_map_item_t *_item);
LWS_VISIBLE LWS_EXTERN size_t
aws_lws_map_item_key_len(aws_lws_map_item_t *_item);
LWS_VISIBLE LWS_EXTERN size_t
aws_lws_map_item_value_len(aws_lws_map_item_t *_item);

/*
 * Helpers for C string keys case
 */

#define aws_lws_map_item_create_ks(_map, _str, _v, _vl) \
		aws_lws_map_item_create(_map, (const aws_lws_map_key_t)_str, \
				    strlen(_str), (const aws_lws_map_value_t)_v, \
						    _vl)
#define aws_lws_map_item_lookup_ks(_map, _str) \
		aws_lws_map_item_lookup(_map, (const aws_lws_map_key_t)_str, strlen(_str))

/**
 * aws_lws_map_create() - create a map object and hashtables on heap
 *
 * \param info: description of map to create
 *
 * Creates a map object on heap, using aws_lws_malloc().
 *
 * \p info may be all zeros inside, if so, modulo defaults to 8, and the
 * operation callbacks default to using aws_lws_malloc() / _free() for item alloc,
 * a default xor / shift based hash and simple linear memory key compare.
 *
 * For less typical use-cases, the provided \p info members can be tuned to
 * control how the allocation of mapped items is done, lws provides two exports
 * aws_lws_map_alloc_lwsac() and aws_lws_map_free_lwsac() that can be used for _alloc
 * and _free to have items allocated inside an aws_lwsac.
 *
 * The map itself is created on the heap directly, the info._alloc() op is only
 * used when creating items.
 *
 * keys have individual memory sizes and do not need to all be the same length.
 */
LWS_VISIBLE LWS_EXTERN aws_lws_map_t *
aws_lws_map_create(const aws_lws_map_info_t *info);

/*
 * helpers that can be used for info._alloc and info._free if using aws_lwsac
 * allocation for items, set info.opaque to point to the aws_lwsac pointer, and
 * aux to (void *)chunksize, or leave zero / NULL for the default
 */

LWS_VISIBLE LWS_EXTERN void *
aws_lws_map_alloc_lwsac(struct aws_lws_map *map, size_t x);

LWS_VISIBLE LWS_EXTERN void
aws_lws_map_free_lwsac(void *v);

/**
 * aws_lws_map_destroy() - deallocate all items and free map
 *
 * \param pmap: pointer to pointer map object to deallocate
 *
 * Frees all items in the map, using info._free(), and then frees the map
 * from heap directly.  \p *pmap is set to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
aws_lws_map_destroy(aws_lws_map_t **pmap);

/**
 * aws_lws_map_item_create() - allocate and map an item into an existing map
 *
 * \param map: the map to add items into
 * \param key: the key, may be any kind of object
 * \param keylen: the length of the key in bytes
 * \param value: the value, may be any kind of object
 * \param valuelen: the length of value
 *
 * Allocates space for the item, key and value using the map allocator, and
 * if non-NULL, copies the key and value into the item.
 *
 * If an item with the same key exists, it is removed and destroyed before
 * creating and adding the new one.
 */

LWS_VISIBLE LWS_EXTERN aws_lws_map_item_t *
aws_lws_map_item_create(aws_lws_map_t *map,
		    const aws_lws_map_key_t key, size_t keylen,
		    const aws_lws_map_value_t value, size_t valuelen);

/**
 * aws_lws_map_item_destroy() - remove item from map and free
 *
 * \param item: the item in the map to remove and free
 */
LWS_VISIBLE LWS_EXTERN void
aws_lws_map_item_destroy(aws_lws_map_item_t *item);

/**
 * aws_lws_map_item_lookup() - look for a item with the given key in the map
 *
 * \param map: the map
 * \param key: the key to look for
 * \param keylen: the length of the key to look for
 *
 * Searches for the key in the map, using the map's key hash and key compare
 * functions.
 */

LWS_VISIBLE LWS_EXTERN aws_lws_map_item_t *
aws_lws_map_item_lookup(aws_lws_map_t *map, const aws_lws_map_key_t key, size_t keylen);

//@}

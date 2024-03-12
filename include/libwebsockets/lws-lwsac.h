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

/** \defgroup aws_lwsac aws_lwsac
 *
 * ##Allocated Chunks
 *
 * If you know you will be allocating a large, unknown number of same or
 * differently sized objects, it's certainly possible to do it with libc
 * malloc.  However the allocation cost in time and memory overhead can
 * add up, and deallocation means walking the structure of every object and
 * freeing them in turn.
 *
 * aws_lwsac (LWS Allocated Chunks) allocates chunks intended to be larger
 * than your objects (4000 bytes by default) which you linearly allocate from
 * using aws_lwsac_use().
 *
 * If your next request won't fit in the current chunk, a new chunk is added
 * to the chain of chunks and the allocaton done from there.  If the request
 * is larger than the chunk size, an oversize chunk is created to satisfy it.
 *
 * When you are finished with the allocations, you call aws_lwsac_free() and
 * free all the *chunks*.  So you may have thousands of objects in the chunks,
 * but they are all destroyed with the chunks without having to deallocate them
 * one by one pointlessly.
 */
///@{

struct aws_lwsac;
typedef unsigned char * aws_lwsac_cached_file_t;


#define aws_lws_list_ptr_container(P,T,M) ((T *)((char *)(P) - offsetof(T, M)))

/*
 * linked-list helper that's commonly useful to manage lists of things
 * allocated using aws_lwsac.
 *
 * These lists point to their corresponding "next" member in the target, NOT
 * the original containing struct.  To get the containing struct, you must use
 * aws_lws_list_ptr_container() to convert.
 *
 * It's like that because it means we no longer have to have the next pointer
 * at the start of the struct, and we can have the same struct on multiple
 * linked-lists with everything held in the struct itself.
 */
typedef void * aws_lws_list_ptr;

/*
 * optional sorting callback called by aws_lws_list_ptr_insert() to sort the right
 * things inside the opqaue struct being sorted / inserted on the list.
 */
typedef int (*aws_lws_list_ptr_sort_func_t)(aws_lws_list_ptr a, aws_lws_list_ptr b);

#define aws_lws_list_ptr_advance(_lp) _lp = *((void **)_lp)

/* sort may be NULL if you don't care about order */
LWS_VISIBLE LWS_EXTERN void
aws_lws_list_ptr_insert(aws_lws_list_ptr *phead, aws_lws_list_ptr *add,
		    aws_lws_list_ptr_sort_func_t sort);


/**
 * aws_lwsac_use - allocate / use some memory from a aws_lwsac
 *
 * \param head: pointer to the aws_lwsac list object
 * \param ensure: the number of bytes we want to use
 * \param chunk_size: 0, or the size of the chunk to (over)allocate if
 *			what we want won't fit in the current tail chunk.  If
 *			0, the default value of 4000 is used. If ensure is
 *			larger, it is used instead.
 *
 * This also serves to init the aws_lwsac if *head is NULL.  Basically it does
 * whatever is necessary to return you a pointer to ensure bytes of memory
 * reserved for the caller.
 *
 * This always allocates in the current chunk or a new chunk... see the
 * aws_lwsac_use_backfill() variant to try first to find space in earlier chunks.
 *
 * Returns NULL if OOM.
 */
LWS_VISIBLE LWS_EXTERN void *
aws_lwsac_use(struct aws_lwsac **head, size_t ensure, size_t chunk_size);

/**
 * aws_lwsac_use_backfill - allocate / use some memory from a aws_lwsac
 *
 * \param head: pointer to the aws_lwsac list object
 * \param ensure: the number of bytes we want to use
 * \param chunk_size: 0, or the size of the chunk to (over)allocate if
 *			what we want won't fit in the current tail chunk.  If
 *			0, the default value of 4000 is used. If ensure is
 *			larger, it is used instead.
 *
 * This also serves to init the aws_lwsac if *head is NULL.  Basically it does
 * whatever is necessary to return you a pointer to ensure bytes of memory
 * reserved for the caller.
 *
 * Also checks if earlier blocks have enough remaining space to take the
 * allocation before making a new allocation.
 *
 * Returns NULL if OOM.
 */
LWS_VISIBLE LWS_EXTERN void *
aws_lwsac_use_backfill(struct aws_lwsac **head, size_t ensure, size_t chunk_size);

/**
 * aws_lwsac_use - allocate / use some memory from a aws_lwsac
 *
 * \param head: pointer to the aws_lwsac list object
 * \param ensure: the number of bytes we want to use, which must be zeroed
 * \param chunk_size: 0, or the size of the chunk to (over)allocate if
 *			what we want won't fit in the current tail chunk.  If
 *			0, the default value of 4000 is used. If ensure is
 *			larger, it is used instead.
 *
 * Same as aws_lwsac_use(), but \p ensure bytes of memory at the return address
 * are zero'd before returning.
 *
 * Returns NULL if OOM.
 */
LWS_VISIBLE LWS_EXTERN void *
aws_lwsac_use_zero(struct aws_lwsac **head, size_t ensure, size_t chunk_size);

#define aws_lwsac_use_zeroed aws_lwsac_use_zero

/**
 * aws_lwsac_free - deallocate all chunks in the aws_lwsac and set head NULL
 *
 * \param head: pointer to the aws_lwsac list object
 *
 * This deallocates all chunks in the aws_lwsac, then sets *head to NULL.  All
 * aws_lwsac_use() pointers are invalidated in one hit without individual frees.
 */
LWS_VISIBLE LWS_EXTERN void
aws_lwsac_free(struct aws_lwsac **head);

/*
 * Optional helpers useful for where consumers may need to defer destruction
 * until all consumers are finished with the aws_lwsac
 */

/**
 * aws_lwsac_detach() - destroy an aws_lwsac unless somebody else is referencing it
 *
 * \param head: pointer to the aws_lwsac list object
 *
 * The creator of the aws_lwsac can all this instead of aws_lwsac_free() when it itself
 * has finished with the aws_lwsac, but other code may be consuming it.
 *
 * If there are no other references, the aws_lwsac is destroyed, *head is set to
 * NULL and that's the end; however if something else has called
 * aws_lwsac_reference() on the aws_lwsac, it simply returns.  When aws_lws_unreference()
 * is called and no references are left, it will be destroyed then.
 */
LWS_VISIBLE LWS_EXTERN void
aws_lwsac_detach(struct aws_lwsac **head);

/**
 * aws_lwsac_reference() - increase the aws_lwsac reference count
 *
 * \param head: pointer to the aws_lwsac list object
 *
 * Increment the reference count on the aws_lwsac to defer destruction.
 */
LWS_VISIBLE LWS_EXTERN void
aws_lwsac_reference(struct aws_lwsac *head);

/**
 * aws_lwsac_unreference() - decrease the aws_lwsac reference count
 *
 * \param head: pointer to the aws_lwsac list object
 *
 * Decrement the reference count on the aws_lwsac... if it reached 0 on a detached
 * aws_lwsac then the aws_lwsac is immediately destroyed and *head set to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
aws_lwsac_unreference(struct aws_lwsac **head);

/**
 * aws_lwsac_extend() - try to increase the size of the last block
 *
 * \param head: pointer to the aws_lwsac list object
 * \param amount: amount to try to increase usage for
 *
 * This will either increase the usage reservation of the last allocated block
 * by amount and return 0, or fail and return 1.
 *
 * This is very cheap to call and is designed to optimize usage after a static
 * struct for vari-sized additional content which may flow into an additional
 * block in a new chunk if necessary, but wants to make the most of the space
 * in front of it first to try to avoid gaps and the new chunk if it can.
 *
 * The additional area if the call succeeds will have been memset to 0.
 *
 * To use it, the following must be true:
 *
 * - only the last aws_lwsac use can be extended
 *
 * - if another use happens inbetween the use and extend, it will break
 *
 * - the use cannot have been using backfill
 *
 * - a user object must be tracking the current allocated size of the last use
 *   (aws_lwsac doesn't know it) and increment by amount if the extend call succeeds
 *
 * Despite these restrictions this can be an important optimization for some
 * cases
 */
LWS_VISIBLE LWS_EXTERN int
aws_lwsac_extend(struct aws_lwsac *head, size_t amount);

/* helpers to keep a file cached in memory */

LWS_VISIBLE LWS_EXTERN void
aws_lwsac_use_cached_file_start(aws_lwsac_cached_file_t cache);

LWS_VISIBLE LWS_EXTERN void
aws_lwsac_use_cached_file_end(aws_lwsac_cached_file_t *cache);

LWS_VISIBLE LWS_EXTERN void
aws_lwsac_use_cached_file_detach(aws_lwsac_cached_file_t *cache);

LWS_VISIBLE LWS_EXTERN int
aws_lwsac_cached_file(const char *filepath, aws_lwsac_cached_file_t *cache,
		  size_t *len);

/* more advanced helpers */

/* offset from lac to start of payload, first = 1 = first lac in chain */
LWS_VISIBLE LWS_EXTERN size_t
aws_lwsac_sizeof(int first);

LWS_VISIBLE LWS_EXTERN size_t
aws_lwsac_get_tail_pos(struct aws_lwsac *lac);

LWS_VISIBLE LWS_EXTERN struct aws_lwsac *
aws_lwsac_get_next(struct aws_lwsac *lac);

LWS_VISIBLE LWS_EXTERN size_t
aws_lwsac_align(size_t length);

LWS_VISIBLE LWS_EXTERN void
aws_lwsac_info(struct aws_lwsac *head);

LWS_VISIBLE LWS_EXTERN uint64_t
aws_lwsac_total_alloc(struct aws_lwsac *head);

LWS_VISIBLE LWS_EXTERN uint64_t
aws_lwsac_total_overhead(struct aws_lwsac *head);

/**
 * aws_lwsac_scan_extant() - returns existing copy of blob, or NULL
 *
 * \param head: the aws_lwsac to scan
 * \param find: the blob to look for
 * \param len: the length of the blob to look for
 * \param nul: nonzero if the next byte must be NUL
 *
 * Helper that looks through a whole aws_lwsac for a given binary blob already
 * present.  Used in the case that aws_lwsac contents are const once written, and
 * strings or blobs may be repeated in the input: this allows the earlier
 * copy to be pointed to by subsequent references without repeating the string
 * or blob redundantly.
 */
LWS_VISIBLE LWS_EXTERN uint8_t *
aws_lwsac_scan_extant(struct aws_lwsac *head, uint8_t *find, size_t len, int nul);

///@}

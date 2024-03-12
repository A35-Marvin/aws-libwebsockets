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

struct aws_lws_dsh_search {
	size_t		required;
	int		kind;
	aws_lws_dsh_obj_t	*best;
	aws_lws_dsh_t	*dsh;

	aws_lws_dsh_t	*already_checked;
	aws_lws_dsh_t	*this_dsh;
};

static int
aws__lws_dsh_alloc_tail(aws_lws_dsh_t *dsh, int kind, const void *src1, size_t size1,
		    const void *src2, size_t size2, aws_lws_dll2_t *replace);

static size_t
aws_lws_dsh_align(size_t length)
{
	size_t align = sizeof(int *);

	if (length & (align - 1))
		length += align - (length & (align - 1));

	return length;
}

aws_lws_dsh_t *
aws_lws_dsh_create(aws_lws_dll2_owner_t *owner, size_t buf_len, int count_kinds)
{
	size_t oha_len = sizeof(aws_lws_dsh_obj_head_t) * (unsigned int)(++count_kinds);
	aws_lws_dsh_obj_t *obj;
	aws_lws_dsh_t *dsh;
	int n;

	assert(buf_len);
	assert(count_kinds > 1);
	assert(buf_len > sizeof(aws_lws_dsh_t) + oha_len);
	buf_len += 64;

	dsh = aws_lws_malloc(sizeof(aws_lws_dsh_t) + buf_len + oha_len, __func__);
	if (!dsh)
		return NULL;

	/* set convenience pointers to the overallocated parts */

	dsh->oha = (aws_lws_dsh_obj_head_t *)&dsh[1];
	dsh->buf = ((uint8_t *)dsh->oha) + oha_len;
	dsh->count_kinds = count_kinds;
	dsh->buffer_size = buf_len;
	dsh->being_destroyed = 0;

	/* clear down the obj heads array */

	memset(dsh->oha, 0, oha_len);
	for (n = 0; n < count_kinds; n++) {
		dsh->oha[n].kind = n;
		dsh->oha[n].total_size = 0;
	}

	/* initially the whole buffer is on the free kind (0) list */

	obj = (aws_lws_dsh_obj_t *)dsh->buf;
	memset(obj, 0, sizeof(*obj));
	obj->asize = buf_len - sizeof(*obj);

	aws_lws_dll2_add_head(&obj->list, &dsh->oha[0].owner);

	dsh->locally_free = obj->asize;
	dsh->locally_in_use = 0;

	aws_lws_dll2_clear(&dsh->list);
	if (owner)
		aws_lws_dll2_add_head(&dsh->list, owner);

	// aws_lws_dsh_describe(dsh, "post-init");

	return dsh;
}

static int
search_best_free(struct aws_lws_dll2 *d, void *user)
{
	struct aws_lws_dsh_search *s = (struct aws_lws_dsh_search *)user;
	aws_lws_dsh_obj_t *obj = aws_lws_container_of(d, aws_lws_dsh_obj_t, list);

	aws_lwsl_debug("%s: obj %p, asize %zu (req %zu)\n", __func__, obj,
			obj->asize, s->required);

	if (obj->asize >= s->required &&
	    (!s->best || obj->asize < s->best->asize)) {
		s->best = obj;
		s->dsh = s->this_dsh;
	}

	return 0;
}

void
aws_lws_dsh_destroy(aws_lws_dsh_t **pdsh)
{
	aws_lws_dsh_t *dsh = *pdsh;

	if (!dsh)
		return;

	dsh->being_destroyed = 1;

	aws_lws_dll2_remove(&dsh->list);

	/* everything else is in one heap allocation */

	aws_lws_free_set_NULL(*pdsh);
}

size_t
aws_lws_dsh_get_size(struct aws_lws_dsh *dsh, int kind)
{
	kind++;
	assert(kind < dsh->count_kinds);

	return dsh->oha[kind].total_size;
}

static int
aws__lws_dsh_alloc_tail(aws_lws_dsh_t *dsh, int kind, const void *src1, size_t size1,
		    const void *src2, size_t size2, aws_lws_dll2_t *replace)
{
	size_t asize = sizeof(aws_lws_dsh_obj_t) + aws_lws_dsh_align(size1 + size2);
	struct aws_lws_dsh_search s;

	assert(kind >= 0);
	kind++;
	assert(!dsh || kind < dsh->count_kinds);

	/*
	 * Search our free list looking for the smallest guy who will fit
	 * what we want to allocate
	 */
	s.required = asize;
	s.kind = kind;
	s.best = NULL;
	s.already_checked = NULL;
	s.this_dsh = dsh;

	if (dsh && !dsh->being_destroyed)
		aws_lws_dll2_foreach_safe(&dsh->oha[0].owner, &s, search_best_free);

	if (!s.best) {
		aws_lwsl_notice("%s: no buffer has space\n", __func__);

		return 1;
	}

	/* anything coming out of here must be aligned */
	assert(!(((unsigned long)s.best) & (sizeof(int *) - 1)));

	if (s.best->asize < asize + (2 * sizeof(*s.best))) {
		/*
		 * Exact fit, or close enough we can't / don't want to have to
		 * track the little bit of free area that would be left.
		 *
		 * Move the object from the free list to the oha of the
		 * desired kind
		 */
		aws_lws_dll2_remove(&s.best->list);
		s.best->dsh = s.dsh;
		s.best->kind = kind;
		s.best->size = size1 + size2;
		memcpy(&s.best[1], src1, size1);
		if (src2)
			memcpy((uint8_t *)&s.best[1] + size1, src2, size2);

		if (replace) {
			s.best->list.prev = replace->prev;
			s.best->list.next = replace->next;
			s.best->list.owner = replace->owner;
			if (replace->prev)
				replace->prev->next = &s.best->list;
			if (replace->next)
				replace->next->prev = &s.best->list;
		} else
			if (dsh) {
				assert(!(((unsigned long)(intptr_t)(s.best)) & (sizeof(int *) - 1)));
				aws_lws_dll2_add_tail(&s.best->list, &dsh->oha[kind].owner);
			}

		assert(s.dsh->locally_free >= s.best->asize);
		s.dsh->locally_free -= s.best->asize;
		s.dsh->locally_in_use += s.best->asize;
		dsh->oha[kind].total_size += s.best->asize;
		assert(s.dsh->locally_in_use <= s.dsh->buffer_size);
	} else {
		aws_lws_dsh_obj_t *obj;

		/*
		 * Free area was oversize enough that we need to split it.
		 *
		 * Leave the first part of the free area where it is and
		 * reduce its extent by our asize.  Use the latter part of
		 * the original free area as the allocation.
		 */
		aws_lwsl_debug("%s: splitting... free reduce %zu -> %zu\n",
				__func__, s.best->asize, s.best->asize - asize);

		s.best->asize -= asize;

		/* latter part becomes new object */

		obj = (aws_lws_dsh_obj_t *)(((uint8_t *)s.best) + aws_lws_dsh_align(s.best->asize));

		aws_lws_dll2_clear(&obj->list);
		obj->dsh = s.dsh;
		obj->kind = kind;
		obj->size = size1 + size2;
		obj->asize = asize;

		memcpy(&obj[1], src1, size1);
		if (src2)
			memcpy((uint8_t *)&obj[1] + size1, src2, size2);

		if (replace) {
			s.best->list.prev = replace->prev;
			s.best->list.next = replace->next;
			s.best->list.owner = replace->owner;
			if (replace->prev)
				replace->prev->next = &s.best->list;
			if (replace->next)
				replace->next->prev = &s.best->list;
		} else
			if (dsh) {
				assert(!(((unsigned long)(intptr_t)(obj)) & (sizeof(int *) - 1)));
				aws_lws_dll2_add_tail(&obj->list, &dsh->oha[kind].owner);
			}

		assert(s.dsh->locally_free >= asize);
		s.dsh->locally_free -= asize;
		s.dsh->locally_in_use += asize;
		dsh->oha[kind].total_size += asize;
		assert(s.dsh->locally_in_use <= s.dsh->buffer_size);
	}

	// aws_lws_dsh_describe(dsh, "post-alloc");

	return 0;
}

int
aws_lws_dsh_alloc_tail(aws_lws_dsh_t *dsh, int kind, const void *src1, size_t size1,
		   const void *src2, size_t size2)
{
	return aws__lws_dsh_alloc_tail(dsh, kind, src1, size1, src2, size2, NULL);
}

static int
buf_compare(const aws_lws_dll2_t *d, const aws_lws_dll2_t *i)
{
	return (int)aws_lws_ptr_diff(d, i);
}

void
aws_lws_dsh_free(void **pobj)
{
	aws_lws_dsh_obj_t *_o = (aws_lws_dsh_obj_t *)((uint8_t *)(*pobj) - sizeof(*_o)),
			*_o2;
	aws_lws_dsh_t *dsh = _o->dsh;

	/* anything coming out of here must be aligned */
	assert(!(((unsigned long)_o) & (sizeof(int *) - 1)));

	/*
	 * Remove the object from its list and place on the free list of the
	 * dsh the buffer space belongs to
	 */

	aws_lws_dll2_remove(&_o->list);
	*pobj = NULL;

	assert(dsh->locally_in_use >= _o->asize);
	dsh->locally_free += _o->asize;
	dsh->locally_in_use -= _o->asize;
	dsh->oha[_o->kind].total_size -= _o->asize; /* account for usage by kind */
	assert(dsh->locally_in_use <= dsh->buffer_size);

	/*
	 * The free space list is sorted in buffer address order, so detecting
	 * coalescing opportunities is cheap.  Because the free list should be
	 * continuously tending to reduce by coalescing, the sorting should not
	 * be expensive to maintain.
	 */
	_o->size = 0; /* not meaningful when on free list */
	aws_lws_dll2_add_sorted(&_o->list, &_o->dsh->oha[0].owner, buf_compare);

	/* First check for already-free block at the end we can subsume.
	 * Because the free list is sorted, if there is such a guy he is
	 * already our list.next */

	_o2 = (aws_lws_dsh_obj_t *)_o->list.next;
	if (_o2 && (uint8_t *)_o + _o->asize == (uint8_t *)_o2) {
		/*
		 * since we are freeing _obj, we can coalesce with a
		 * free area immediately ahead of it
		 *
		 *  [ _o (being freed) ][ _o2 (free) ]  -> [ larger _o ]
		 */
		_o->asize += _o2->asize;

		/* guy next to us was absorbed into us */
		aws_lws_dll2_remove(&_o2->list);
	}

	/* Then check if we can be subsumed by a free block behind us.
	 * Because the free list is sorted, if there is such a guy he is
	 * already our list.prev */

	_o2 = (aws_lws_dsh_obj_t *)_o->list.prev;
	if (_o2 && (uint8_t *)_o2 + _o2->asize == (uint8_t *)_o) {
		/*
		 * since we are freeing obj, we can coalesce it with
		 * the previous free area that abuts it
		 *
		 *  [ _o2 (free) ][ _o (being freed) ] -> [ larger _o2 ]
		 */
		_o2->asize += _o->asize;

		/* we were absorbed! */
		aws_lws_dll2_remove(&_o->list);
	}

	// aws_lws_dsh_describe(dsh, "post-alloc");
}

int
aws_lws_dsh_get_head(aws_lws_dsh_t *dsh, int kind, void **obj, size_t *size)
{
	aws_lws_dsh_obj_t *_obj;

	if (!dsh)
		return 1;

	_obj = (aws_lws_dsh_obj_t *)aws_lws_dll2_get_head(&dsh->oha[kind + 1].owner);

	if (!_obj) {
		*obj = 0;
		*size = 0;

		return 1;	/* there is no head */
	}

	*obj = (void *)(&_obj[1]);
	*size = _obj->size;

	/* anything coming out of here must be aligned */
	assert(!(((unsigned long)(intptr_t)(*obj)) & (sizeof(int *) - 1)));

	return 0;	/* we returned the head */
}

#if defined(_DEBUG) && !defined(LWS_WITH_NO_LOGS)

static int
describe_kind(struct aws_lws_dll2 *d, void *user)
{
	aws_lws_dsh_obj_t *obj = aws_lws_container_of(d, aws_lws_dsh_obj_t, list);

	aws_lwsl_info("    _obj %p - %p, dsh %p, size %zu, asize %zu\n",
			obj, (uint8_t *)obj + obj->asize,
			obj->dsh, obj->size, obj->asize);

	return 0;
}

void
aws_lws_dsh_describe(aws_lws_dsh_t *dsh, const char *desc)
{
	int n = 0;

	aws_lwsl_info("%s: dsh %p, bufsize %zu, kinds %d, lf: %zu, liu: %zu, %s\n",
		    __func__, dsh, dsh->buffer_size, dsh->count_kinds,
		    dsh->locally_free, dsh->locally_in_use, desc);

	for (n = 0; n < dsh->count_kinds; n++) {
		aws_lwsl_info("  Kind %d:\n", n);
		aws_lws_dll2_foreach_safe(&dsh->oha[n].owner, dsh, describe_kind);
	}
}
#endif

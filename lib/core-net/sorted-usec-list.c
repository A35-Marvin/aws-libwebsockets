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

#include "private-lib-core.h"

static int
sul_compare(const aws_lws_dll2_t *d, const aws_lws_dll2_t *i)
{
	aws_lws_usec_t a = ((aws_lws_sorted_usec_list_t *)d)->us;
	aws_lws_usec_t b = ((aws_lws_sorted_usec_list_t *)i)->us;

	/*
	 * Simply returning (a - b) in an int
	 * may lead to an integer overflow bug
	 */

	if (a > b)
		return 1;
	if (a < b)
		return -1;

	return 0;
}

/*
 * notice owner was chosen already, and sul->us was already computed
 */

int
aws___lws_sul_insert(aws_lws_dll2_owner_t *own, aws_lws_sorted_usec_list_t *sul)
{
	aws_lws_dll2_remove(&sul->list);

	assert(sul->cb);

	/*
	 * we sort the pt's list of sequencers with pending timeouts, so it's
	 * cheap to check it every poll wait
	 */

	aws_lws_dll2_add_sorted(&sul->list, own, sul_compare);

	return 0;
}

void
aws_lws_sul_cancel(aws_lws_sorted_usec_list_t *sul)
{
	aws_lws_dll2_remove(&sul->list);

	/* we are clearing the timeout and leaving ourselves detached */
	sul->us = 0;
}

void
aws_lws_sul2_schedule(struct aws_lws_context *context, int tsi, int flags,
	          aws_lws_sorted_usec_list_t *sul)
{
	struct aws_lws_context_per_thread *pt = &context->pt[tsi];

	aws_lws_pt_assert_lock_held(pt);

	assert(sul->cb);

	aws___lws_sul_insert(
		&pt->pt_sul_owner[!!(flags & LWSSULLI_WAKE_IF_SUSPENDED)], sul);
}

/*
 * own points to the first in an array of length own_len
 *
 * While any sul list owner has a "ripe", ie, ready to handle sul we do them
 * strictly in order of sul time.  When nobody has a ripe sul we return 0, if
 * actually nobody has any sul, or the interval between usnow and the next
 * earliest scheduled event on any list.
 */

aws_lws_usec_t
aws___lws_sul_service_ripe(aws_lws_dll2_owner_t *own, int own_len, aws_lws_usec_t usnow)
{
	struct aws_lws_context_per_thread *pt = (struct aws_lws_context_per_thread *)
			aws_lws_container_of(own, struct aws_lws_context_per_thread,
					 pt_sul_owner);

	if (pt->attach_owner.count)
		aws_lws_system_do_attach(pt);

	aws_lws_pt_assert_lock_held(pt);

	/* must be at least 1 */
	assert(own_len > 0);

	/*
	 * Of the own_len sul owning lists, the earliest next sul could be on
	 * any of them.  We have to find it and handle each in turn until no
	 * ripe sul left on any owning list, and we can exit.
	 *
	 * This ensures the ripe sul are handled strictly in the right order no
	 * matter which owning list they are on.
	 */

	do {
		aws_lws_sorted_usec_list_t *hit = NULL;
		aws_lws_usec_t lowest = 0;
		int n = 0;

		for (n = 0; n < own_len; n++) {
			aws_lws_sorted_usec_list_t *sul;
			if (!own[n].count)
				continue;
			 sul = (aws_lws_sorted_usec_list_t *)
						     aws_lws_dll2_get_head(&own[n]);

			if (!hit || sul->us <= lowest) {
				hit = sul;
				lowest = sul->us;
			}
		}

		if (!hit)
			return 0;

		if (lowest > usnow)
			return lowest - usnow;

		/* his moment has come... remove him from his owning list */

		aws_lws_dll2_remove(&hit->list);
		hit->us = 0;

		// aws_lwsl_notice("%s: sul: %p\n", __func__, hit->cb);

		pt->inside_lws_service = 1;
		hit->cb(hit);
		pt->inside_lws_service = 0;

	} while (1);

	/* unreachable */

	return 0;
}

/*
 * Normally we use the OS monotonic time, which does not step when the
 * gettimeofday() time is adjusted after, eg, ntpclient.  But on some OSes,
 * high resolution monotonic time doesn't exist; sul time is computed from and
 * compared against gettimeofday() time and breaks when that steps.
 *
 * For those cases, this allows us to retrospectively adjust existing suls on
 * all owning lists by the step amount, at the same time we adjust the
 * nonmonotonic clock.  Then nothing breaks so long as we do this when the
 * gettimeofday() clock is stepped.
 *
 * Linux and so on offer Posix MONOTONIC, which lws uses.  FreeRTOS doesn't
 * have a high-resolution monotonic clock and has to use gettimeofday(), which
 * requires this adjustment when it is stepped.
 */

aws_lws_usec_t
aws_lws_sul_nonmonotonic_adjust(struct aws_lws_context *ctx, int64_t step_us)
{
	struct aws_lws_context_per_thread *pt = &ctx->pt[0];
	int n, m;

	/*
	 * for each pt
	 */

	for (m = 0; m < ctx->count_threads; m++) {

		/*
		 * For each owning list...
		 */

		aws_lws_pt_lock(pt, __func__);

		for (n = 0; n < LWS_COUNT_PT_SUL_OWNERS; n++) {

			if (!pt->pt_sul_owner[n].count)
				continue;

			/* ... and for every existing sul on a list... */

			aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p,
					      aws_lws_dll2_get_head(
							&pt->pt_sul_owner[n])) {
				aws_lws_sorted_usec_list_t *sul = aws_lws_container_of(
					       p, aws_lws_sorted_usec_list_t, list);

				/*
				 * ... retrospectively step its ripe time by the
				 * step we will adjust the gettimeofday() clock
				 * with
				 */

				sul->us += step_us;

			} aws_lws_end_foreach_dll(p);
		}

		aws_lws_pt_unlock(pt);

		pt++;
	}

	return 0;
}

/*
 * Earliest wakeable event on any pt
 */

int
aws_lws_sul_earliest_wakeable_event(struct aws_lws_context *ctx, aws_lws_usec_t *pearliest)
{
	struct aws_lws_context_per_thread *pt;
	int n = 0, hit = -1;
	aws_lws_usec_t lowest = 0;

	for (n = 0; n < ctx->count_threads; n++) {
		pt = &ctx->pt[n];

		aws_lws_pt_lock(pt, __func__);

		if (pt->pt_sul_owner[LWSSULLI_WAKE_IF_SUSPENDED].count) {
			aws_lws_sorted_usec_list_t *sul = (aws_lws_sorted_usec_list_t *)
					aws_lws_dll2_get_head(&pt->pt_sul_owner[
					           LWSSULLI_WAKE_IF_SUSPENDED]);

			if (hit == -1 || sul->us < lowest) {
				hit = n;
				lowest = sul->us;
			}
		}

		aws_lws_pt_unlock(pt);
	}


	if (hit == -1)
		/* there is no pending event */
		return 1;

	*pearliest = lowest;

	return 0;
}

void
aws_lws_sul_schedule(struct aws_lws_context *ctx, int tsi, aws_lws_sorted_usec_list_t *sul,
		 sul_cb_t _cb, aws_lws_usec_t _us)
{
	struct aws_lws_context_per_thread *_pt = &ctx->pt[tsi];

	assert(_cb);

	aws_lws_pt_lock(_pt, __func__);

	if (_us == (aws_lws_usec_t)LWS_SET_TIMER_USEC_CANCEL)
		aws_lws_sul_cancel(sul);
	else {
		sul->cb = _cb;
		sul->us = aws_lws_now_usecs() + _us;
		aws_lws_sul2_schedule(ctx, tsi, LWSSULLI_MISS_IF_SUSPENDED, sul);
	}

	aws_lws_pt_unlock(_pt);
}

void
aws_lws_sul_schedule_wakesuspend(struct aws_lws_context *ctx, int tsi,
			     aws_lws_sorted_usec_list_t *sul, sul_cb_t _cb,
			     aws_lws_usec_t _us)
{
	struct aws_lws_context_per_thread *_pt = &ctx->pt[tsi];

	assert(_cb);

	aws_lws_pt_lock(_pt, __func__);

	if (_us == (aws_lws_usec_t)LWS_SET_TIMER_USEC_CANCEL)
		aws_lws_sul_cancel(sul);
	else {
		sul->cb = _cb;
		sul->us = aws_lws_now_usecs() + _us;
		aws_lws_sul2_schedule(ctx, tsi, LWSSULLI_WAKE_IF_SUSPENDED, sul);
	}

	aws_lws_pt_unlock(_pt);
}

#if defined(LWS_WITH_SUL_DEBUGGING)

/*
 * Sanity checker for any sul left scheduled when its containing object is
 * freed... code scheduling suls must take care to cancel them when destroying
 * their object.  This optional debugging helper checks that when an object is
 * being destroyed, there is no live sul scheduled from inside the object.
 */

void
aws_lws_sul_debug_zombies(struct aws_lws_context *ctx, void *po, size_t len,
		      const char *destroy_description)
{
	struct aws_lws_context_per_thread *pt;
	int n, m;

	for (n = 0; n < ctx->count_threads; n++) {
		pt = &ctx->pt[n];

		aws_lws_pt_lock(pt, __func__);

		for (m = 0; m < LWS_COUNT_PT_SUL_OWNERS; m++) {

			aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p,
				      aws_lws_dll2_get_head(&pt->pt_sul_owner[m])) {
				aws_lws_sorted_usec_list_t *sul =
					aws_lws_container_of(p,
						aws_lws_sorted_usec_list_t, list);

				if (!po) {
					aws_lwsl_cx_err(ctx, "%s",
							 destroy_description);
					/* just sanity check the list */
					assert(sul->cb);
				}

				/*
				 * Is the sul resident inside the object that is
				 * indicated as being deleted?
				 */

				if (po &&
				    (void *)sul >= po &&
				    (size_t)aws_lws_ptr_diff(sul, po) < len) {
					aws_lwsl_cx_err(ctx, "ERROR: Zombie Sul "
						 "(on list %d) %s, cb %p\n", m,
						 destroy_description, sul->cb);
					/*
					 * This assert fires if you have left
					 * a sul scheduled to fire later, but
					 * are about to destroy the object the
					 * sul lives in.  You must take care to
					 * do aws_lws_sul_cancel(&sul) on any suls
					 * that may be scheduled before
					 * destroying the object the sul lives
					 * inside.
					 *
					 * You can look up the cb pointer in
					 * your mapfile to find out which
					 * callback function the sul was using
					 * which usually tells you which sul
					 * it is.
					 */
					assert(0);
				}

			} aws_lws_end_foreach_dll(p);
		}

		aws_lws_pt_unlock(pt);
	}
}

#endif

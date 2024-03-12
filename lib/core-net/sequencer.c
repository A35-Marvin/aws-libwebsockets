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

/*
 * per pending event
 */
typedef struct aws_lws_seq_event {
	struct aws_lws_dll2			seq_event_list;

	void				*data;
	void				*aux;
	aws_lws_seq_events_t		e;
} aws_lws_seq_event_t;

/*
 * per sequencer
 */
typedef struct aws_lws_sequencer {
	struct aws_lws_dll2			seq_list;

	aws_lws_sorted_usec_list_t		sul_timeout;
	aws_lws_sorted_usec_list_t		sul_pending;

	struct aws_lws_dll2_owner		seq_event_owner;
	struct aws_lws_context_per_thread	*pt;
	aws_lws_seq_event_cb		cb;
	const char			*name;
	const aws_lws_retry_bo_t		*retry;

	aws_lws_usec_t			time_created;
	aws_lws_usec_t			timeout; /* 0 or time we timeout */

	uint8_t				going_down:1;
	uint8_t				wakesuspend:1;
} aws_lws_seq_t;

#define QUEUE_SANITY_LIMIT 10

static void
aws_lws_sul_seq_heartbeat_cb(aws_lws_sorted_usec_list_t *sul)
{
	struct aws_lws_context_per_thread *pt = aws_lws_container_of(sul,
			struct aws_lws_context_per_thread, sul_seq_heartbeat);

	/* send every sequencer a heartbeat message... it can ignore it */

	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, tp,
				   aws_lws_dll2_get_head(&pt->seq_owner)) {
		aws_lws_seq_t *s = aws_lws_container_of(p, aws_lws_seq_t, seq_list);

		/* queue the message to inform the sequencer */
		aws_lws_seq_queue_event(s, LWSSEQ_HEARTBEAT, NULL, NULL);

	} aws_lws_end_foreach_dll_safe(p, tp);

	/* schedule the next one */

	__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &pt->sul_seq_heartbeat, LWS_US_PER_SEC);
}

int
aws_lws_seq_pt_init(struct aws_lws_context_per_thread *pt)
{
	pt->sul_seq_heartbeat.cb = aws_lws_sul_seq_heartbeat_cb;

	/* schedule the first heartbeat */
	__lws_sul_insert_us(&pt->pt_sul_owner[LWSSULLI_MISS_IF_SUSPENDED],
			    &pt->sul_seq_heartbeat, LWS_US_PER_SEC);

	return 0;
}

aws_lws_seq_t *
aws_lws_seq_create(aws_lws_seq_info_t *i)
{
	struct aws_lws_context_per_thread *pt = &i->context->pt[i->tsi];
	aws_lws_seq_t *seq = aws_lws_zalloc(sizeof(*seq) + i->user_size, __func__);

	if (!seq)
		return NULL;

	seq->cb = i->cb;
	seq->pt = pt;
	seq->name = i->name;
	seq->retry = i->retry;
	seq->wakesuspend = i->wakesuspend;

	*i->puser = (void *)&seq[1];

	/* add the sequencer to the pt */

	aws_lws_pt_lock(pt, __func__); /* ---------------------------------- pt { */

	aws_lws_dll2_add_tail(&seq->seq_list, &pt->seq_owner);

	aws_lws_pt_unlock(pt); /* } pt ------------------------------------------ */

	seq->time_created = aws_lws_now_usecs();

	/* try to queue the creation cb */

	if (aws_lws_seq_queue_event(seq, LWSSEQ_CREATED, NULL, NULL)) {
		aws_lws_dll2_remove(&seq->seq_list);
		aws_lws_free(seq);

		return NULL;
	}

	return seq;
}

static int
seq_ev_destroy(struct aws_lws_dll2 *d, void *user)
{
	aws_lws_seq_event_t *seqe = aws_lws_container_of(d, aws_lws_seq_event_t,
						 seq_event_list);

	aws_lws_dll2_remove(&seqe->seq_event_list);
	aws_lws_free(seqe);

	return 0;
}

void
aws_lws_seq_destroy(aws_lws_seq_t **pseq)
{
	aws_lws_seq_t *seq = *pseq;

	/* defeat another thread racing to add events while we are destroying */
	seq->going_down = 1;

	seq->cb(seq, (void *)&seq[1], LWSSEQ_DESTROYED, NULL, NULL);

	aws_lws_pt_lock(seq->pt, __func__); /* -------------------------- pt { */

	aws_lws_dll2_remove(&seq->seq_list);
	aws_lws_dll2_remove(&seq->sul_timeout.list);
	aws_lws_dll2_remove(&seq->sul_pending.list);
	/* remove and destroy any pending events */
	aws_lws_dll2_foreach_safe(&seq->seq_event_owner, NULL, seq_ev_destroy);

	aws_lws_pt_unlock(seq->pt); /* } pt ---------------------------------- */


	aws_lws_free_set_NULL(seq);
}

void
aws_lws_seq_destroy_all_on_pt(struct aws_lws_context_per_thread *pt)
{
	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, tp,
				   pt->seq_owner.head) {
		aws_lws_seq_t *s = aws_lws_container_of(p, aws_lws_seq_t,
						      seq_list);

		aws_lws_seq_destroy(&s);

	} aws_lws_end_foreach_dll_safe(p, tp);
}

static void
aws_lws_seq_sul_pending_cb(aws_lws_sorted_usec_list_t *sul)
{
	aws_lws_seq_t *seq = aws_lws_container_of(sul, aws_lws_seq_t, sul_pending);
	aws_lws_seq_event_t *seqe;
	struct aws_lws_dll2 *dh;
	int n;

	if (!seq->seq_event_owner.count)
		return;

	/* events are only added at tail, so no race possible yet... */

	dh = aws_lws_dll2_get_head(&seq->seq_event_owner);
	seqe = aws_lws_container_of(dh, aws_lws_seq_event_t, seq_event_list);

	n = (int)seq->cb(seq, (void *)&seq[1], (int)seqe->e, seqe->data, seqe->aux);

	/* ... have to lock here though, because we will change the list */

	aws_lws_pt_lock(seq->pt, __func__); /* ----------------------------- pt { */

	/* detach event from sequencer event list and free it */
	aws_lws_dll2_remove(&seqe->seq_event_list);
	aws_lws_free(seqe);
	aws_lws_pt_unlock(seq->pt); /* } pt ------------------------------------- */

	if (n) {
		aws_lwsl_info("%s: destroying seq '%s' by request\n", __func__,
				seq->name);
		aws_lws_seq_destroy(&seq);
	}
}

int
aws_lws_seq_queue_event(aws_lws_seq_t *seq, aws_lws_seq_events_t e, void *data, void *aux)
{
	aws_lws_seq_event_t *seqe;

	if (!seq || seq->going_down)
		return 1;

	seqe = aws_lws_zalloc(sizeof(*seqe), __func__);
	if (!seqe)
		return 1;

	seqe->e = e;
	seqe->data = data;
	seqe->aux = aux;

	// aws_lwsl_notice("%s: seq %s: event %d\n", __func__, seq->name, e);

	aws_lws_pt_lock(seq->pt, __func__); /* ----------------------------- pt { */

	if (seq->seq_event_owner.count > QUEUE_SANITY_LIMIT) {
		aws_lwsl_err("%s: more than %d events queued\n", __func__,
			 QUEUE_SANITY_LIMIT);
	}

	aws_lws_dll2_add_tail(&seqe->seq_event_list, &seq->seq_event_owner);

	seq->sul_pending.cb = aws_lws_seq_sul_pending_cb;
	__lws_sul_insert_us(&seq->pt->pt_sul_owner[seq->wakesuspend],
			    &seq->sul_pending, 1);

	aws_lws_pt_unlock(seq->pt); /* } pt ------------------------------------- */

	return 0;
}

/*
 * Check if wsi still extant, by peeking in the message queue for a
 * LWSSEQ_WSI_CONN_CLOSE message about wsi.  (Doesn't need to do the same for
 * CONN_FAIL since that will never have produced any messages prior to that).
 *
 * Use this to avoid trying to perform operations on wsi that have already
 * closed but we didn't get to that message yet.
 *
 * Returns 0 if not closed yet or 1 if it has closed but we didn't process the
 * close message yet.
 */

int
aws_lws_seq_check_wsi(aws_lws_seq_t *seq, struct lws *wsi)
{
	aws_lws_seq_event_t *seqe;
	struct aws_lws_dll2 *dh;

	aws_lws_pt_lock(seq->pt, __func__); /* ----------------------------- pt { */

	dh = aws_lws_dll2_get_head(&seq->seq_event_owner);
	while (dh) {
		seqe = aws_lws_container_of(dh, aws_lws_seq_event_t, seq_event_list);

		if (seqe->e == LWSSEQ_WSI_CONN_CLOSE && seqe->data == wsi)
			break;

		dh = dh->next;
	}

	aws_lws_pt_unlock(seq->pt); /* } pt ------------------------------------- */

	return !!dh;
}


static void
aws_lws_seq_sul_timeout_cb(aws_lws_sorted_usec_list_t *sul)
{
	aws_lws_seq_t *s = aws_lws_container_of(sul, aws_lws_seq_t, sul_timeout);

	aws_lws_seq_queue_event(s, LWSSEQ_TIMED_OUT, NULL, NULL);
}

/* set us to LWS_SET_TIMER_USEC_CANCEL to remove timeout */

int
aws_lws_seq_timeout_us(aws_lws_seq_t *seq, aws_lws_usec_t us)
{
	seq->sul_timeout.cb = aws_lws_seq_sul_timeout_cb;
	/* list is always at the very top of the sul */
	__lws_sul_insert_us(&seq->pt->pt_sul_owner[seq->wakesuspend],
			(aws_lws_sorted_usec_list_t *)&seq->sul_timeout.list, us);

	return 0;
}

aws_lws_seq_t *
aws_lws_seq_from_user(void *u)
{
	return &((aws_lws_seq_t *)u)[-1];
}

const char *
aws_lws_seq_name(aws_lws_seq_t *seq)
{
	return seq->name;
}

aws_lws_usec_t
aws_lws_seq_us_since_creation(aws_lws_seq_t *seq)
{
	return aws_lws_now_usecs() - seq->time_created;
}

struct aws_lws_context *
aws_lws_seq_get_context(aws_lws_seq_t *seq)
{
	return seq->pt->context;
}


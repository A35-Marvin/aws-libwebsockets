/*
 * ws protocol handler plugin for "lws-minimal"
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This version uses an aws_lws_ring ringbuffer to cache up to 8 messages at a time,
 * so it's not so easy to lose messages.
 *
 * This also demonstrates how to "cull", ie, aws_kill, connections that can't
 * keep up for some reason.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

/* one of these created for each message */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
};

/* one of these is created for each client connecting to us */

struct per_session_data__minimal {
	struct per_session_data__minimal *pss_list;
	struct aws_lws *wsi;
	uint32_t tail;

	unsigned int culled:1;
};

/* one of these is created for each vhost our protocol is used with */

struct per_vhost_data__minimal {
	struct aws_lws_context *context;
	struct aws_lws_vhost *vhost;
	const struct aws_lws_protocols *protocol;

	struct per_session_data__minimal *pss_list; /* linked-list of live pss*/

	struct aws_lws_ring *ring; /* ringbuffer holding unsent messages */
};

static void
cull_lagging_clients(struct per_vhost_data__minimal *vhd)
{
	uint32_t oldest_tail = aws_lws_ring_get_oldest_tail(vhd->ring);
	struct per_session_data__minimal *old_pss = NULL;
	int most = 0, before = (int)aws_lws_ring_get_count_waiting_elements(vhd->ring,
					&oldest_tail), m;

	/*
	 * At least one guy with the oldest tail has lagged too far, filling
	 * the ringbuffer with stuff waiting for them, while new stuff is
	 * coming in, and they must close, freeing up ringbuffer entries.
	 */

	aws_lws_start_foreach_llp_safe(struct per_session_data__minimal **,
			      ppss, vhd->pss_list, pss_list) {

		if ((*ppss)->tail == oldest_tail) {
			old_pss = *ppss;

			aws_lwsl_user("Killing lagging client %p\n", (*ppss)->wsi);

			aws_lws_set_timeout((*ppss)->wsi, PENDING_TIMEOUT_LAGGING,
					/*
					 * we may aws_kill the wsi we came in on,
					 * so the actual close is deferred
					 */
					LWS_TO_KILL_ASYNC);

			/*
			 * We might try to write something before we get a
			 * chance to close.  But this pss is now detached
			 * from the ring buffer.  Mark this pss as culled so we
			 * don't try to do anything more with it.
			 */

			(*ppss)->culled = 1;

			/*
			 * Because we can't aws_kill it synchronously, but we
			 * know it's closing momentarily and don't want its
			 * participation any more, remove its pss from the
			 * vhd pss list early.  (This is safe to repeat
			 * uselessly later in the close flow).
			 *
			 * Notice this changes *ppss!
			 */

			aws_lws_ll_fwd_remove(struct per_session_data__minimal,
					  pss_list, (*ppss), vhd->pss_list);

			/* use the changed *ppss so we won't skip anything */

			continue;

		} else {
			/*
			 * so this guy is a survivor of the cull.  Let's track
			 * what is the largest number of pending ring elements
			 * for any survivor.
			 */
			m = (int)aws_lws_ring_get_count_waiting_elements(vhd->ring,
							&((*ppss)->tail));
			if (m > most)
				most = m;
		}

	} aws_lws_end_foreach_llp_safe(ppss);

	/* it would mean we lost track of oldest... but Coverity insists */
	if (!old_pss)
		return;

	/*
	 * Let's recover (ie, free up) all the ring slots between the
	 * original oldest's last one and the "worst" survivor.
	 */

	aws_lws_ring_consume_and_update_oldest_tail(vhd->ring,
		struct per_session_data__minimal, &old_pss->tail, (size_t)(before - most),
		vhd->pss_list, tail, pss_list);

	aws_lwsl_user("%s: shrunk ring from %d to %d\n", __func__, before, most);
}

/* destroys the message when everyone has had a copy of it */

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

static int
callback_minimal(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_session_data__minimal *pss =
			(struct per_session_data__minimal *)user;
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)
			aws_lws_protocol_vh_priv_get(aws_lws_get_vhost(wsi),
					aws_lws_get_protocol(wsi));
	const struct msg *pmsg;
	struct msg amsg;
	int n, m;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = aws_lws_protocol_vh_priv_zalloc(aws_lws_get_vhost(wsi),
				aws_lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__minimal));
		vhd->context = aws_lws_get_context(wsi);
		vhd->protocol = aws_lws_get_protocol(wsi);
		vhd->vhost = aws_lws_get_vhost(wsi);

		vhd->ring = aws_lws_ring_create(sizeof(struct msg), 8,
					    __minimal_destroy_message);
		if (!vhd->ring)
			return 1;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		aws_lws_ring_destroy(vhd->ring);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/* add ourselves to the list of live pss held in the vhd */
		aws_lwsl_user("LWS_CALLBACK_ESTABLISHED: wsi %p\n", wsi);
		aws_lws_ll_fwd_insert(pss, pss_list, vhd->pss_list);
		pss->tail = aws_lws_ring_get_oldest_tail(vhd->ring);
		pss->wsi = wsi;
		break;

	case LWS_CALLBACK_CLOSED:
		aws_lwsl_user("LWS_CALLBACK_CLOSED: wsi %p\n", wsi);
		/* remove our closing pss from the list of live pss */
		aws_lws_ll_fwd_remove(struct per_session_data__minimal, pss_list,
				  pss, vhd->pss_list);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (pss->culled)
			break;
		pmsg = aws_lws_ring_get_element(vhd->ring, &pss->tail);
		if (!pmsg)
			break;

		/* notice we allowed for LWS_PRE in the payload already */
		m = aws_lws_write(wsi, ((unsigned char *)pmsg->payload) +
			      LWS_PRE, pmsg->len, LWS_WRITE_TEXT);
		if (m < (int)pmsg->len) {
			aws_lwsl_err("ERROR %d writing to ws socket\n", m);
			return -1;
		}

		aws_lws_ring_consume_and_update_oldest_tail(
			vhd->ring,	/* aws_lws_ring object */
			struct per_session_data__minimal, /* type of objects with tails */
			&pss->tail,	/* tail of guy doing the consuming */
			1,		/* number of payload objects being consumed */
			vhd->pss_list,	/* head of list of objects with tails */
			tail,		/* member name of tail in objects with tails */
			pss_list	/* member name of next object in objects with tails */
		);

		/* more to do for us? */
		if (aws_lws_ring_get_element(vhd->ring, &pss->tail))
			/* come back as soon as we can write more */
			aws_lws_callback_on_writable(pss->wsi);
		break;

	case LWS_CALLBACK_RECEIVE:
		n = (int)aws_lws_ring_get_count_free_elements(vhd->ring);
		if (!n) {
			/* forcibly make space */
			cull_lagging_clients(vhd);
			n = (int)aws_lws_ring_get_count_free_elements(vhd->ring);
		}
		if (!n)
			break;

		aws_lwsl_user("LWS_CALLBACK_RECEIVE: free space %d\n", n);

		amsg.len = len;
		/* notice we over-allocate by LWS_PRE... */
		amsg.payload = malloc(LWS_PRE + len);
		if (!amsg.payload) {
			aws_lwsl_user("OOM: dropping\n");
			break;
		}

		/* ...and we copy the payload in at +LWS_PRE */
		memcpy((char *)amsg.payload + LWS_PRE, in, len);
		if (!aws_lws_ring_insert(vhd->ring, &amsg, 1)) {
			__minimal_destroy_message(&amsg);
			aws_lwsl_user("dropping!\n");
			break;
		}

		/*
		 * let everybody know we want to write something on them
		 * as soon as they are ready
		 */
		aws_lws_start_foreach_llp(struct per_session_data__minimal **,
				      ppss, vhd->pss_list) {
			aws_lws_callback_on_writable((*ppss)->wsi);
		} aws_lws_end_foreach_llp(ppss, pss_list);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_MINIMAL \
	{ \
		"lws-minimal", \
		callback_minimal, \
		sizeof(struct per_session_data__minimal), \
		0, \
		0, NULL, 0 \
	}

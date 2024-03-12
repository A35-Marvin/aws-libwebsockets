/*
 * ws protocol handler plugin for "lws-minimal" demonstrating multithread
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

/* one of these created for each message in the ringbuffer */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
};

/*
 * One of these is created for each client connecting to us.
 *
 * It is ONLY read or written from the lws service thread context.
 */

struct per_session_data__minimal {
	struct per_session_data__minimal *pss_list;
	struct aws_lws *wsi;
	uint32_t tail;
};

/* one of these is created for each vhost our protocol is used with */

struct per_vhost_data__minimal {
	struct aws_lws_context *context;
	struct aws_lws_vhost *vhost;
	const struct aws_lws_protocols *protocol;

	struct per_session_data__minimal *pss_list; /* linked-list of live pss*/
	pthread_t pthread_spam[2];

	pthread_mutex_t lock_ring; /* serialize access to the ring buffer */
	struct aws_lws_ring *ring; /* {lock_ring} ringbuffer holding unsent content */

	const char *config;
	char finished;
};

#if defined(WIN32)
static void usleep(unsigned long l) { Sleep(l / 1000); }
#endif

/*
 * This runs under both lws service and "spam threads" contexts.
 * Access is serialized by vhd->lock_ring.
 */

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

/*
 * This runs under the "spam thread" thread context only.
 *
 * We spawn two threads that generate messages with this.
 *
 */

static void *
thread_spam(void *d)
{
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)d;
	struct msg amsg;
	int len = 128, index = 1, n, whoami = 0;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
		if (pthread_equal(pthread_self(), vhd->pthread_spam[n]))
			whoami = n + 1;

	do {
		/* don't generate output if nobody connected */
		if (!vhd->pss_list)
			goto wait;

		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */

		/* only create if space in ringbuffer */
		n = (int)aws_lws_ring_get_count_free_elements(vhd->ring);
		if (!n) {
			aws_lwsl_user("dropping!\n");
			goto wait_unlock;
		}

		amsg.payload = malloc((unsigned int)(LWS_PRE + len));
		if (!amsg.payload) {
			aws_lwsl_user("OOM: dropping\n");
			goto wait_unlock;
		}
		n = aws_lws_snprintf((char *)amsg.payload + LWS_PRE, (unsigned int)len,
			         "%s: tid: %d, msg: %d", vhd->config,
			         whoami, index++);
		amsg.len = (unsigned int)n;
		n = (int)aws_lws_ring_insert(vhd->ring, &amsg, 1);
		if (n != 1) {
			__minimal_destroy_message(&amsg);
			aws_lwsl_user("dropping!\n");
		} else
			/*
			 * This will cause a LWS_CALLBACK_EVENT_WAIT_CANCELLED
			 * in the lws service thread context.
			 */
			aws_lws_cancel_service(vhd->context);

wait_unlock:
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */

wait:
		usleep(100000);

	} while (!vhd->finished);

	aws_lwsl_notice("thread_spam %d exiting\n", whoami);

	pthread_exit(NULL);

	return NULL;
}

/* this runs under the lws service thread context only */

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
	const struct aws_lws_protocol_vhost_options *pvo;
	const struct msg *pmsg;
	void *retval;
	int n, m, r = 0;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		/* create our per-vhost struct */
		vhd = aws_lws_protocol_vh_priv_zalloc(aws_lws_get_vhost(wsi),
				aws_lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__minimal));
		if (!vhd)
			return 1;

		pthread_mutex_init(&vhd->lock_ring, NULL);

		/* recover the pointer to the globals struct */
		pvo = aws_lws_pvo_search(
			(const struct aws_lws_protocol_vhost_options *)in,
			"config");
		if (!pvo || !pvo->value) {
			aws_lwsl_err("%s: Can't find \"config\" pvo\n", __func__);
			return 1;
		}
		vhd->config = pvo->value;

		vhd->context = aws_lws_get_context(wsi);
		vhd->protocol = aws_lws_get_protocol(wsi);
		vhd->vhost = aws_lws_get_vhost(wsi);

		vhd->ring = aws_lws_ring_create(sizeof(struct msg), 8,
					    __minimal_destroy_message);
		if (!vhd->ring) {
			aws_lwsl_err("%s: failed to create ring\n", __func__);
			return 1;
		}

		/* start the content-creating threads */

		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
			if (pthread_create(&vhd->pthread_spam[n], NULL,
					   thread_spam, vhd)) {
				aws_lwsl_err("thread creation failed\n");
				r = 1;
				goto init_fail;
			}
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
init_fail:
		vhd->finished = 1;
		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
			if (vhd->pthread_spam[n])
				pthread_join(vhd->pthread_spam[n], &retval);

		if (vhd->ring)
			aws_lws_ring_destroy(vhd->ring);

		pthread_mutex_destroy(&vhd->lock_ring);
		break;

	case LWS_CALLBACK_ESTABLISHED:
		/* add ourselves to the list of live pss held in the vhd */
		aws_lws_ll_fwd_insert(pss, pss_list, vhd->pss_list);
		pss->tail = aws_lws_ring_get_oldest_tail(vhd->ring);
		pss->wsi = wsi;
		break;

	case LWS_CALLBACK_CLOSED:
		/* remove our closing pss from the list of live pss */
		aws_lws_ll_fwd_remove(struct per_session_data__minimal, pss_list,
				  pss, vhd->pss_list);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */

		pmsg = aws_lws_ring_get_element(vhd->ring, &pss->tail);
		if (!pmsg) {
			pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
			break;
		}

		/* notice we allowed for LWS_PRE in the payload already */
		m = aws_lws_write(wsi, ((unsigned char *)pmsg->payload) + LWS_PRE,
			      pmsg->len, LWS_WRITE_TEXT);
		if (m < (int)pmsg->len) {
			pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
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

		/* more to do? */
		if (aws_lws_ring_get_element(vhd->ring, &pss->tail))
			/* come back as soon as we can write more */
			aws_lws_callback_on_writable(pss->wsi);

		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
		break;

	case LWS_CALLBACK_RECEIVE:
		break;

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		if (!vhd)
			break;
		/*
		 * When the "spam" threads add a message to the ringbuffer,
		 * they create this event in the lws service thread context
		 * using aws_lws_cancel_service().
		 *
		 * We respond by scheduling a writable callback for all
		 * connected clients.
		 */
		aws_lws_start_foreach_llp(struct per_session_data__minimal **,
				      ppss, vhd->pss_list) {
			aws_lws_callback_on_writable((*ppss)->wsi);
		} aws_lws_end_foreach_llp(ppss, pss_list);
		break;

	default:
		break;
	}

	return r;
}

#define LWS_PLUGIN_PROTOCOL_MINIMAL \
	{ \
		"lws-minimal", \
		callback_minimal, \
		sizeof(struct per_session_data__minimal), \
		128, \
		0, NULL, 0 \
	}

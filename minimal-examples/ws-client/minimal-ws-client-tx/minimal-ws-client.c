/*
 * lws-minimal-ws-client-tx
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a ws "publisher" to go with the minimal-ws-broker
 * example.
 *
 * Two threads are spawned that produce messages to be sent to the broker,
 * via a local ringbuffer.  Locking is provided to make ringbuffer access
 * threadsafe.
 *
 * When a nailed-up client connection to the broker is established, the
 * ringbuffer is sent to the broker, which distributes the events to all
 * connected clients.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#if defined(WIN32)
#define HAVE_STRUCT_TIMESPEC
#if defined(pid_t)
#undef pid_t
#endif
#endif
#include <pthread.h>

static int interrupted;

/* one of these created for each message */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
};

struct per_vhost_data__minimal {
	struct aws_lws_context *context;
	struct aws_lws_vhost *vhost;
	const struct aws_lws_protocols *protocol;
	pthread_t pthread_spam[2];

	aws_lws_sorted_usec_list_t sul;

	pthread_mutex_t lock_ring; /* serialize access to the ring buffer */
	struct aws_lws_ring *ring; /* ringbuffer holding unsent messages */
	uint32_t tail;

	struct aws_lws_client_connect_info i;
	struct aws_lws *client_wsi;

	int counter;
	char finished;
	char established;
};

#if defined(WIN32)
static void usleep(unsigned long l) { Sleep(l / 1000); }
#endif

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

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
		/* don't generate output if client not connected */
		if (!vhd->established)
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
			         "tid: %d, msg: %d", whoami, index++);
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

static void
sul_connect_attempt(struct aws_lws_sorted_usec_list *sul)
{
	struct per_vhost_data__minimal *vhd =
		aws_lws_container_of(sul, struct per_vhost_data__minimal, sul);

	vhd->i.context = vhd->context;
	vhd->i.port = 7681;
	vhd->i.address = "localhost";
	vhd->i.path = "/publisher";
	vhd->i.host = vhd->i.address;
	vhd->i.origin = vhd->i.address;
	vhd->i.ssl_connection = 0;

	vhd->i.protocol = "lws-minimal-broker";
	vhd->i.pwsi = &vhd->client_wsi;

	if (!aws_lws_client_connect_via_info(&vhd->i))
		aws_lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, 10 * LWS_US_PER_SEC);
}

static int
callback_minimal_broker(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
			void *user, void *in, size_t len)
{
	struct per_vhost_data__minimal *vhd =
			(struct per_vhost_data__minimal *)
			aws_lws_protocol_vh_priv_get(aws_lws_get_vhost(wsi),
					aws_lws_get_protocol(wsi));
	const struct msg *pmsg;
	void *retval;
	int n, m, r = 0;

	switch (reason) {

	/* --- protocol lifecycle callbacks --- */

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

		pthread_mutex_init(&vhd->lock_ring, NULL);

		/* start the content-creating threads */

		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
			if (pthread_create(&vhd->pthread_spam[n], NULL,
					   thread_spam, vhd)) {
				aws_lwsl_err("thread creation failed\n");
				r = 1;
				goto init_fail;
			}

		sul_connect_attempt(&vhd->sul);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
init_fail:
		vhd->finished = 1;
		for (n = 0; n < (int)LWS_ARRAY_SIZE(vhd->pthread_spam); n++)
			pthread_join(vhd->pthread_spam[n], &retval);

		if (vhd->ring)
			aws_lws_ring_destroy(vhd->ring);

		aws_lws_sul_cancel(&vhd->sul);
		pthread_mutex_destroy(&vhd->lock_ring);

		return r;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		aws_lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		vhd->client_wsi = NULL;
		aws_lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, LWS_US_PER_SEC);
		break;

	/* --- client callbacks --- */

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		aws_lwsl_user("%s: established\n", __func__);
		vhd->established = 1;
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:
		pthread_mutex_lock(&vhd->lock_ring); /* --------- ring lock { */
		pmsg = aws_lws_ring_get_element(vhd->ring, &vhd->tail);
		if (!pmsg)
			goto skip;

		/* notice we allowed for LWS_PRE in the payload already */
		m = aws_lws_write(wsi, ((unsigned char *)pmsg->payload) + LWS_PRE,
			      pmsg->len, LWS_WRITE_TEXT);
		if (m < (int)pmsg->len) {
			pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock */
			aws_lwsl_err("ERROR %d writing to ws socket\n", m);
			return -1;
		}

		aws_lws_ring_consume_single_tail(vhd->ring, &vhd->tail, 1);

		/* more to do for us? */
		if (aws_lws_ring_get_element(vhd->ring, &vhd->tail))
			/* come back as soon as we can write more */
			aws_lws_callback_on_writable(wsi);

skip:
		pthread_mutex_unlock(&vhd->lock_ring); /* } ring lock ------- */
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		vhd->client_wsi = NULL;
		vhd->established = 0;
		aws_lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, LWS_US_PER_SEC);
		break;

	case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
		/*
		 * When the "spam" threads add a message to the ringbuffer,
		 * they create this event in the lws service thread context
		 * using aws_lws_cancel_service().
		 *
		 * We respond by scheduling a writable callback for the
		 * connected client, if any.
		 */
		if (vhd && vhd->client_wsi && vhd->established)
			aws_lws_callback_on_writable(vhd->client_wsi);
		break;

	default:
		break;
	}

	return aws_lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct aws_lws_protocols protocols[] = {
	{
		"lws-minimal-broker",
		callback_minimal_broker,
		0, 0, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int main(int argc, const char **argv)
{
	struct aws_lws_context_creation_info info;
	struct aws_lws_context *context;
	const char *p;
	int n = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
			/* for LLL_ verbosity above NOTICE to be built into lws,
			 * lws must have been configured and built with
			 * -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE */
			/* | LLL_INFO */ /* | LLL_PARSER */ /* | LLL_HEADER */
			/* | LLL_EXT */ /* | LLL_CLIENT */ /* | LLL_LATENCY */
			/* | LLL_DEBUG */;

	signal(SIGINT, sigint_handler);

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS minimal ws client tx\n");
	aws_lwsl_user("  Run minimal-ws-broker and browse to that\n");

	memset(&info, 0, sizeof info); /* otherwise uninitialized garbage */
	info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
	info.protocols = protocols;
	/*
	 * since we know this lws context is only ever going to be used with
	 * one client wsis / fds / sockets at a time, let lws know it doesn't
	 * have to use the default allocations for fd tables up to ulimit -n.
	 * It will just allocate for 1 internal and 1 (+ 1 http2 nwsi) that we
	 * will use.
	 */
	info.fd_limit_per_thread = 1 + 1 + 1;

	context = aws_lws_create_context(&info);
	if (!context) {
		aws_lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = aws_lws_service(context, 0);

	aws_lws_context_destroy(context);
	aws_lwsl_user("Completed\n");

	return 0;
}

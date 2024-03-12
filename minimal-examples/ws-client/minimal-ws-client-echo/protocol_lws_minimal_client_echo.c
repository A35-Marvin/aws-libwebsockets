/*
 * ws protocol handler plugin for "lws-minimal-client-echo"
 *
 * Written in 2010-2019 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The protocol shows how to send and receive bulk messages over a ws connection
 * that optionally may have the permessage-deflate extension negotiated on it.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

#define RING_DEPTH 1024

/* one of these created for each message */

struct msg {
	void *payload; /* is malloc'd */
	size_t len;
	char binary;
	char first;
	char final;
};

struct per_session_data__minimal_client_echo {
	struct aws_lws_ring *ring;
	uint32_t tail;
	char flow_controlled;
	uint8_t completed:1;
	uint8_t write_consume_pending:1;
};

struct vhd_minimal_client_echo {
	struct aws_lws_context *context;
	struct aws_lws_vhost *vhost;
	struct aws_lws *client_wsi;

	aws_lws_sorted_usec_list_t sul;

	int *interrupted;
	int *options;
	const char **url;
	const char **ads;
	const char **iface;
	int *port;
};

static void
sul_connect_attempt(struct aws_lws_sorted_usec_list *sul)
{
	struct vhd_minimal_client_echo *vhd =
		aws_lws_container_of(sul, struct vhd_minimal_client_echo, sul);
	struct aws_lws_client_connect_info i;
	char host[128];

	aws_lws_snprintf(host, sizeof(host), "%s:%u", *vhd->ads, *vhd->port);

	memset(&i, 0, sizeof(i));

	i.context = vhd->context;
	i.port = *vhd->port;
	i.address = *vhd->ads;
	i.path = *vhd->url;
	i.host = host;
	i.origin = host;
	i.ssl_connection = 0;
	if ((*vhd->options) & 2)
		i.ssl_connection |= LCCSCF_USE_SSL;
	i.vhost = vhd->vhost;
	i.iface = *vhd->iface;
	//i.protocol = ;
	i.pwsi = &vhd->client_wsi;

	aws_lwsl_user("connecting to %s:%d/%s\n", i.address, i.port, i.path);

	if (!aws_lws_client_connect_via_info(&i))
		aws_lws_sul_schedule(vhd->context, 0, &vhd->sul,
				 sul_connect_attempt, 10 * LWS_US_PER_SEC);
}

static void
__minimal_destroy_message(void *_msg)
{
	struct msg *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

static int
callback_minimal_client_echo(struct aws_lws *wsi, enum aws_lws_callback_reasons reason,
			  void *user, void *in, size_t len)
{
	struct per_session_data__minimal_client_echo *pss =
			(struct per_session_data__minimal_client_echo *)user;
	struct vhd_minimal_client_echo *vhd = (struct vhd_minimal_client_echo *)
			aws_lws_protocol_vh_priv_get(aws_lws_get_vhost(wsi),
				aws_lws_get_protocol(wsi));
	const struct msg *pmsg;
	struct msg amsg;
	int n, m, flags;

	switch (reason) {

	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = aws_lws_protocol_vh_priv_zalloc(aws_lws_get_vhost(wsi),
				aws_lws_get_protocol(wsi),
				sizeof(struct vhd_minimal_client_echo));
		if (!vhd)
			return -1;

		vhd->context = aws_lws_get_context(wsi);
		vhd->vhost = aws_lws_get_vhost(wsi);

		/* get the pointer to "interrupted" we were passed in pvo */
		vhd->interrupted = (int *)aws_lws_pvo_search(
			(const struct aws_lws_protocol_vhost_options *)in,
			"interrupted")->value;
		vhd->port = (int *)aws_lws_pvo_search(
			(const struct aws_lws_protocol_vhost_options *)in,
			"port")->value;
		vhd->options = (int *)aws_lws_pvo_search(
			(const struct aws_lws_protocol_vhost_options *)in,
			"options")->value;
		vhd->ads = (const char **)aws_lws_pvo_search(
			(const struct aws_lws_protocol_vhost_options *)in,
			"ads")->value;
		vhd->url = (const char **)aws_lws_pvo_search(
			(const struct aws_lws_protocol_vhost_options *)in,
			"url")->value;
		vhd->iface = (const char **)aws_lws_pvo_search(
			(const struct aws_lws_protocol_vhost_options *)in,
			"iface")->value;

		sul_connect_attempt(&vhd->sul);
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		aws_lws_sul_cancel(&vhd->sul);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		aws_lwsl_user("LWS_CALLBACK_CLIENT_ESTABLISHED\n");
		pss->ring = aws_lws_ring_create(sizeof(struct msg), RING_DEPTH,
					    __minimal_destroy_message);
		if (!pss->ring)
			return 1;
		pss->tail = 0;
		break;

	case LWS_CALLBACK_CLIENT_WRITEABLE:

		aws_lwsl_user("LWS_CALLBACK_CLIENT_WRITEABLE\n");

		if (pss->write_consume_pending) {
			/* perform the deferred fifo consume */
			aws_lws_ring_consume_single_tail(pss->ring, &pss->tail, 1);
			pss->write_consume_pending = 0;
		}
		pmsg = aws_lws_ring_get_element(pss->ring, &pss->tail);
		if (!pmsg) {
			aws_lwsl_user(" (nothing in ring)\n");
			break;
		}

		flags = aws_lws_write_ws_flags(
			    pmsg->binary ? LWS_WRITE_BINARY : LWS_WRITE_TEXT,
			    pmsg->first, pmsg->final);

		/* notice we allowed for LWS_PRE in the payload already */
		m = aws_lws_write(wsi, ((unsigned char *)pmsg->payload) +
			      LWS_PRE, pmsg->len, (enum aws_lws_write_protocol)flags);
		if (m < (int)pmsg->len) {
			aws_lwsl_err("ERROR %d writing to ws socket\n", m);
			return -1;
		}

		aws_lwsl_user(" wrote %d: flags: 0x%x first: %d final %d\n",
				m, flags, pmsg->first, pmsg->final);

		if ((*vhd->options & 1) && pmsg && pmsg->final)
			pss->completed = 1;

		/*
		 * Workaround deferred deflate in pmd extension by only
		 * consuming the fifo entry when we are certain it has been
		 * fully deflated at the next WRITABLE callback.  You only need
		 * this if you're using pmd.
		 */
		pss->write_consume_pending = 1;
		aws_lws_callback_on_writable(wsi);

		if (pss->flow_controlled &&
		    (int)aws_lws_ring_get_count_free_elements(pss->ring) > RING_DEPTH - 5) {
			aws_lws_rx_flow_control(wsi, 1);
			pss->flow_controlled = 0;
		}

		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:

		aws_lwsl_user("LWS_CALLBACK_CLIENT_RECEIVE: %4d (rpp %5d, first %d, last %d, bin %d)\n",
			(int)len, (int)aws_lws_remaining_packet_payload(wsi),
			aws_lws_is_first_fragment(wsi),
			aws_lws_is_final_fragment(wsi),
			aws_lws_frame_is_binary(wsi));

		// aws_lwsl_hexdump_notice(in, len);

		amsg.first = (char)aws_lws_is_first_fragment(wsi);
		amsg.final = (char)aws_lws_is_final_fragment(wsi);
		amsg.binary = (char)aws_lws_frame_is_binary(wsi);
		n = (int)aws_lws_ring_get_count_free_elements(pss->ring);
		if (!n) {
			aws_lwsl_user("dropping!\n");
			break;
		}

		amsg.len = len;
		/* notice we over-allocate by LWS_PRE */
		amsg.payload = malloc(LWS_PRE + len);
		if (!amsg.payload) {
			aws_lwsl_user("OOM: dropping\n");
			break;
		}

		memcpy((char *)amsg.payload + LWS_PRE, in, len);
		if (!aws_lws_ring_insert(pss->ring, &amsg, 1)) {
			__minimal_destroy_message(&amsg);
			aws_lwsl_user("dropping!\n");
			break;
		}
		aws_lws_callback_on_writable(wsi);

		if (!pss->flow_controlled && n < 3) {
			pss->flow_controlled = 1;
			aws_lws_rx_flow_control(wsi, 0);
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		aws_lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		vhd->client_wsi = NULL;
		if (!*vhd->interrupted)
			*vhd->interrupted = 3;
		aws_lws_cancel_service(aws_lws_get_context(wsi));
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		aws_lwsl_user("LWS_CALLBACK_CLIENT_CLOSED\n");
		aws_lws_ring_destroy(pss->ring);
		vhd->client_wsi = NULL;
		if (!*vhd->interrupted)
			*vhd->interrupted = 1 + pss->completed;
		aws_lws_cancel_service(aws_lws_get_context(wsi));
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_MINIMAL_CLIENT_ECHO \
	{ \
		"lws-minimal-client-echo", \
		callback_minimal_client_echo, \
		sizeof(struct per_session_data__minimal_client_echo), \
		1024, \
		0, NULL, 0 \
	}

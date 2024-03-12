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

#if !defined(__LWS_CORE_NET_PRIVATE_H__)
#define __LWS_CORE_NET_PRIVATE_H__

#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

/*
 * Generic pieces needed to manage muxable stream protocols like h2
 */

struct aws_lws_muxable {
	struct aws_lws	*parent_wsi;
	struct aws_lws	*child_list;
	struct aws_lws	*sibling_list;

	unsigned int	my_sid;
	unsigned int	child_count;

	uint32_t	highest_sid;

	uint8_t		requested_POLLOUT;
};

#include "private-lib-roles.h"

#ifdef __cplusplus
extern "C" {
#endif

#define aws___lws_sul_insert_us(owner, sul, _us) \
		(sul)->us = aws_lws_now_usecs() + (aws_lws_usec_t)(_us); \
		aws___lws_sul_insert(owner, sul)


/*
 *
 *  ------ roles ------
 *
 */

/* null-terminated array of pointers to roles lws built with */
extern const struct aws_lws_role_ops *aws_available_roles[];

#define LWS_FOR_EVERY_AVAILABLE_ROLE_START(xx) { \
		const struct aws_lws_role_ops **ppxx = aws_available_roles; \
		while (*ppxx) { \
			const struct aws_lws_role_ops *xx = *ppxx++;

#define LWS_FOR_EVERY_AVAILABLE_ROLE_END }}

/*
 *
 *  ------ event_loop ops ------
 *
 */

/* enums of socks version */
enum socks_version {
	SOCKS_VERSION_4 = 4,
	SOCKS_VERSION_5 = 5
};

/* enums of subnegotiation version */
enum socks_subnegotiation_version {
	SOCKS_SUBNEGOTIATION_VERSION_1 = 1,
};

/* enums of socks commands */
enum socks_command {
	SOCKS_COMMAND_CONNECT = 1,
	SOCKS_COMMAND_BIND = 2,
	SOCKS_COMMAND_UDP_ASSOCIATE = 3
};

/* enums of socks address type */
enum socks_atyp {
	SOCKS_ATYP_IPV4 = 1,
	SOCKS_ATYP_DOMAINNAME = 3,
	SOCKS_ATYP_IPV6 = 4
};

/* enums of socks authentication methods */
enum socks_auth_method {
	SOCKS_AUTH_NO_AUTH = 0,
	SOCKS_AUTH_GSSAPI = 1,
	SOCKS_AUTH_USERNAME_PASSWORD = 2
};

/* enums of subnegotiation status */
enum socks_subnegotiation_status {
	SOCKS_SUBNEGOTIATION_STATUS_SUCCESS = 0,
};

/* enums of socks request reply */
enum socks_request_reply {
	SOCKS_REQUEST_REPLY_SUCCESS = 0,
	SOCKS_REQUEST_REPLY_FAILURE_GENERAL = 1,
	SOCKS_REQUEST_REPLY_CONNECTION_NOT_ALLOWED = 2,
	SOCKS_REQUEST_REPLY_NETWORK_UNREACHABLE = 3,
	SOCKS_REQUEST_REPLY_HOST_UNREACHABLE = 4,
	SOCKS_REQUEST_REPLY_CONNECTION_REFUSED = 5,
	SOCKS_REQUEST_REPLY_TTL_EXPIRED = 6,
	SOCKS_REQUEST_REPLY_COMMAND_NOT_SUPPORTED = 7,
	SOCKS_REQUEST_REPLY_ATYP_NOT_SUPPORTED = 8
};

/* enums used to generate socks messages */
enum socks_msg_type {
	/* greeting */
	SOCKS_MSG_GREETING,
	/* credential, user name and password */
	SOCKS_MSG_USERNAME_PASSWORD,
	/* connect command */
	SOCKS_MSG_CONNECT
};

enum {
	LWS_RXFLOW_ALLOW = (1 << 0),
	LWS_RXFLOW_PENDING_CHANGE = (1 << 1),
};

typedef enum aws_lws_parser_return {
	LPR_FORBIDDEN	= -2,
	LPR_FAIL	= -1,
	LPR_OK		= 0,
	LPR_DO_FALLBACK = 2,
} aws_lws_parser_return_t;

enum pmd_return {
	PMDR_UNKNOWN,
	PMDR_DID_NOTHING,
	PMDR_HAS_PENDING,
	PMDR_EMPTY_NONFINAL,
	PMDR_EMPTY_FINAL,
	PMDR_NOTHING_WE_SHOULD_DO,

	PMDR_FAILED = -1
};

#if defined(LWS_WITH_PEER_LIMITS)
struct aws_lws_peer {
	struct aws_lws_peer *next;
	struct aws_lws_peer *peer_wait_list;

	aws_lws_sockaddr46	sa46;

	time_t time_created;
	time_t time_closed_all;

	uint32_t hash;
	uint32_t count_wsi;
	uint32_t total_wsi;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct aws_lws_peer_role_http http;
#endif
};
#endif

#ifdef LWS_WITH_IPV6
#define LWS_IPV6_ENABLED(vh) \
	(!aws_lws_check_opt(vh->context->options, LWS_SERVER_OPTION_DISABLE_IPV6) && \
	 !aws_lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_IPV6))
#else
#define LWS_IPV6_ENABLED(context) (0)
#endif

#ifdef LWS_WITH_UNIX_SOCK
#define LWS_UNIX_SOCK_ENABLED(vhost) \
	(vhost->options & LWS_SERVER_OPTION_UNIX_SOCK)
#else
#define LWS_UNIX_SOCK_ENABLED(vhost) (0)
#endif

enum uri_path_states {
	URIPS_IDLE,
	URIPS_SEEN_SLASH,
	URIPS_SEEN_SLASH_DOT,
	URIPS_SEEN_SLASH_DOT_DOT,
};

enum uri_esc_states {
	URIES_IDLE,
	URIES_SEEN_PERCENT,
	URIES_SEEN_PERCENT_H1,
};

#if defined(LWS_WITH_CLIENT)

enum {
	CIS_ADDRESS,
	CIS_PATH,
	CIS_HOST,
	CIS_ORIGIN,
	CIS_PROTOCOL,
	CIS_METHOD,
	CIS_IFACE,
	CIS_ALPN,


	CIS_COUNT
};

struct client_info_stash {
	char *cis[CIS_COUNT];
	void *opaque_user_data; /* not allocated or freed by lws */
};
#endif

#if defined(LWS_WITH_UDP)
#define aws_lws_wsi_is_udp(___wsi) (!!___wsi->udp)
#endif

#define LWS_H2_FRAME_HEADER_LENGTH 9

aws_lws_usec_t
aws___lws_sul_service_ripe(aws_lws_dll2_owner_t *own, int num_own, aws_lws_usec_t usnow);

/*
 * aws_lws_async_dns
 */

typedef struct aws_lws_async_dns {
	aws_lws_sockaddr46 		sa46; /* nameserver */
	aws_lws_dll2_owner_t	waiting;
	aws_lws_dll2_owner_t	cached;
	struct aws_lws		*wsi;
	time_t			time_set_server;
	uint8_t			dns_server_set:1;
	uint8_t			dns_server_connected:1;
} aws_lws_async_dns_t;

typedef enum {
	LADNS_CONF_SERVER_UNKNOWN				= -1,
	LADNS_CONF_SERVER_SAME,
	LADNS_CONF_SERVER_CHANGED
} aws_lws_async_dns_server_check_t;

#if defined(LWS_WITH_SYS_ASYNC_DNS)
void
aws_lws_aysnc_dns_completed(struct aws_lws *wsi, void *sa, size_t salen,
			aws_lws_async_dns_retcode_t ret);
#endif
void
aws_lws_async_dns_cancel(struct aws_lws *wsi);

void
aws_lws_async_dns_drop_server(struct aws_lws_context *context);

/*
 * so we can have n connections being serviced simultaneously,
 * these things need to be isolated per-thread.
 */

struct aws_lws_context_per_thread {
#if LWS_MAX_SMP > 1
	pthread_mutex_t lock_stats;
	struct aws_lws_mutex_refcount mr;
	pthread_t self;
#endif
	struct aws_lws_dll2_owner dll_buflist_owner;  /* guys with pending rxflow */
	struct aws_lws_dll2_owner seq_owner;	   /* list of aws_lws_sequencer-s */
	aws_lws_dll2_owner_t      attach_owner;	/* pending aws_lws_attach */

#if defined(LWS_WITH_SECURE_STREAMS)
	aws_lws_dll2_owner_t ss_owner;
#endif
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API) || \
    defined(LWS_WITH_SECURE_STREAMS_THREAD_API)
	aws_lws_dll2_owner_t ss_dsh_owner;
	aws_lws_dll2_owner_t ss_client_owner;
#endif

	struct aws_lws_dll2_owner pt_sul_owner[LWS_COUNT_PT_SUL_OWNERS];

#if defined (LWS_WITH_SEQUENCER)
	aws_lws_sorted_usec_list_t sul_seq_heartbeat;
#endif
#if (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)) && defined(LWS_WITH_SERVER)
	aws_lws_sorted_usec_list_t sul_ah_lifecheck;
#endif
#if defined(LWS_WITH_TLS) && defined(LWS_WITH_SERVER)
	aws_lws_sorted_usec_list_t sul_tls;
#endif
#if defined(LWS_PLAT_UNIX)
	aws_lws_sorted_usec_list_t sul_plat;
#endif
#if defined(LWS_ROLE_CGI)
	aws_lws_sorted_usec_list_t sul_cgi;
#endif
#if defined(LWS_WITH_PEER_LIMITS)
	aws_lws_sorted_usec_list_t sul_peer_limits;
#endif

#if !defined(LWS_PLAT_FREERTOS)
	struct aws_lws *fake_wsi;   /* used for callbacks where there's no wsi */
#endif

#if defined(WIN32)
	struct sockaddr_in frt_pipe_si;
#endif

#if defined(LWS_WITH_TLS)
	struct aws_lws_pt_tls tls;
#endif
	struct aws_lws_context *context;

	/*
	 * usable by anything in the service code, but only if the scope
	 * does not last longer than the service action (since next service
	 * of any socket can likewise use it and overwrite)
	 */
	unsigned char *serv_buf;

	struct aws_lws_pollfd *fds;
	volatile struct aws_lws_foreign_thread_pollfd * volatile foreign_pfd_list;

	aws_lws_sockfd_type dummy_pipe_fds[2];
	struct aws_lws *pipe_wsi;

	/* --- role based members --- */

#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	struct aws_lws_pt_role_ws ws;
#endif
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct aws_lws_pt_role_http http;
#endif
#if defined(LWS_ROLE_DBUS)
	struct aws_lws_pt_role_dbus dbus;
#endif
	/* --- event library based members --- */

	void		*evlib_pt; /* overallocated */

	/* --- */

	unsigned long count_conns;
	unsigned int fds_count;

	/*
	 * set to the Thread ID that's doing the service loop just before entry
	 * to poll indicates service thread likely idling in poll()
	 * volatile because other threads may check it as part of processing
	 * for pollfd event change.
	 */
	volatile int service_tid;
	int service_tid_detected;
#if !defined(LWS_PLAT_FREERTOS)
	int count_event_loop_static_asset_handles;
#endif

	volatile unsigned char inside_poll;
	volatile unsigned char foreign_spinlock;

	unsigned char tid;

	unsigned char inside_service:1;
	unsigned char inside_lws_service:1;
	unsigned char event_loop_foreign:1;
	unsigned char event_loop_destroy_processing_done:1;
	unsigned char event_loop_pt_unused:1;
	unsigned char destroy_self:1;
	unsigned char is_destroyed:1;
};

/*
 * virtual host -related context information
 *   vhostwide SSL context
 *   vhostwide proxy
 *
 * hierarchy:
 *
 * context -> vhost -> wsi
 *
 * incoming connection non-SSL vhost binding:
 *
 *    listen socket -> wsi -> select vhost after first headers
 *
 * incoming connection SSL vhost binding:
 *
 *    SSL SNI -> wsi -> bind after SSL negotiation
 */

struct aws_lws_vhost {
#if defined(LWS_WITH_CLIENT) && defined(LWS_CLIENT_HTTP_PROXYING)
	char proxy_basic_auth_token[128];
#endif
#if LWS_MAX_SMP > 1
	struct aws_lws_mutex_refcount		mr;
	char					close_flow_vs_tsi[LWS_MAX_SMP];
#endif

#if defined(LWS_ROLE_H2)
	struct aws_lws_vhost_role_h2 h2;
#endif
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct aws_lws_vhost_role_http http;
#endif
#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	struct aws_lws_vhost_role_ws ws;
#endif

	aws_lws_lifecycle_t		lc;
	aws_lws_dll2_t		vh_being_destroyed_list;

#if defined(LWS_WITH_SOCKS5)
	char socks_proxy_address[128];
	char socks_user[96];
	char socks_password[96];
#endif

#if defined(LWS_WITH_TLS_SESSIONS)
	aws_lws_dll2_owner_t	tls_sessions; /* vh lock */
#endif

#if defined(LWS_WITH_EVENT_LIBS)
	void		*evlib_vh; /* overallocated */
#endif
#if defined(LWS_WITH_SYS_METRICS)
	aws_lws_metric_t	*mt_traffic_rx;
	aws_lws_metric_t	*mt_traffic_tx;
#endif

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	aws_lws_fi_ctx_t				fic;
	/**< Fault Injection ctx for the vhost, hierarchy vhost->context */
#endif

	uint64_t options;

	struct aws_lws_context *context;
	struct aws_lws_vhost *vhost_next;

	const aws_lws_retry_bo_t *retry_policy;

#if defined(LWS_WITH_TLS_JIT_TRUST)
	aws_lws_sorted_usec_list_t		sul_unref; /* grace period after idle */
#endif

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_SECURE_STREAMS)
	aws_lws_ss_handle_t		*ss_handle; /* ss handle for the server obj */
#endif

	aws_lws_dll2_owner_t	listen_wsi;

	const char *name;
	const char *iface;
	const char *listen_accept_role;
	const char *listen_accept_protocol;
	const char *unix_socket_perms;

	void (*finalize)(struct aws_lws_vhost *vh, void *arg);
	void *finalize_arg;

	const struct aws_lws_protocols *protocols;
	void **protocol_vh_privs;
	const struct aws_lws_protocol_vhost_options *pvo;
	const struct aws_lws_protocol_vhost_options *headers;
	struct aws_lws_dll2_owner *same_vh_protocol_owner;
	struct aws_lws_vhost *no_listener_vhost_list;
	struct aws_lws_dll2_owner abstract_instances_owner;		/* vh lock */

#if defined(LWS_WITH_CLIENT)
	struct aws_lws_dll2_owner dll_cli_active_conns_owner;
#endif
	struct aws_lws_dll2_owner vh_awaiting_socket_owner;

#if defined(LWS_WITH_TLS)
	struct aws_lws_vhost_tls tls;
#endif

	void *user;

	int listen_port;
#if !defined(LWS_PLAT_FREERTOS) && !defined(OPTEE_TA) && !defined(WIN32)
	int bind_iface;
#endif

#if defined(LWS_WITH_SOCKS5)
	unsigned int socks_proxy_port;
#endif
	int count_protocols;
	int ka_time;
	int ka_probes;
	int ka_interval;
	int keepalive_timeout;
	int timeout_secs_ah_idle;
	int connect_timeout_secs;
	int fo_listen_queue;

	int count_bound_wsi;

#ifdef LWS_WITH_ACCESS_LOG
	int log_fd;
#endif

#if defined(LWS_WITH_TLS_SESSIONS)
	uint32_t		tls_session_cache_max;
#endif

#if defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY) || defined(LWS_WITH_SECURE_STREAMS_CPP)
	int8_t			ss_refcount;
	/**< refcount of number of ss connections with streamtypes using this
	 * trust store */
#endif

	uint8_t allocated_vhost_protocols:1;
	uint8_t created_vhost_protocols:1;
	uint8_t being_destroyed:1;
	uint8_t from_ss_policy:1;
#if defined(LWS_WITH_TLS_JIT_TRUST)
	uint8_t 		grace_after_unref:1;
	/* grace time / autodelete aoplies to us */
#endif

	unsigned char default_protocol_index;
	unsigned char raw_protocol_index;
};

void
aws___lws_vhost_destroy2(struct aws_lws_vhost *vh);

#define mux_to_wsi(_m) aws_lws_container_of(_m, struct aws_lws, mux)

void
aws_lws_wsi_mux_insert(struct aws_lws *wsi, struct aws_lws *parent_wsi, unsigned int sid);
int
aws_lws_wsi_mux_mark_parents_needing_writeable(struct aws_lws *wsi);
struct aws_lws *
aws_lws_wsi_mux_move_child_to_tail(struct aws_lws **wsi2);
int
aws_lws_wsi_mux_action_pending_writeable_reqs(struct aws_lws *wsi);

void
aws_lws_wsi_mux_dump_children(struct aws_lws *wsi);

void
aws_lws_wsi_mux_close_children(struct aws_lws *wsi, int reason);

void
aws_lws_wsi_mux_sibling_disconnect(struct aws_lws *wsi);

void
aws_lws_wsi_mux_dump_waiting_children(struct aws_lws *wsi);

int
aws_lws_wsi_mux_apply_queue(struct aws_lws *wsi);

/*
 * struct aws_lws
 */

/*
 * These pieces are very commonly used (via accessors) in user protocol handlers
 * and have to be valid, even in the case no real wsi is available for the cb.
 *
 * We put all this category of pointers in there and compose it at the top of
 * struct aws_lws, so a dummy wsi providing these only needs to be this big, while
 * still being castable for being a struct wsi *
 */

struct aws_lws_a {
	struct aws_lws_context		*context;
	struct aws_lws_vhost		*vhost;
	const struct aws_lws_protocols	*protocol;
	void				*opaque_user_data;
};

/*
 * For RTOS-class platforms, their code is relatively new, post-minimal examples
 * and tend to not have legacy user protocol handler baggage touching unexpected
 * things in fakewsi unconditionally... we can use an aws_lws_a on the stack and
 * don't need to define the rest of the wsi content, just cast it, this saves
 * a wsi footprint in heap (typ 800 bytes nowadays even on RTOS).
 *
 * For other platforms that have been around for years and have thousands of
 * different user protocol handler implementations, it's likely some of them
 * will be touching the struct aws_lws content unconditionally in the handler even
 * when we are calling back with a non wsi-specific reason, and may react badly
 * to it being garbage.  So continue to implement those as a full, zero-ed down
 * prepared fakewsi on heap at context creation time.
 */

#if defined(LWS_PLAT_FREERTOS)
#define aws_lws_fakewsi_def_plwsa(pt) struct aws_lws_a aws_lwsa, *plwsa = &aws_lwsa
#else
#define aws_lws_fakewsi_def_plwsa(pt) struct aws_lws_a *plwsa = &(pt)->fake_wsi->a
#endif
/* since we reuse the pt version, also correct to zero down the aws_lws_a part */
#define aws_lws_fakewsi_prep_plwsa_ctx(_c) \
		memset(plwsa, 0, sizeof(*plwsa)); plwsa->context = _c

struct aws_lws {

	struct aws_lws_a			a;

	/* structs */

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct aws__lws_http_mode_related	http;
#endif
#if defined(LWS_ROLE_H2)
	struct aws__lws_h2_related		h2;
#endif
#if defined(LWS_ROLE_WS)
	struct aws__lws_websocket_related	*ws; /* allocated if we upgrade to ws */
#endif
#if defined(LWS_ROLE_DBUS)
	struct aws__lws_dbus_mode_related	dbus;
#endif
#if defined(LWS_ROLE_MQTT)
	struct aws__lws_mqtt_related	*mqtt;
#endif

#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_MQTT)
	struct aws_lws_muxable		mux;
	struct aws_lws_tx_credit		txc;
#endif

	aws_lws_lifecycle_t			lc;

	/* lifetime members */

#if defined(LWS_WITH_EVENT_LIBS)
	void				*evlib_wsi; /* overallocated */
#endif

	aws_lws_sorted_usec_list_t		sul_timeout;
	aws_lws_sorted_usec_list_t		sul_hrtimer;
	aws_lws_sorted_usec_list_t		sul_validity;
	aws_lws_sorted_usec_list_t		sul_connect_timeout;

	struct aws_lws_dll2			dll_buflist; /* guys with pending rxflow */
	struct aws_lws_dll2			same_vh_protocol;
	struct aws_lws_dll2			vh_awaiting_socket;
#if defined(LWS_WITH_SYS_ASYNC_DNS)
	struct aws_lws_dll2			adns; /* on adns list of guys to tell result */
	aws_lws_async_dns_cb_t		adns_cb; /* callback with result */
#endif
#if defined(LWS_WITH_SERVER)
	struct aws_lws_dll2			listen_list;
#endif
#if defined(LWS_WITH_CLIENT)
	struct aws_lws_dll2			dll_cli_active_conns;
	struct aws_lws_dll2			dll2_cli_txn_queue;
	struct aws_lws_dll2_owner		dll2_cli_txn_queue_owner;

	/**< caliper is reused for tcp, tls and txn conn phases */

	aws_lws_dll2_t			speculative_list;
	aws_lws_dll2_owner_t		speculative_connect_owner;
	/* wsis: additional connection candidates */
	aws_lws_dll2_owner_t		dns_sorted_list;
	/* aws_lws_dns_sort_t: dns results wrapped and sorted in a linked-list...
	 * deleted as they are tried, list empty == everything tried */
#endif

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	aws_lws_fi_ctx_t			fic;
	/**< Fault Injection ctx for the wsi, hierarchy wsi->vhost->context */
	aws_lws_sorted_usec_list_t		sul_fault_timedclose;
	/**< used to inject a fault that closes the wsi after a random time */
#endif

#if defined(LWS_WITH_SYS_METRICS)
	aws_lws_metrics_caliper_compose(cal_conn)
#endif

	aws_lws_sockaddr46			sa46_local;
	aws_lws_sockaddr46			sa46_peer;

	/* pointers */

	struct aws_lws			*parent; /* points to parent, if any */
	struct aws_lws			*child_list; /* points to first child */
	struct aws_lws			*sibling_list; /* subsequent children at same level */
	const struct aws_lws_role_ops	*role_ops;
	struct aws_lws_sequencer		*seq;	/* associated sequencer if any */
	const aws_lws_retry_bo_t		*retry_policy;

	aws_lws_log_cx_t			*log_cx;

#if defined(LWS_WITH_THREADPOOL)
	aws_lws_dll2_owner_t		tp_task_owner; /* struct aws_lws_threadpool_task */
#endif

#if defined(LWS_WITH_PEER_LIMITS)
	struct aws_lws_peer			*peer;
#endif

#if defined(LWS_WITH_UDP)
	struct aws_lws_udp			*udp;
#endif
#if defined(LWS_WITH_CLIENT)
	struct client_info_stash	*stash;
	char				*cli_hostname_copy;

#if defined(LWS_WITH_CONMON)
	struct aws_lws_conmon		conmon;
	aws_lws_usec_t			conmon_datum;
#endif
#endif /* WITH_CLIENT */
	void				*user_space;
	void				*opaque_parent_data;

	struct aws_lws_buflist		*buflist; /* input-side buflist */
	struct aws_lws_buflist		*buflist_out; /* output-side buflist */

#if defined(LWS_WITH_TLS)
	struct aws_lws_lws_tls		tls;
	char				alpn[24];
#endif

	aws_lws_sock_file_fd_type		desc; /* .filefd / .sockfd */

	aws_lws_wsi_state_t			wsistate;
	aws_lws_wsi_state_t			wsistate_pre_close;

	/* ints */
#define LWS_NO_FDS_POS (-1)
	int				position_in_fds_table;

#if defined(LWS_WITH_CLIENT)
	int				chunk_remaining;
	int				flags;
#endif
	unsigned int			cache_secs;

	short				bugcatcher;

	unsigned int			hdr_parsing_completed:1;
	unsigned int			mux_substream:1;
	unsigned int			upgraded_to_http2:1;
	unsigned int			mux_stream_immortal:1;
	unsigned int			h2_stream_carries_ws:1; /* immortal set as well */
	unsigned int			h2_stream_carries_sse:1; /* immortal set as well */
	unsigned int			h2_acked_settings:1;
	unsigned int			seen_nonpseudoheader:1;
	unsigned int			listener:1;
	unsigned int			pf_packet:1;
	unsigned int			do_broadcast:1;
	unsigned int			user_space_externally_allocated:1;
	unsigned int			socket_is_permanently_unusable:1;
	unsigned int			rxflow_change_to:2;
	unsigned int			conn_stat_done:1;
	unsigned int			cache_reuse:1;
	unsigned int			cache_revalidate:1;
	unsigned int			cache_intermediaries:1;
	unsigned int			favoured_pollin:1;
	unsigned int			sending_chunked:1;
	unsigned int			interpreting:1;
	unsigned int			already_did_cce:1;
	unsigned int			told_user_closed:1;
	unsigned int			told_event_loop_closed:1;
	unsigned int			waiting_to_send_close_frame:1;
	unsigned int			close_needs_ack:1;
	unsigned int			ipv6:1;
	unsigned int			parent_pending_cb_on_writable:1;
	unsigned int			cgi_stdout_zero_length:1;
	unsigned int			seen_zero_length_recv:1;
	unsigned int			rxflow_will_be_applied:1;
	unsigned int			event_pipe:1;
	unsigned int			handling_404:1;
	unsigned int			protocol_bind_balance:1;
	unsigned int			unix_skt:1;
	unsigned int			close_when_buffered_out_drained:1;
	unsigned int			h1_ws_proxied:1;
	unsigned int			proxied_ws_parent:1;
	unsigned int			do_bind:1;
	unsigned int			validity_hup:1;
	unsigned int			skip_fallback:1;
	unsigned int			file_desc:1;
	unsigned int			conn_validity_wakesuspend:1;
	unsigned int			dns_reachability:1;

	unsigned int			could_have_pending:1; /* detect back-to-back writes */
	unsigned int			outer_will_close:1;
	unsigned int			shadow:1; /* we do not control fd lifecycle at all */
#if defined(LWS_WITH_SECURE_STREAMS)
	unsigned int			for_ss:1;
	unsigned int			bound_ss_proxy_conn:1;
	unsigned int			client_bound_sspc:1;
	unsigned int			client_proxy_onward:1;
#endif
	unsigned int                    tls_borrowed:1;
	unsigned int                    tls_borrowed_hs:1;
	unsigned int                    tls_read_wanted_write:1;

#ifdef LWS_WITH_ACCESS_LOG
	unsigned int			access_log_pending:1;
#endif
#if defined(LWS_WITH_CLIENT)
	unsigned int			do_ws:1; /* whether we are doing http or ws flow */
	unsigned int			chunked:1; /* if the clientside connection is chunked */
	unsigned int			client_rx_avail:1;
	unsigned int			client_http_body_pending:1;
	unsigned int			transaction_from_pipeline_queue:1;
	unsigned int			keepalive_active:1;
	unsigned int			keepalive_rejected:1;
	unsigned int			redirected_to_get:1;
	unsigned int			client_pipeline:1;
	unsigned int			client_h2_alpn:1;
	unsigned int			client_mux_substream:1;
	unsigned int			client_mux_migrated:1;
	unsigned int			client_subsequent_mime_part:1;
	unsigned int                    client_no_follow_redirect:1;
	unsigned int                    client_suppress_CONNECTION_ERROR:1;
	/**< because the client connection creation api is still the parent of
	 * this activity, and will report the failure */
	unsigned int			tls_session_reused:1;
	unsigned int			perf_done:1;
	unsigned int			close_is_redirect:1;
	unsigned int			client_mux_substream_was:1;
#endif

#ifdef _WIN32
	unsigned int sock_send_blocking:1;
#endif

	uint16_t			ocport, c_port, conn_port;
	uint16_t			retry;
#if defined(LWS_WITH_CLIENT)
	uint16_t			keep_warm_secs;
#endif

	/* chars */

	char aws_lws_rx_parse_state; /* enum aws_lws_rx_parse_state */
	char rx_frame_type; /* enum aws_lws_write_protocol */
	char pending_timeout; /* enum pending_timeout */
	char tsi; /* thread service index we belong to */
	char protocol_interpret_idx;
	char redirects;
	uint8_t rxflow_bitmap;
	uint8_t bound_vhost_index;
	uint8_t lsp_channel; /* which of stdin/out/err */
#ifdef LWS_WITH_CGI
	char hdr_state;
#endif
#if defined(LWS_WITH_CLIENT)
	char chunk_parser; /* enum aws_lws_chunk_parser */
	uint8_t addrinfo_idx;
	uint8_t sys_tls_client_cert;
	uint8_t c_pri;
#endif
	uint8_t		af;
#if defined(LWS_WITH_CGI) || defined(LWS_WITH_CLIENT)
	char reason_bf; /* internal writeable callback reason bitfield */
#endif
#if defined(LWS_WITH_NETLINK)
	aws_lws_route_uidx_t		peer_route_uidx;
	/**< unique index of the route the connection is estimated to take */
#endif
	uint8_t immortal_substream_count;
	/* volatile to make sure code is aware other thread can change */
	volatile char handling_pollout;
	volatile char leave_pollout_active;
#if LWS_MAX_SMP > 1
	volatile char undergoing_init_from_other_pt;
#endif

};

#define aws_lws_is_flowcontrolled(w) (!!(wsi->rxflow_bitmap))

#if defined(LWS_WITH_SPAWN)

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#include <sys/times.h>
#endif

struct aws_lws_spawn_piped {

	struct aws_lws_spawn_piped_info	info;

	struct aws_lws_dll2			dll;
	aws_lws_sorted_usec_list_t		sul;
	aws_lws_sorted_usec_list_t		sul_reap;

	struct aws_lws_context		*context;
	struct aws_lws			*stdwsi[3];
	aws_lws_filefd_type			pipe_fds[3][2];
	int				count_log_lines;

	aws_lws_usec_t			created; /* set by aws_lws_spawn_piped() */
	aws_lws_usec_t			reaped;

	aws_lws_usec_t			accounting[4];

#if defined(WIN32)
	HANDLE				child_pid;
	aws_lws_sorted_usec_list_t		sul_poll;
#else
	pid_t				child_pid;

	siginfo_t			si;
#endif
	int				reap_retry_budget;

	uint8_t				pipes_alive:2;
	uint8_t				we_killed_him_timeout:1;
	uint8_t				we_killed_him_spew:1;
	uint8_t				ungraceful:1;
};

void
aws_lws_spawn_piped_destroy(struct aws_lws_spawn_piped **lsp);

int
aws_lws_spawn_reap(struct aws_lws_spawn_piped *lsp);

#endif

void
aws_lws_service_do_ripe_rxflow(struct aws_lws_context_per_thread *pt);

const struct aws_lws_role_ops *
aws_lws_role_by_name(const char *name);

int
aws_lws_socket_bind(struct aws_lws_vhost *vhost, struct aws_lws *wsi,
		aws_lws_sockfd_type sockfd, int port, const char *iface,
		int ipv6_allowed);

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
void
aws_lws_wsi_fault_timedclose(struct aws_lws *wsi);
#else
#define aws_lws_wsi_fault_timedclose(_w)
#endif

#if defined(LWS_WITH_IPV6)
unsigned long
aws_lws_get_addr_scope(struct aws_lws *wsi, const char *ipaddr);
#endif

void
aws_lws_close_free_wsi(struct aws_lws *wsi, enum aws_lws_close_status, const char *caller);
void
aws___lws_close_free_wsi(struct aws_lws *wsi, enum aws_lws_close_status, const char *caller);

void
aws___lws_free_wsi(struct aws_lws *wsi);

void
aws_lws_conmon_addrinfo_destroy(struct addrinfo *ai);

int
aws_lws_conmon_append_copy_new_dns_results(struct aws_lws *wsi,
				       const struct addrinfo *cai);

#if LWS_MAX_SMP > 1

static LWS_INLINE void
aws_lws_pt_mutex_init(struct aws_lws_context_per_thread *pt)
{
	aws_lws_mutex_refcount_init(&pt->mr);
	pthread_mutex_init(&pt->lock_stats, NULL);
}

static LWS_INLINE void
aws_lws_pt_mutex_destroy(struct aws_lws_context_per_thread *pt)
{
	pthread_mutex_destroy(&pt->lock_stats);
	aws_lws_mutex_refcount_destroy(&pt->mr);
}

#define aws_lws_pt_lock(pt, reason) aws_lws_mutex_refcount_lock(&pt->mr, reason)
#define aws_lws_pt_unlock(pt) aws_lws_mutex_refcount_unlock(&pt->mr)
#define aws_lws_pt_assert_lock_held(pt) aws_lws_mutex_refcount_assert_held(&pt->mr)

static LWS_INLINE void
aws_lws_pt_stats_lock(struct aws_lws_context_per_thread *pt)
{
	pthread_mutex_lock(&pt->lock_stats);
}

static LWS_INLINE void
aws_lws_pt_stats_unlock(struct aws_lws_context_per_thread *pt)
{
	pthread_mutex_unlock(&pt->lock_stats);
}
#endif

/*
 * EXTENSIONS
 */

#if defined(LWS_WITHOUT_EXTENSIONS)
#define aws_lws_any_extension_handled(_a, _b, _c, _d) (0)
#define aws_lws_ext_cb_active(_a, _b, _c, _d) (0)
#define aws_lws_ext_cb_all_exts(_a, _b, _c, _d, _e) (0)
#define aws_lws_issue_raw_ext_access aws_lws_issue_raw
#define aws_lws_context_init_extensions(_a, _b)
#endif

int LWS_WARN_UNUSED_RESULT
aws_lws_client_interpret_server_handshake(struct aws_lws *wsi);

int LWS_WARN_UNUSED_RESULT
aws_lws_ws_rx_sm(struct aws_lws *wsi, char already_processed, unsigned char c);

int LWS_WARN_UNUSED_RESULT
aws_lws_issue_raw_ext_access(struct aws_lws *wsi, unsigned char *buf, size_t len);

void
aws_lws_role_transition(struct aws_lws *wsi, enum aws_lwsi_role role, enum aws_lwsi_state state,
		    const struct aws_lws_role_ops *ops);

int
aws_lws_http_to_fallback(struct aws_lws *wsi, unsigned char *buf, size_t len);

int LWS_WARN_UNUSED_RESULT
aws_user_callback_handle_rxflow(aws_lws_callback_function, struct aws_lws *wsi,
			    enum aws_lws_callback_reasons reason, void *user,
			    void *in, size_t len);

int
aws_lws_plat_set_nonblocking(aws_lws_sockfd_type fd);

int
aws_lws_plat_set_socket_options(struct aws_lws_vhost *vhost, aws_lws_sockfd_type fd,
			    int unix_skt);

int
aws_lws_plat_set_socket_options_ip(aws_lws_sockfd_type fd, uint8_t pri, int aws_lws_flags);

int
aws_lws_plat_check_connection_error(struct aws_lws *wsi);

int LWS_WARN_UNUSED_RESULT
aws_lws_header_table_attach(struct aws_lws *wsi, int autoservice);

int
aws_lws_header_table_detach(struct aws_lws *wsi, int autoservice);
int
aws___lws_header_table_detach(struct aws_lws *wsi, int autoservice);

void
aws_lws_header_table_reset(struct aws_lws *wsi, int autoservice);

void
aws___lws_header_table_reset(struct aws_lws *wsi, int autoservice);

char * LWS_WARN_UNUSED_RESULT
aws_lws_hdr_simple_ptr(struct aws_lws *wsi, enum aws_lws_token_indexes h);

int LWS_WARN_UNUSED_RESULT
aws_lws_hdr_simple_create(struct aws_lws *wsi, enum aws_lws_token_indexes h, const char *s);

int LWS_WARN_UNUSED_RESULT
aws_lws_ensure_user_space(struct aws_lws *wsi);

int LWS_WARN_UNUSED_RESULT
aws_lws_change_pollfd(struct aws_lws *wsi, int _and, int _or);

#if defined(LWS_WITH_SERVER)
 int aws__lws_vhost_init_server(const struct aws_lws_context_creation_info *info,
			      struct aws_lws_vhost *vhost);
struct aws_lws_vhost *
 aws_lws_select_vhost(struct aws_lws_context *context, int port, const char *servername);
int LWS_WARN_UNUSED_RESULT
 aws_lws_parse_ws(struct aws_lws *wsi, unsigned char **buf, size_t len);
void
 aws_lws_server_get_canonical_hostname(struct aws_lws_context *context,
				   const struct aws_lws_context_creation_info *info);
#else
 #define aws__lws_vhost_init_server(_a, _b) (0)
 #define aws_lws_parse_ws(_a, _b, _c) (0)
 #define aws_lws_server_get_canonical_hostname(_a, _b)
#endif

int
aws___remove_wsi_socket_from_fds(struct aws_lws *wsi);

enum {
	LWSRXFC_ERROR = -1,
	LWSRXFC_CACHED = 0,
	LWSRXFC_ADDITIONAL = 1,
	LWSRXFC_TRIMMED = 2,
};


int
aws__lws_plat_service_forced_tsi(struct aws_lws_context *context, int tsi);

int
aws_lws_rxflow_cache(struct aws_lws *wsi, unsigned char *buf, size_t n, size_t len);

int
aws_lws_service_flag_pending(struct aws_lws_context *context, int tsi);

int
aws_lws_has_buffered_out(struct aws_lws *wsi);

int LWS_WARN_UNUSED_RESULT
aws_lws_ws_client_rx_sm(struct aws_lws *wsi, unsigned char c);

aws_lws_parser_return_t LWS_WARN_UNUSED_RESULT
aws_lws_parse(struct aws_lws *wsi, unsigned char *buf, int *len);

int LWS_WARN_UNUSED_RESULT
aws_lws_parse_urldecode(struct aws_lws *wsi, uint8_t *_c);

void
aws_lws_sa46_copy_address(aws_lws_sockaddr46 *sa46a, const void *in, int af);

int LWS_WARN_UNUSED_RESULT
aws_lws_http_action(struct aws_lws *wsi);

void
aws___lws_close_free_wsi_final(struct aws_lws *wsi);
void
aws_lws_libuv_closehandle(struct aws_lws *wsi);
int
aws_lws_libuv_check_watcher_active(struct aws_lws *wsi);

#if defined(LWS_WITH_EVLIB_PLUGINS) || defined(LWS_WITH_PLUGINS)
const aws_lws_plugin_header_t *
aws_lws_plat_dlopen(struct aws_lws_plugin **pplugin, const char *libpath,
		const char *sofilename, const char *_class,
		each_plugin_cb_t each, void *each_user);

int
aws_lws_plat_destroy_dl(struct aws_lws_plugin *p);
#endif

struct aws_lws *
aws_lws_adopt_socket_vhost(struct aws_lws_vhost *vh, aws_lws_sockfd_type accept_fd);

void
aws_lws_vhost_bind_wsi(struct aws_lws_vhost *vh, struct aws_lws *wsi);
void
aws___lws_vhost_unbind_wsi(struct aws_lws *wsi); /* req cx + vh lock */

void
aws___lws_set_timeout(struct aws_lws *wsi, enum pending_timeout reason, int secs);
int
aws___lws_change_pollfd(struct aws_lws *wsi, int _and, int _or);


int
aws_lws_callback_as_writeable(struct aws_lws *wsi);

int
aws_lws_role_call_client_bind(struct aws_lws *wsi,
			  const struct aws_lws_client_connect_info *i);
void
aws_lws_remove_child_from_any_parent(struct aws_lws *wsi);

char *
aws_lws_generate_client_ws_handshake(struct aws_lws *wsi, char *p, const char *conn1);
int
aws_lws_client_ws_upgrade(struct aws_lws *wsi, const char **cce);
int
aws_lws_create_client_ws_object(const struct aws_lws_client_connect_info *i,
			    struct aws_lws *wsi);
int
aws_lws_alpn_comma_to_openssl(const char *comma, uint8_t *os, int len);
int
aws_lws_role_call_alpn_negotiated(struct aws_lws *wsi, const char *alpn);
int
aws_lws_tls_server_conn_alpn(struct aws_lws *wsi);

int
aws_lws_ws_client_rx_sm_block(struct aws_lws *wsi, unsigned char **buf, size_t len);
void
aws_lws_destroy_event_pipe(struct aws_lws *wsi);

/* socks */
int
aws_lws_socks5c_generate_msg(struct aws_lws *wsi, enum socks_msg_type type, ssize_t *msg_len);

int LWS_WARN_UNUSED_RESULT
aws___insert_wsi_socket_into_fds(struct aws_lws_context *context, struct aws_lws *wsi);

int LWS_WARN_UNUSED_RESULT
aws_lws_issue_raw(struct aws_lws *wsi, unsigned char *buf, size_t len);

aws_lws_usec_t
aws___lws_seq_timeout_check(struct aws_lws_context_per_thread *pt, aws_lws_usec_t usnow);

aws_lws_usec_t
aws___lws_ss_timeout_check(struct aws_lws_context_per_thread *pt, aws_lws_usec_t usnow);

struct aws_lws * LWS_WARN_UNUSED_RESULT
aws_lws_client_connect_2_dnsreq(struct aws_lws *wsi);

LWS_VISIBLE struct aws_lws * LWS_WARN_UNUSED_RESULT
aws_lws_client_reset(struct aws_lws **wsi, int ssl, const char *address, int port,
		 const char *path, const char *host, char weak);

struct aws_lws * LWS_WARN_UNUSED_RESULT
aws_lws_create_new_server_wsi(struct aws_lws_vhost *vhost, int fixed_tsi, const char *desc);

char * LWS_WARN_UNUSED_RESULT
aws_lws_generate_client_handshake(struct aws_lws *wsi, char *pkt);

int
aws_lws_handle_POLLOUT_event(struct aws_lws *wsi, struct aws_lws_pollfd *pollfd);

struct aws_lws *
aws_lws_http_client_connect_via_info2(struct aws_lws *wsi);


struct aws_lws *
aws___lws_wsi_create_with_role(struct aws_lws_context *context, int tsi,
			 const struct aws_lws_role_ops *ops,
			 aws_lws_log_cx_t *log_cx_template);
int
aws_lws_wsi_inject_to_loop(struct aws_lws_context_per_thread *pt, struct aws_lws *wsi);

int
aws_lws_wsi_extract_from_loop(struct aws_lws *wsi);


#if defined(LWS_WITH_CLIENT)
int
aws_lws_http_client_socket_service(struct aws_lws *wsi, struct aws_lws_pollfd *pollfd);

int LWS_WARN_UNUSED_RESULT
aws_lws_http_transaction_completed_client(struct aws_lws *wsi);
#if !defined(LWS_WITH_TLS)
	#define aws_lws_context_init_client_ssl(_a, _b) (0)
#endif
void
aws_lws_decode_ssl_error(void);
#else
#define aws_lws_context_init_client_ssl(_a, _b) (0)
#endif

int
aws___lws_rx_flow_control(struct aws_lws *wsi);

int
aws__lws_change_pollfd(struct aws_lws *wsi, int _and, int _or, struct aws_lws_pollargs *pa);

#if defined(LWS_WITH_SERVER)
int
aws_lws_handshake_server(struct aws_lws *wsi, unsigned char **buf, size_t len);
#else
#define aws_lws_server_socket_service(_b, _c) (0)
#define aws_lws_handshake_server(_a, _b, _c) (0)
#endif

#ifdef LWS_WITH_ACCESS_LOG
int
aws_lws_access_log(struct aws_lws *wsi);
void
aws_lws_prepare_access_log_info(struct aws_lws *wsi, char *uri_ptr, int len, int meth);
#else
#define aws_lws_access_log(_a)
#endif

#if defined(_DEBUG)
void
aws_lws_wsi_txc_describe(struct aws_lws_tx_credit *txc, const char *at, uint32_t sid);
#else
#define aws_lws_wsi_txc_describe(x, y, z) { (void)x; }
#endif

int
aws_lws_wsi_txc_check_skint(struct aws_lws_tx_credit *txc, int32_t tx_cr);

int
aws_lws_wsi_txc_report_manual_txcr_in(struct aws_lws *wsi, int32_t bump);

void
aws_lws_mux_mark_immortal(struct aws_lws *wsi);
void
aws_lws_http_close_immortal(struct aws_lws *wsi);

int
aws_lws_cgi_kill_terminated(struct aws_lws_context_per_thread *pt);

void
aws_lws_cgi_remove_and_kill(struct aws_lws *wsi);

void
aws_lws_plat_delete_socket_from_fds(struct aws_lws_context *context,
				struct aws_lws *wsi, int m);
void
aws_lws_plat_insert_socket_into_fds(struct aws_lws_context *context,
				struct aws_lws *wsi);

int
aws_lws_plat_change_pollfd(struct aws_lws_context *context, struct aws_lws *wsi,
		       struct aws_lws_pollfd *pfd);

#if defined(LWS_WITH_SERVER) && defined(LWS_WITH_SECURE_STREAMS)
int
aws_lws_adopt_ss_server_accept(struct aws_lws *new_wsi);
#endif

int
aws_lws_plat_pipe_create(struct aws_lws *wsi);
int
aws_lws_plat_pipe_signal(struct aws_lws_context *ctx, int tsi);
void
aws_lws_plat_pipe_close(struct aws_lws *wsi);

void
aws_lws_addrinfo_clean(struct aws_lws *wsi);

void
aws_lws_add_wsi_to_draining_ext_list(struct aws_lws *wsi);
void
aws_lws_remove_wsi_from_draining_ext_list(struct aws_lws *wsi);
int
aws_lws_poll_listen_fd(struct aws_lws_pollfd *fd);
int
aws_lws_plat_service(struct aws_lws_context *context, int timeout_ms);
LWS_VISIBLE int
aws__lws_plat_service_tsi(struct aws_lws_context *context, int timeout_ms, int tsi);

int
aws_lws_pthread_self_to_tsi(struct aws_lws_context *context);
const char * LWS_WARN_UNUSED_RESULT
aws_lws_plat_inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
int LWS_WARN_UNUSED_RESULT
aws_lws_plat_inet_pton(int af, const char *src, void *dst);

void
aws_lws_same_vh_protocol_remove(struct aws_lws *wsi);
void
aws___lws_same_vh_protocol_remove(struct aws_lws *wsi);
void
aws_lws_same_vh_protocol_insert(struct aws_lws *wsi, int n);

int
aws_lws_client_stash_create(struct aws_lws *wsi, const char **cisin);

void
aws_lws_seq_destroy_all_on_pt(struct aws_lws_context_per_thread *pt);

void
aws_lws_addrinfo_clean(struct aws_lws *wsi);

int
aws__lws_route_pt_close_unroutable(struct aws_lws_context_per_thread *pt);

void
aws__lws_routing_entry_dump(struct aws_lws_context *cx, aws_lws_route_t *rou);

void
aws__lws_routing_table_dump(struct aws_lws_context *cx);

#define LRR_IGNORE_PRI			(1 << 0)
#define LRR_MATCH_SRC			(1 << 1)
#define LRR_JUST_CHECK			(1 << 2)

aws_lws_route_t *
aws__lws_route_remove(struct aws_lws_context_per_thread *pt, aws_lws_route_t *robj, int flags);

void
aws__lws_route_table_empty(struct aws_lws_context_per_thread *pt);

void
aws__lws_route_table_ifdown(struct aws_lws_context_per_thread *pt, int idx);

aws_lws_route_uidx_t
aws__lws_route_get_uidx(struct aws_lws_context *cx);

int
aws__lws_route_pt_close_route_users(struct aws_lws_context_per_thread *pt,
			        aws_lws_route_uidx_t uidx);

aws_lws_route_t *
aws__lws_route_est_outgoing(struct aws_lws_context_per_thread *pt,
		        const aws_lws_sockaddr46 *dest);

int
aws_lws_sort_dns(struct aws_lws *wsi, const struct addrinfo *result);

int
aws_lws_broadcast(struct aws_lws_context_per_thread *pt, int reason, void *in, size_t len);


#if defined(LWS_WITH_PEER_LIMITS)
void
aws_lws_peer_track_wsi_close(struct aws_lws_context *context, struct aws_lws_peer *peer);
int
aws_lws_peer_confirm_ah_attach_ok(struct aws_lws_context *context,
			      struct aws_lws_peer *peer);
void
aws_lws_peer_track_ah_detach(struct aws_lws_context *context, struct aws_lws_peer *peer);
void
aws_lws_peer_cull_peer_wait_list(struct aws_lws_context *context);
struct aws_lws_peer *
aws_lws_get_or_create_peer(struct aws_lws_vhost *vhost, aws_lws_sockfd_type sockfd);
void
aws_lws_peer_add_wsi(struct aws_lws_context *context, struct aws_lws_peer *peer,
		 struct aws_lws *wsi);
void
aws_lws_peer_dump_from_wsi(struct aws_lws *wsi);
#endif

#ifdef LWS_WITH_HUBBUB
hubbub_error
html_parser_cb(const hubbub_token *token, void *pw);
#endif

#if defined(_DEBUG)
void
aws_lws_service_assert_loop_thread(struct aws_lws_context *cx, int tsi);
#else
#define aws_lws_service_assert_loop_thread(_cx, _tsi)
#endif

int
aws_lws_threadpool_tsi_context(struct aws_lws_context *context, int tsi);

void
aws_lws_threadpool_wsi_closing(struct aws_lws *wsi);

void
aws___lws_wsi_remove_from_sul(struct aws_lws *wsi);

void
aws_lws_validity_confirmed(struct aws_lws *wsi);
void
aws__lws_validity_confirmed_role(struct aws_lws *wsi);

int
aws_lws_seq_pt_init(struct aws_lws_context_per_thread *pt);

int
aws_lws_buflist_aware_read(struct aws_lws_context_per_thread *pt, struct aws_lws *wsi,
		       struct aws_lws_tokens *ebuf, char fr, const char *hint);
int
aws_lws_buflist_aware_finished_consuming(struct aws_lws *wsi, struct aws_lws_tokens *ebuf,
				     int used, int buffered, const char *hint);

extern const struct aws_lws_protocols protocol_abs_client_raw_skt,
				  protocol_abs_client_unit_test;

void
aws___lws_reset_wsi(struct aws_lws *wsi);

void
aws_lws_metrics_dump(struct aws_lws_context *ctx);

void
aws_lws_inform_client_conn_fail(struct aws_lws *wsi, void *arg, size_t len);

#if defined(LWS_WITH_SYS_ASYNC_DNS)
aws_lws_async_dns_server_check_t
aws_lws_plat_asyncdns_init(struct aws_lws_context *context, aws_lws_sockaddr46 *sa);
int
aws_lws_async_dns_init(struct aws_lws_context *context);
void
aws_lws_async_dns_deinit(aws_lws_async_dns_t *dns);
#endif

int
aws_lws_protocol_init_vhost(struct aws_lws_vhost *vh, int *any);
int
aws__lws_generic_transaction_completed_active_conn(struct aws_lws **wsi, char take_vh_lock);

#define ACTIVE_CONNS_SOLO 0
#define ACTIVE_CONNS_MUXED 1
#define ACTIVE_CONNS_QUEUED 2
#define ACTIVE_CONNS_FAILED 3

#if defined(_DEBUG) && !defined(LWS_PLAT_FREERTOS) && !defined(WIN32) && !defined(LWS_PLAT_OPTEE)

int
sanity_assert_no_wsi_traces(const struct aws_lws_context *context, struct aws_lws *wsi);
int
sanity_assert_no_sockfd_traces(const struct aws_lws_context *context,
			       aws_lws_sockfd_type sfd);
#else
static inline int sanity_assert_no_wsi_traces(const struct aws_lws_context *context, struct aws_lws *wsi) { (void)context; (void)wsi; return 0; }
static inline int sanity_assert_no_sockfd_traces(const struct aws_lws_context *context, aws_lws_sockfd_type sfd) { (void)context; (void)sfd; return 0; }
#endif


void
delete_from_fdwsi(const struct aws_lws_context *context, struct aws_lws *wsi);

int
aws_lws_vhost_active_conns(struct aws_lws *wsi, struct aws_lws **nwsi, const char *adsin);

const char *
aws_lws_wsi_client_stash_item(struct aws_lws *wsi, int stash_idx, int hdr_idx);

int
aws_lws_plat_BINDTODEVICE(aws_lws_sockfd_type fd, const char *ifname);

int
aws_lws_socks5c_ads_server(struct aws_lws_vhost *vh,
		       const struct aws_lws_context_creation_info *info);

int
aws_lws_socks5c_handle_state(struct aws_lws *wsi, struct aws_lws_pollfd *pollfd,
			 const char **pcce);

int
aws_lws_socks5c_greet(struct aws_lws *wsi, const char **pcce);

int
aws_lws_plat_mbedtls_net_send(void *ctx, const uint8_t *buf, size_t len);

int
aws_lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len);

aws_lws_usec_t
aws_lws_sul_nonmonotonic_adjust(struct aws_lws_context *ctx, int64_t step_us);

void
aws___lws_vhost_destroy_pt_wsi_dieback_start(struct aws_lws_vhost *vh);

int
aws_lws_vhost_compare_listen(struct aws_lws_vhost *v1, struct aws_lws_vhost *v2);

void
aws_lws_netdev_instance_remove_destroy(struct aws_lws_netdev_instance *ni);

int
aws_lws_score_dns_results(struct aws_lws_context *ctx,
			     const struct addrinfo **result);

#if defined(LWS_WITH_SYS_SMD)
int
aws_lws_netdev_smd_cb(void *opaque, aws_lws_smd_class_t _class, aws_lws_usec_t timestamp,
		  void *buf, size_t len);
#endif

void
aws_lws_netdev_instance_create(aws_lws_netdev_instance_t *ni, struct aws_lws_context *ctx,
			   const aws_lws_netdev_ops_t *ops, const char *name,
			   void *platinfo);

int
aws_lws_netdev_wifi_rssi_sort_compare(const aws_lws_dll2_t *d, const aws_lws_dll2_t *i);
void
aws_lws_netdev_wifi_scan_empty(aws_lws_netdev_instance_wifi_t *wnd);

aws_lws_wifi_sta_t *
aws_lws_netdev_wifi_scan_find(aws_lws_netdev_instance_wifi_t *wnd, const char *ssid,
			  const uint8_t *bssid);

int
aws_lws_netdev_wifi_scan_select(aws_lws_netdev_instance_wifi_t *wnd);

aws_lws_wifi_creds_t *
aws_lws_netdev_credentials_find(aws_lws_netdevs_t *netdevs, const char *ssid,
			    const uint8_t *bssid);

int
aws_lws_netdev_wifi_redo_last(aws_lws_netdev_instance_wifi_t *wnd);

void
aws_lws_ntpc_trigger(struct aws_lws_context *ctx);

void
aws_lws_netdev_wifi_scan(aws_lws_sorted_usec_list_t *sul);

#define aws_lws_netdevs_from_ndi(ni) \
		aws_lws_container_of((ni)->list.owner, aws_lws_netdevs_t, owner)

#define aws_lws_context_from_netdevs(nd) \
		aws_lws_container_of(nd, struct aws_lws_context, netdevs)

/* get the owner of the ni, then compute the context the owner is embedded in */
#define netdev_instance_to_ctx(ni) \
		aws_lws_container_of(aws_lws_netdevs_from_ndi(ni), \
				 struct aws_lws_context, netdevs)

enum {
	LW5CHS_RET_RET0,
	LW5CHS_RET_BAIL3,
	LW5CHS_RET_STARTHS,
	LW5CHS_RET_NOTHING
};

void
aws_lws_4to6(uint8_t *v6addr, const uint8_t *v4addr);
void
aws_lws_sa46_4to6(aws_lws_sockaddr46 *sa46, const uint8_t *v4addr, uint16_t port);

#ifdef __cplusplus
};
#endif

#endif

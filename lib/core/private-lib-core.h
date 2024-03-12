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

#if !defined(__LWS_PRIVATE_LIB_CORE_H__)
#define __LWS_PRIVATE_LIB_CORE_H__

#include "lws_config.h"
#include "lws_config_private.h"


#if defined(LWS_WITH_CGI) && defined(LWS_HAVE_VFORK) && \
    !defined(NO_GNU_SOURCE_THIS_TIME) && !defined(_GNU_SOURCE)
 #define  _GNU_SOURCE
#endif

/*
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>

#ifdef LWS_HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <assert.h>

#ifdef LWS_HAVE_SYS_TYPES_H
 #include <sys/types.h>
#endif
#if defined(LWS_HAVE_SYS_STAT_H) && !defined(LWS_PLAT_OPTEE)
 #include <sys/stat.h>
#endif

#if LWS_MAX_SMP > 1 || defined(LWS_WITH_SYS_SMD)
 /* https://stackoverflow.com/questions/33557506/timespec-redefinition-error */
 #define HAVE_STRUCT_TIMESPEC
 #include <pthread.h>
#else
 #if !defined(pid_t) && defined(WIN32)
 #define pid_t int
 #endif
#endif

#ifndef LWS_DEF_HEADER_LEN
#define LWS_DEF_HEADER_LEN 4096
#endif
#ifndef LWS_DEF_HEADER_POOL
#define LWS_DEF_HEADER_POOL 4
#endif
#ifndef LWS_MAX_PROTOCOLS
#define LWS_MAX_PROTOCOLS 5
#endif
#ifndef LWS_MAX_EXTENSIONS_ACTIVE
#define LWS_MAX_EXTENSIONS_ACTIVE 1
#endif
#ifndef LWS_MAX_EXT_OFFERS
#define LWS_MAX_EXT_OFFERS 8
#endif
#ifndef SPEC_LATEST_SUPPORTED
#define SPEC_LATEST_SUPPORTED 13
#endif
#ifndef CIPHERS_LIST_STRING
#define CIPHERS_LIST_STRING "DEFAULT"
#endif
#ifndef LWS_SOMAXCONN
#define LWS_SOMAXCONN SOMAXCONN
#endif

#define MAX_WEBSOCKET_04_KEY_LEN 128

#ifndef SYSTEM_RANDOM_FILEPATH
#define SYSTEM_RANDOM_FILEPATH "/dev/urandom"
#endif

#define LWS_H2_RX_SCRATCH_SIZE 512

#define aws_lws_socket_is_valid(x) (x != LWS_SOCK_INVALID)

#ifndef LWS_HAVE_STRERROR
 #define strerror(x) ""
#endif

 /*
  *
  *  ------ private platform defines ------
  *
  */

#if defined(LWS_PLAT_FREERTOS)
 #include "private-lib-plat-freertos.h"
#else
 #if defined(WIN32) || defined(_WIN32)
  #include "private-lib-plat-windows.h"
 #else
  #if defined(LWS_PLAT_OPTEE)
   #include "private-lib-plat.h"
  #else
   #include "private-lib-plat-unix.h"
  #endif
 #endif
#endif

 /*
  *
  *  ------ public api ------
  *
  */

#include "libwebsockets.h"

/*
 * aws_lws_dsh
*/

typedef struct aws_lws_dsh_obj_head {
	aws_lws_dll2_owner_t		owner;
	size_t				total_size; /* for this kind in dsh */
	int				kind;
} aws_lws_dsh_obj_head_t;

typedef struct aws_lws_dsh_obj {
	aws_lws_dll2_t			list;	/* must be first */
	struct aws_lws_dsh	  		*dsh;	/* invalid when on free list */
	size_t				size;	/* invalid when on free list */
	size_t				asize;
	int				kind; /* so we can account at free */
} aws_lws_dsh_obj_t;

typedef struct aws_lws_dsh {
	aws_lws_dll2_t			list;
	uint8_t				*buf;
	aws_lws_dsh_obj_head_t		*oha;	/* array of object heads/kind */
	size_t				buffer_size;
	size_t				locally_in_use;
	size_t				locally_free;
	int				count_kinds;
	uint8_t				being_destroyed;
	/*
	 * Overallocations at create:
	 *
	 *  - the buffer itself
	 *  - the object heads array
	 */
} aws_lws_dsh_t;

 /*
  *
  *  ------ lifecycle defines ------
  *
  */

typedef struct aws_lws_lifecycle_group {
	aws_lws_dll2_owner_t		owner; /* active count / list */
	uint64_t			ordinal; /* monotonic uid count */
	const char			*tag_prefix; /* eg, "wsi" */
} aws_lws_lifecycle_group_t;

typedef struct aws_lws_lifecycle {
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
	/* we append parent streams on the tag */
	char				gutag[96]; /* object unique tag + relationship info */
#else
	char				gutag[64];
#endif
	aws_lws_dll2_t			list; /* group list membership */
	uint64_t			us_creation; /* creation timestamp */
	aws_lws_log_cx_t			*log_cx;
} aws_lws_lifecycle_t;

void
__lws_lc_tag(struct aws_lws_context *cx, aws_lws_lifecycle_group_t *grp,
	     aws_lws_lifecycle_t *lc, const char *format, ...);

void
__lws_lc_tag_append(aws_lws_lifecycle_t *lc, const char *app);

void
__lws_lc_untag(struct aws_lws_context *cx, aws_lws_lifecycle_t *lc);

const char *
aws_lws_lc_tag(aws_lws_lifecycle_t *lc);

extern aws_lws_log_cx_t log_cx;

/*
 * Generic bidi tx credit management
 */

struct aws_lws_tx_credit {
	int32_t			tx_cr;		/* our credit to write peer */
	int32_t			peer_tx_cr_est; /* peer's credit to write us */

	int32_t			manual_initial_tx_credit;

	uint8_t			skint; /* unable to write anything */
	uint8_t			manual;
};

#ifdef LWS_WITH_IPV6
#if defined(WIN32) || defined(_WIN32)
#include <iphlpapi.h>
#else
#include <net/if.h>
#endif
#endif

#undef X509_NAME

/*
 * All aws_lws_tls...() functions must return this type, converting the
 * native backend result and doing the extra work to determine which one
 * as needed.
 *
 * Native TLS backend return codes are NOT ALLOWED outside the backend.
 *
 * Non-SSL mode also uses these types.
 */
enum aws_lws_ssl_capable_status {
	LWS_SSL_CAPABLE_ERROR			= -1, /* it failed */
	LWS_SSL_CAPABLE_DONE			= 0,  /* it succeeded */
	LWS_SSL_CAPABLE_MORE_SERVICE_READ	= -2, /* retry WANT_READ */
	LWS_SSL_CAPABLE_MORE_SERVICE_WRITE	= -3, /* retry WANT_WRITE */
	LWS_SSL_CAPABLE_MORE_SERVICE		= -4, /* general retry */
};

enum aws_lws_context_destroy {
	LWSCD_NO_DESTROY,		/* running */
	LWSCD_PT_WAS_DEFERRED,		/* destroy from inside service */
	LWSCD_PT_WAIT_ALL_DESTROYED,	/* libuv ends up here later */
	LWSCD_FINALIZATION		/* the final destruction of context */
};

#if defined(LWS_WITH_TLS)
#include "private-lib-tls.h"
#endif

#if defined(WIN32) || defined(_WIN32)
	 // Visual studio older than 2015 and WIN_CE has only _stricmp
	#if (defined(_MSC_VER) && _MSC_VER < 1900) || defined(_WIN32_WCE)
	#define strcasecmp _stricmp
	#define strncasecmp _strnicmp
	#elif !defined(__MINGW32__)
	#define strcasecmp stricmp
	#define strncasecmp strnicmp
	#endif
	#define getdtablesize() 30000
#endif

#ifndef LWS_ARRAY_SIZE
#define LWS_ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define aws_lws_safe_modulo(_a, _b) ((_b) ? ((_a) % (_b)) : 0)

#if defined(__clang__)
#define aws_lws_memory_barrier() __sync_synchronize()
#elif defined(__GNUC__)
#define aws_lws_memory_barrier() __sync_synchronize()
#else
#define aws_lws_memory_barrier()
#endif


struct aws_lws_ring {
	void *buf;
	void (*destroy_element)(void *element);
	uint32_t buflen;
	uint32_t element_len;
	uint32_t head;
	uint32_t oldest_tail;
};

struct aws_lws_protocols;
struct lws;

#if defined(LWS_WITH_NETWORK) /* network */
#include "private-lib-event-libs.h"

#if defined(LWS_WITH_SECURE_STREAMS)
#include "private-lib-secure-streams.h"
#endif

#if defined(LWS_WITH_SYS_SMD)
#include "private-lib-system-smd.h"
#endif

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
#include "private-lib-system-fault-injection.h"
#endif

#include "private-lib-system-metrics.h"


struct aws_lws_foreign_thread_pollfd {
	struct aws_lws_foreign_thread_pollfd *next;
	int fd_index;
	int _and;
	int _or;
};
#endif /* network */

#if defined(LWS_WITH_NETWORK)
#include "private-lib-core-net.h"
#endif

struct aws_lws_system_blob {
	union {
		struct aws_lws_buflist *bl;
		struct {
			const uint8_t *ptr;
			size_t len;
		} direct;
	} u;
	char	is_direct;
};


typedef struct aws_lws_attach_item {
	aws_lws_dll2_t			list;
	aws_lws_attach_cb_t			cb;
	void				*opaque;
	aws_lws_system_states_t		state;
} aws_lws_attach_item_t;

/*
 * These are the context's lifecycle group indexes that exist in this build
 * configuration.  If you add some, make sure to also add the tag_prefix in
 * context.c context creation with matching preprocessor conditionals.
 */

enum {
	LWSLCG_WSI,			/* generic wsi, eg, pipe, listen */
	LWSLCG_VHOST,

	LWSLCG_WSI_SERVER,		/* server wsi */

#if defined(LWS_ROLE_H2) || defined(LWS_ROLE_MQTT)
	LWSLCG_WSI_MUX,			/* a mux child wsi */
#endif

#if defined(LWS_WITH_CLIENT)
	LWSLCG_WSI_CLIENT,		/* client wsi */
#endif

#if defined(LWS_WITH_SECURE_STREAMS)
#if defined(LWS_WITH_CLIENT)
	LWSLCG_SS_CLIENT,		/* secstream client handle */
#endif
#if defined(LWS_WITH_SERVER)
	LWSLCG_SS_SERVER,		/* secstream server handle */
#endif
#if defined(LWS_WITH_CLIENT)
	LWSLCG_WSI_SS_CLIENT,		/* wsi bound to ss client handle */
#endif
#if defined(LWS_WITH_SERVER)
	LWSLCG_WSI_SS_SERVER,		/* wsi bound to ss server handle */
#endif
#endif

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
#if defined(LWS_WITH_CLIENT)
	LWSLCG_SSP_CLIENT,		/* SSPC handle client connection to proxy */
#endif
#if defined(LWS_WITH_SERVER)
	LWSLCG_SSP_ONWARD,		/* SS handle at proxy for onward conn */
#endif
#if defined(LWS_WITH_CLIENT)
	LWSLCG_WSI_SSP_CLIENT,		/* wsi bound to SSPC cli conn to proxy */
#endif
#if defined(LWS_WITH_SERVER)
	LWSLCG_WSI_SSP_ONWARD,		/* wsi bound to Proxy onward connection */
#endif
#endif

	/* always last */
	LWSLCG_COUNT
};

/*
 * the rest is managed per-context, that includes
 *
 *  - processwide single fd -> wsi lookup
 *  - contextwide headers pool
 */

struct aws_lws_context {
 #if defined(LWS_WITH_SERVER)
	char canonical_hostname[96];
 #endif

#if defined(LWS_WITH_FILE_OPS)
	struct aws_lws_plat_file_ops fops_platform;
#endif

#if defined(LWS_WITH_ZIP_FOPS)
	struct aws_lws_plat_file_ops fops_zip;
#endif

	aws_lws_system_blob_t system_blobs[LWS_SYSBLOB_TYPE_COUNT];

#if defined(LWS_WITH_SYS_SMD)
	aws_lws_smd_t				smd;
#endif
#if defined(LWS_WITH_SECURE_STREAMS)
	struct aws_lws_ss_handle			*ss_cpd;
#endif
	aws_lws_sorted_usec_list_t			sul_cpd_defer;

#if defined(LWS_WITH_NETWORK)
	struct aws_lws_context_per_thread		pt[LWS_MAX_SMP];
	aws_lws_retry_bo_t				default_retry;
	aws_lws_sorted_usec_list_t			sul_system_state;

	aws_lws_lifecycle_group_t			lcg[LWSLCG_COUNT];

	const struct aws_lws_protocols		*protocols_copy;

#if defined(LWS_WITH_NETLINK)
	aws_lws_sorted_usec_list_t			sul_nl_coldplug;
	/* process can only have one netlink socket, have to do it in ctx */
	aws_lws_dll2_owner_t			routing_table;
	struct lws				*netlink;
#endif

#if defined(LWS_PLAT_FREERTOS)
	struct sockaddr_in			frt_pipe_si;
#endif

#if defined(LWS_WITH_HTTP2)
	struct http2_settings			set;
#endif

#if LWS_MAX_SMP > 1
	struct aws_lws_mutex_refcount		mr;
#endif

#if defined(LWS_WITH_SYS_METRICS)
	aws_lws_dll2_owner_t			owner_mtr_dynpol;
	/**< owner for aws_lws_metric_policy_dyn_t (dynamic part of metric pols) */
	aws_lws_dll2_owner_t			owner_mtr_no_pol;
	/**< owner for aws_lws_metric_pub_t with no policy to bind to */
#endif

#if defined(LWS_WITH_NETWORK)
/*
 * LWS_WITH_NETWORK =====>
 */

	aws_lws_dll2_owner_t		owner_vh_being_destroyed;

	aws_lws_metric_t			*mt_service; /* doing service */
	const aws_lws_metric_policy_t	*metrics_policies;
	const char			*metrics_prefix;

#if defined(LWS_WITH_SYS_METRICS) && defined(LWS_WITH_CLIENT)
	aws_lws_metric_t			*mt_conn_tcp; /* client tcp conns */
	aws_lws_metric_t			*mt_conn_tls; /* client tcp conns */
	aws_lws_metric_t			*mt_conn_dns; /* client dns external lookups */
	aws_lws_metric_t			*mth_conn_failures; /* histogram of conn failure reasons */
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	aws_lws_metric_t			*mt_http_txn; /* client http transaction */
#endif
#if defined(LWS_WITH_SYS_ASYNC_DNS)
	aws_lws_metric_t			*mt_adns_cache; /* async dns lookup lat */
#endif
#if defined(LWS_WITH_SECURE_STREAMS)
	aws_lws_metric_t			*mth_ss_conn; /* SS connection outcomes */
#endif
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
	aws_lws_metric_t			*mt_ss_cliprox_conn; /* SS cli->prox conn */
	aws_lws_metric_t			*mt_ss_cliprox_paylat; /* cli->prox payload latency */
	aws_lws_metric_t			*mt_ss_proxcli_paylat; /* prox->cli payload latency */
#endif
#endif /* client */

#if defined(LWS_WITH_SERVER)
	aws_lws_metric_t			*mth_srv;
#endif

#if defined(LWS_WITH_EVENT_LIBS)
	struct aws_lws_plugin		*evlib_plugin_list;
	void				*evlib_ctx; /* overallocated */
#endif

#if defined(LWS_WITH_TLS)
	struct aws_lws_context_tls		tls;
#if defined (LWS_WITH_TLS_JIT_TRUST)
	aws_lws_dll2_owner_t		jit_inflight;
	/* ongoing sync or async jit trust lookups */
	struct aws_lws_cache_ttl_lru	*trust_cache;
	/* caches host -> truncated trust SKID mappings */
#endif
#endif
#if defined(LWS_WITH_DRIVERS)
	aws_lws_netdevs_t			netdevs;
#endif

#if defined(LWS_WITH_SYS_ASYNC_DNS)
	aws_lws_async_dns_t			async_dns;
#endif

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	aws_lws_fi_ctx_t			fic;
	/**< Toplevel Fault Injection ctx */
#endif

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)
	struct aws_lws_cache_ttl_lru *l1, *nsc;
#endif

#if defined(LWS_WITH_SYS_NTPCLIENT)
	void				*ntpclient_priv;
#endif

#if defined(LWS_WITH_SECURE_STREAMS)
	struct aws_lws_ss_handle		*hss_fetch_policy;
#if defined(LWS_WITH_SECURE_STREAMS_SYS_AUTH_API_AMAZON_COM)
	struct aws_lws_ss_handle		*hss_auth;
	aws_lws_sorted_usec_list_t		sul_api_amazon_com;
	aws_lws_sorted_usec_list_t		sul_api_amazon_com_kick;
#endif
#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	struct aws_lws_ss_x509		*server_der_list;
#endif
#endif

#if defined(LWS_WITH_SYS_STATE)
	aws_lws_state_manager_t		mgr_system;
	aws_lws_state_notify_link_t		protocols_notify;
#endif
#if defined (LWS_WITH_SYS_DHCP_CLIENT)
	aws_lws_dll2_owner_t		dhcpc_owner;
					/**< list of ifaces with dhcpc */
#endif

	/* pointers */

	struct aws_lws_vhost		*vhost_list;
	struct aws_lws_vhost		*no_listener_vhost_list;
	struct aws_lws_vhost		*vhost_pending_destruction_list;
	struct aws_lws_vhost		*vhost_system;

#if defined(LWS_WITH_SERVER)
	const char			*server_string;
#endif

	const struct aws_lws_event_loop_ops	*event_loop_ops;
#endif

#if defined(LWS_WITH_TLS)
	const struct aws_lws_tls_ops	*tls_ops;
#endif

#if defined(LWS_WITH_PLUGINS)
	struct aws_lws_plugin		*plugin_list;
#endif
#ifdef _WIN32
/* different implementation between unix and windows */
	struct aws_lws_fd_hashtable fd_hashtable[FD_HASHTABLE_MODULUS];
#else
	struct lws **aws_lws_lookup;

#endif

/*
 * <====== LWS_WITH_NETWORK end
 */

#endif /* NETWORK */

	aws_lws_log_cx_t			*log_cx;
	const char			*name;

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
	const char	*ss_proxy_bind;
	const char	*ss_proxy_address;
#endif

#if defined(LWS_WITH_FILE_OPS)
	const struct aws_lws_plat_file_ops *fops;
#endif

	struct aws_lws_context **pcontext_finalize;
#if !defined(LWS_PLAT_FREERTOS)
	const char *username, *groupname;
#endif

#if defined(LWS_WITH_MBEDTLS)
	mbedtls_entropy_context mec;
	mbedtls_ctr_drbg_context mcdc;
#endif

#if defined(LWS_WITH_THREADPOOL)
	struct aws_lws_threadpool *tp_list_head;
#endif

#if defined(LWS_WITH_PEER_LIMITS)
	struct aws_lws_peer			**pl_hash_table;
	struct aws_lws_peer			*peer_wait_list;
	aws_lws_peer_limits_notify_t	pl_notify_cb;
	time_t				next_cull;
#endif

	const aws_lws_system_ops_t		*system_ops;

#if defined(LWS_WITH_SECURE_STREAMS)
#if !defined(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY)
	const char			*pss_policies_json;
	struct aws_lwsac			*ac_policy;
	void				*pol_args;
#endif
	const aws_lws_ss_policy_t		*pss_policies;
	const aws_lws_ss_auth_t		*pss_auths;
#if defined(LWS_WITH_SSPLUGINS)
	const aws_lws_ss_plugin_t		**pss_plugins;
#endif
#endif

	void *external_baggage_free_on_destroy;
	const struct aws_lws_token_limits *token_limits;
	void *user_space;
#if defined(LWS_WITH_SERVER)
	const struct aws_lws_protocol_vhost_options *reject_service_keywords;
	aws_lws_reload_func deprecation_cb;
#endif
#if !defined(LWS_PLAT_FREERTOS)
	void (*eventlib_signal_cb)(void *event_lib_handle, int signum);
#endif

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
	cap_value_t caps[4];
	char count_caps;
#endif

	aws_lws_usec_t time_up; /* monotonic */
#if defined(LWS_WITH_SYS_SMD)
	aws_lws_usec_t smd_ttl_us;
#endif
	uint64_t options;

	time_t last_ws_ping_pong_check_s;
#if defined(LWS_WITH_SECURE_STREAMS)
	time_t					last_policy;
#endif

#if defined(LWS_PLAT_FREERTOS)
	unsigned long time_last_state_dump;
	uint32_t last_free_heap;
#endif

	unsigned int max_fds;
#if !defined(LWS_NO_DAEMONIZE)
	pid_t started_with_parent;
#endif

#if !defined(LWS_PLAT_FREERTOS)
	uid_t uid;
	gid_t gid;
	int fd_random;
	int count_cgi_spawned;
#endif

	unsigned int fd_limit_per_thread;
	unsigned int timeout_secs;
	unsigned int pt_serv_buf_size;
	unsigned int max_http_header_data;
	unsigned int max_http_header_pool;
	int simultaneous_ssl_restriction;
	int simultaneous_ssl;
	int simultaneous_ssl_handshake_restriction;
	int simultaneous_ssl_handshake;
#if defined(LWS_WITH_TLS_JIT_TRUST)
	int		vh_idle_grace_ms;
#endif
#if defined(LWS_WITH_PEER_LIMITS)
	uint32_t pl_hash_elements;	/* protected by context->lock */
	uint32_t count_peers;		/* protected by context->lock */
	unsigned short ip_limit_ah;
	unsigned short ip_limit_wsi;
#endif

#if defined(LWS_WITH_SYS_SMD)
	uint16_t smd_queue_depth;
#endif

#if defined(LWS_WITH_NETLINK)
	aws_lws_route_uidx_t			route_uidx;
#endif

	char		tls_gate_accepts;

	unsigned int deprecated:1;
	unsigned int inside_context_destroy:1;
	unsigned int being_destroyed:1;
	unsigned int service_no_longer_possible:1;
	unsigned int being_destroyed2:1;
	unsigned int requested_stop_internal_loops:1;
	unsigned int protocol_init_done:1;
	unsigned int doing_protocol_init:1;
	unsigned int done_protocol_destroy_cb:1;
	unsigned int evlib_finalize_destroy_after_int_loops_stop:1;
	unsigned int max_fds_unrelated_to_ulimit:1;
	unsigned int policy_updated:1;
#if defined(LWS_WITH_NETLINK)
	unsigned int nl_initial_done:1;
#endif

	unsigned short count_threads;
	unsigned short undestroyed_threads;
	short plugin_protocol_count;
	short plugin_extension_count;
	short server_string_len;
	unsigned short deprecation_pending_listen_close_count;
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
	uint16_t	ss_proxy_port;
#endif
	/* 0 if not known, else us resolution of the poll wait */
	uint16_t us_wait_resolution;

	uint8_t max_fi;
	uint8_t captive_portal_detect;
	uint8_t captive_portal_detect_type;

	uint8_t		destroy_state; /* enum aws_lws_context_destroy */
};

#define aws_lws_get_context_protocol(ctx, x) ctx->vhost_list->protocols[x]
#define aws_lws_get_vh_protocol(vh, x) vh->protocols[x]

int
aws_lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max);

void
aws_lws_vhost_destroy1(struct aws_lws_vhost *vh);

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)
int
aws_lws_parse_set_cookie(struct lws *wsi);

int
aws_lws_cookie_send_cookies(struct lws *wsi, char **pp, char *end);
#endif

#if defined(LWS_PLAT_FREERTOS)
int
aws_lws_find_string_in_file(const char *filename, const char *str, int stringlen);
#endif

signed char char_to_hex(const char c);

#if defined(LWS_WITH_NETWORK)
int
aws_lws_system_do_attach(struct aws_lws_context_per_thread *pt);
#endif

struct aws_lws_buflist {
	struct aws_lws_buflist *next;
	size_t len;
	size_t pos;
};

char *
aws_lws_strdup(const char *s);

int
aws_lws_b64_selftest(void);


#ifndef LWS_NO_DAEMONIZE
 pid_t get_daemonize_pid();
#else
 #define get_daemonize_pid() (0)
#endif

void aws_lwsl_emit_stderr(int level, const char *line);

#if !defined(LWS_WITH_TLS)
 #define LWS_SSL_ENABLED(context) (0)
 #define aws_lws_context_init_server_ssl(_a, _b) (0)
 #define aws_lws_ssl_destroy(_a)
 #define aws_lws_context_init_alpn(_a)
 #define aws_lws_ssl_capable_read aws_lws_ssl_capable_read_no_ssl
 #define aws_lws_ssl_capable_write aws_lws_ssl_capable_write_no_ssl
 #define aws_lws_ssl_pending aws_lws_ssl_pending_no_ssl
 #define aws_lws_server_socket_service_ssl(_b, _c, _d) (0)
 #define aws_lws_ssl_close(_a) (0)
 #define aws_lws_ssl_context_destroy(_a)
 #define aws_lws_ssl_SSL_CTX_destroy(_a)
 #define aws_lws_ssl_remove_wsi_from_buffered_list(_a)
 #define __lws_ssl_remove_wsi_from_buffered_list(_a)
 #define aws_lws_context_init_ssl_library(_a, _b)
 #define aws_lws_context_deinit_ssl_library(_a)
 #define aws_lws_tls_check_all_cert_lifetimes(_a)
 #define aws_lws_tls_acme_sni_cert_destroy(_a)
#endif



#if LWS_MAX_SMP > 1
#define aws_lws_context_lock(c, reason) aws_lws_mutex_refcount_lock(&c->mr, reason)
#define aws_lws_context_unlock(c) aws_lws_mutex_refcount_unlock(&c->mr)
#define aws_lws_context_assert_lock_held(c) aws_lws_mutex_refcount_assert_held(&c->mr)
#define aws_lws_vhost_assert_lock_held(v) aws_lws_mutex_refcount_assert_held(&v->mr)
/* enforce context lock held */
#define aws_lws_vhost_lock(v) aws_lws_mutex_refcount_lock(&v->mr, __func__)
#define aws_lws_vhost_unlock(v) aws_lws_mutex_refcount_unlock(&v->mr)


#else
#define aws_lws_pt_mutex_init(_a) (void)(_a)
#define aws_lws_pt_mutex_destroy(_a) (void)(_a)
#define aws_lws_pt_lock(_a, b) (void)(_a)
#define aws_lws_pt_assert_lock_held(_a) (void)(_a)
#define aws_lws_pt_unlock(_a) (void)(_a)
#define aws_lws_context_lock(_a, _b) (void)(_a)
#define aws_lws_context_unlock(_a) (void)(_a)
#define aws_lws_context_assert_lock_held(_a) (void)(_a)
#define aws_lws_vhost_assert_lock_held(_a) (void)(_a)
#define aws_lws_vhost_lock(_a) (void)(_a)
#define aws_lws_vhost_unlock(_a) (void)(_a)
#define aws_lws_pt_stats_lock(_a) (void)(_a)
#define aws_lws_pt_stats_unlock(_a) (void)(_a)
#endif

int LWS_WARN_UNUSED_RESULT
aws_lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, size_t len);

int LWS_WARN_UNUSED_RESULT
aws_lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, size_t len);

int LWS_WARN_UNUSED_RESULT
aws_lws_ssl_pending_no_ssl(struct lws *wsi);

int
aws_lws_tls_check_cert_lifetime(struct aws_lws_vhost *vhost);

int aws_lws_jws_selftest(void);
int aws_lws_jwe_selftest(void);

int
aws_lws_protocol_init(struct aws_lws_context *context);

int
aws_lws_bind_protocol(struct lws *wsi, const struct aws_lws_protocols *p,
		  const char *reason);

const struct aws_lws_protocol_vhost_options *
aws_lws_vhost_protocol_options(struct aws_lws_vhost *vh, const char *name);

const struct aws_lws_http_mount *
aws_lws_find_mount(struct lws *wsi, const char *uri_ptr, int uri_len);

#ifdef LWS_WITH_HTTP2
int aws_lws_wsi_is_h2(struct lws *wsi);
#endif
/*
 * custom allocator
 */
void *
aws_lws_realloc(void *ptr, size_t size, const char *reason);

void * LWS_WARN_UNUSED_RESULT
aws_lws_zalloc(size_t size, const char *reason);

#ifdef LWS_PLAT_OPTEE
void *aws_lws_malloc(size_t size, const char *reason);
void aws_lws_free(void *p);
#define aws_lws_free_set_NULL(P)    do { aws_lws_free(P); (P) = NULL; } while(0)
#else
#define aws_lws_malloc(S, R)	aws_lws_realloc(NULL, S, R)
#define aws_lws_free(P)	aws_lws_realloc(P, 0, "aws_lws_free")
#define aws_lws_free_set_NULL(P)	do { aws_lws_realloc(P, 0, "free"); (P) = NULL; } while(0)
#endif

int
__lws_create_event_pipes(struct aws_lws_context *context);

int
aws_lws_plat_apply_FD_CLOEXEC(int n);

const struct aws_lws_plat_file_ops *
aws_lws_vfs_select_fops(const struct aws_lws_plat_file_ops *fops, const char *vfs_path,
		    const char **vpath);

/* aws_lws_plat_ */

int
aws_lws_plat_context_early_init(void);
void
aws_lws_plat_context_early_destroy(struct aws_lws_context *context);
void
aws_lws_plat_context_late_destroy(struct aws_lws_context *context);

int
aws_lws_plat_init(struct aws_lws_context *context,
	      const struct aws_lws_context_creation_info *info);
int
aws_lws_plat_drop_app_privileges(struct aws_lws_context *context, int actually_drop);

#if defined(LWS_WITH_UNIX_SOCK) && !defined(WIN32)
int
aws_lws_plat_user_colon_group_to_ids(const char *u_colon_g, uid_t *puid, gid_t *pgid);
#endif

int
aws_lws_plat_ntpclient_config(struct aws_lws_context *context);

int
aws_lws_plat_ifname_to_hwaddr(int fd, const char *ifname, uint8_t *hwaddr, int len);

int
aws_lws_plat_vhost_tls_client_ctx_init(struct aws_lws_vhost *vhost);

int
aws_lws_check_byte_utf8(unsigned char state, unsigned char c);
int LWS_WARN_UNUSED_RESULT
aws_lws_check_utf8(unsigned char *state, unsigned char *buf, size_t len);
int alloc_file(struct aws_lws_context *context, const char *filename,
			  uint8_t **buf, aws_lws_filepos_t *amount);

int
aws_lws_lec_scratch(aws_lws_lec_pctx_t *ctx);
void
aws_lws_lec_signed(aws_lws_lec_pctx_t *ctx, int64_t num);

int
aws_lws_cose_key_checks(const aws_lws_cose_key_t *key, int64_t kty, int64_t alg,
		    int key_op, const char *crv);

void aws_lws_msleep(unsigned int);

void
aws_lws_context_destroy2(struct aws_lws_context *context);

#if !defined(PRIu64)
#define PRIu64 "llu"
#endif

#if defined(LWS_WITH_ABSTRACT)
#include "private-lib-abstract.h"
#endif

#ifdef __cplusplus
};
#endif

#endif

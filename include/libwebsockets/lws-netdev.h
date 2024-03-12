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

#define LWS_WIFI_MAX_SCAN_TRACK 16
#define LWS_ETH_ALEN 6

typedef uint8_t	aws_lws_wifi_ch_t;
typedef int8_t aws_lws_wifi_rssi_t;
struct aws_lws_netdev_instance;

typedef enum {
	LWSNDTYP_UNKNOWN,
	LWSNDTYP_WIFI,
	LWSNDTYP_ETH,
} aws_lws_netdev_type_t;

/*
 * Base class for netdev configuration
 */

typedef struct aws_lws_netdev_config {
	void				*plat_config;
} aws_lws_netdev_config_t;

/*
 * Const Logical generic network interface ops
 */

typedef struct aws_lws_netdev_ops {
	struct aws_lws_netdev_instance * (*create)(struct aws_lws_context *ctx,
					       const struct aws_lws_netdev_ops *ops,
					       const char *name, void *platinfo);
	int (*configure)(struct aws_lws_netdev_instance *nd,
			 aws_lws_netdev_config_t *config);
	int (*up)(struct aws_lws_netdev_instance *nd);
	int (*down)(struct aws_lws_netdev_instance *nd);
	int (*event)(struct aws_lws_netdev_instance *nd, aws_lws_usec_t timestamp,
		     void *buf, size_t len);
	/**< these are SMD events coming from lws event loop thread context */
	void (*destroy)(struct aws_lws_netdev_instance **pnd);
	int (*connect)(struct aws_lws_netdev_instance *wnd, const char *ssid,
			    const char *passphrase, uint8_t *bssid);
	void (*scan)(struct aws_lws_netdev_instance *nd);
} aws_lws_netdev_ops_t;

/*
 * Network devices on this platform
 *
 * We also hold a list of all known network credentials (when they are needed
 * because there is a network interface without anything to connect to) and
 * the aws_lws_settings instance they are stored in
 */

typedef struct aws_lws_netdevs {
	aws_lws_dll2_owner_t		owner;
	/**< list of netdevs / aws_lws_netdev_instance_t -based objects */

	aws_lws_dll2_owner_t		owner_creds;
	/**< list of known credentials */
	struct aws_lwsac			*ac_creds;
	/**< aws_lwsac holding retreived credentials settings, or NULL */
	aws_lws_settings_instance_t		*si;

	aws_lws_sockaddr46			sa46_dns_resolver;

	uint8_t				refcount_creds;
	/**< when there are multiple netdevs, must refcount creds in mem */
} aws_lws_netdevs_t;

/*
 * Base class for an allocated instantiated derived object using aws_lws_netdev_ops,
 * ie, a specific ethernet device
 */

typedef struct aws_lws_netdev_instance {
	const char			*name;
	const aws_lws_netdev_ops_t		*ops;
	void				*platinfo;
	aws_lws_dll2_t			list;
	uint8_t				mac[LWS_ETH_ALEN];
	uint8_t				type; /* aws_lws_netdev_type_t */
} aws_lws_netdev_instance_t;

enum {
	LNDIW_ALG_OPEN,
	LNDIW_ALG_WPA2,

	LNDIW_MODE_STA			= (1 << 0),
	LNDIW_MODE_AP			= (1 << 1),
	LNDIW_UP			= (1 << 7),

	LNDIW_ACQ_IPv4			= (1 << 0),
	LNDIW_ACQ_IPv6			= (1 << 1),
};

/*
 * Group AP / Station State
 */

typedef enum {
	LWSNDVWIFI_STATE_INITIAL,
		/*
		 * We should gratuitously try whatever last worked for us, then
		 * if that fails, worry about the rest of the logic
		 */
	LWSNDVWIFI_STATE_SCAN,
		/*
		 * Unconnected, scanning: AP known in one of the config slots ->
		 * configure it, start timeout + LWSNDVWIFI_STATE_STAT, if no AP
		 * already up in same group with lower MAC, after a random
		 * period start up our AP (LWSNDVWIFI_STATE_AP)
		 */
	LWSNDVWIFI_STATE_AP,
		/* Trying to be the group AP... periodically do a scan
		 * LWSNDVWIFI_STATE_AP_SCAN, faster and then slower
       		 */
	LWSNDVWIFI_STATE_AP_SCAN,
		/*
		 * doing a scan while trying to be the group AP... if we see a
		 * lower MAC being the AP for the same group AP, abandon being
		 * an AP and join that AP as a station
		 */
	LWSNDVWIFI_STATE_STAT_GRP_AP,
		/*
		 * We have decided to join another group member who is being the
		 * AP, as its MAC is lower than ours.  This is a stable state,
		 * but we still do periodic scans
		 * LWSNDVWIFI_STATE_STAT_GRP_AP_SCAN and will always prefer an
		 * AP configured in a slot.
		 */
	LWSNDVWIFI_STATE_STAT_GRP_AP_SCAN,
		/*
		 * We have joined a group member who is doing the AP job... we
		 * want to check every now and then if a configured AP has
		 * appeared that we should better use instead.  Otherwise stay
		 * in LWSNDVWIFI_STATE_STAT_GRP_AP
		 */
	LWSNDVWIFI_STATE_STAT,
		/*
		 * trying to connect to another non-group AP. If we don't get an
		 * IP within a timeout and retries, mark it as unusable it and go back
		 */
	LWSNDVWIFI_STATE_STAT_HAPPY,
} aws_lws_netdev_wifi_state_t;

/*
 * Generic WIFI credentials
 */

typedef struct aws_lws_wifi_creds {
	aws_lws_dll2_t			list;

	uint8_t				bssid[LWS_ETH_ALEN];
	char				passphrase[64];
	char				ssid[33];
	uint8_t				alg;
} aws_lws_wifi_creds_t;

/*
 * Generic WIFI Network Device Instance
 */

typedef struct aws_lws_netdev_instance_wifi {
	aws_lws_netdev_instance_t		inst;
	aws_lws_dll2_owner_t		scan; /* sorted scan results */
	aws_lws_sorted_usec_list_t		sul_scan;

	aws_lws_wifi_creds_t		*ap_cred;
	const char			*ap_ip;

	const char			*sta_ads;

	char				current_attempt_ssid[33];
	uint8_t				current_attempt_bssid[LWS_ETH_ALEN];

	uint8_t				flags;
	uint8_t				state; /* aws_lws_netdev_wifi_state_t */
} aws_lws_netdev_instance_wifi_t;

/*
 * Logical scan results sorted list item
 */

typedef struct aws_lws_wifi_sta {
	aws_lws_dll2_t			list;

	uint32_t			last_seen; /* unix time */
	uint32_t			last_tried; /* unix time */

	uint8_t				bssid[LWS_ETH_ALEN];
	char				*ssid; /* points to overallocation */
	uint8_t				ssid_len;
	aws_lws_wifi_ch_t			ch;
	aws_lws_wifi_rssi_t			rssi[8];
	int16_t				rssi_avg;
	uint8_t				authmode;

	uint8_t				rssi_count;
	uint8_t				rssi_next;

	/* ssid overallocated afterwards */
} aws_lws_wifi_sta_t;

#define rssi_averaged(_x) (_x->rssi_count ? \
		((int)_x->rssi_avg / (int)_x->rssi_count) : \
			-200)

LWS_VISIBLE LWS_EXTERN aws_lws_netdevs_t *
aws_lws_netdevs_from_ctx(struct aws_lws_context *ctx);

LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_credentials_settings_set(aws_lws_netdevs_t *nds);

LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_credentials_settings_get(aws_lws_netdevs_t *nds);

LWS_VISIBLE LWS_EXTERN struct aws_lws_netdev_instance *
aws_lws_netdev_wifi_create_plat(struct aws_lws_context *ctx,
			    const aws_lws_netdev_ops_t *ops, const char *name,
			    void *platinfo);
LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_wifi_configure_plat(struct aws_lws_netdev_instance *nd,
			       aws_lws_netdev_config_t *config);
LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_wifi_event_plat(struct aws_lws_netdev_instance *nd, aws_lws_usec_t timestamp,
			   void *buf, size_t len);
LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_wifi_up_plat(struct aws_lws_netdev_instance *nd);
LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_wifi_down_plat(struct aws_lws_netdev_instance *nd);
LWS_VISIBLE LWS_EXTERN void
aws_lws_netdev_wifi_destroy_plat(struct aws_lws_netdev_instance **pnd);
LWS_VISIBLE LWS_EXTERN void
aws_lws_netdev_wifi_scan_plat(aws_lws_netdev_instance_t *nd);

LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_wifi_connect_plat(aws_lws_netdev_instance_t *wnd, const char *ssid,
			     const char *passphrase, uint8_t *bssid);

LWS_VISIBLE LWS_EXTERN aws_lws_netdev_instance_t *
aws_lws_netdev_find(aws_lws_netdevs_t *netdevs, const char *ifname);

#define aws_lws_netdev_wifi_plat_ops \
	.create				= aws_lws_netdev_wifi_create_plat, \
	.configure			= aws_lws_netdev_wifi_configure_plat, \
	.event				= aws_lws_netdev_wifi_event_plat, \
	.up				= aws_lws_netdev_wifi_up_plat, \
	.down				= aws_lws_netdev_wifi_down_plat, \
	.connect			= aws_lws_netdev_wifi_connect_plat, \
	.scan				= aws_lws_netdev_wifi_scan_plat, \
	.destroy			= aws_lws_netdev_wifi_destroy_plat

/*
 * This is for plat / OS level init that is necessary to be able to use
 * networking or wifi at all, without mentioning any specific device
 */

LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_plat_init(void);

LWS_VISIBLE LWS_EXTERN int
aws_lws_netdev_plat_wifi_init(void);

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

#include <private-lib-core.h>

static const aws_lws_struct_map_t lsm_wifi_creds[] = {
	LSM_CARRAY	(aws_lws_wifi_creds_t, ssid,		"ssid"),
	LSM_CARRAY	(aws_lws_wifi_creds_t, passphrase,		"passphrase"),
	LSM_UNSIGNED	(aws_lws_wifi_creds_t, alg,			"alg"),
	LSM_STRING_PTR	(aws_lws_wifi_creds_t, bssid,		"bssid"),
};

static const aws_lws_struct_map_t lsm_netdev_credentials[] = {
	LSM_LIST	(aws_lws_netdevs_t, owner_creds, aws_lws_wifi_creds_t, list,
			 NULL, lsm_wifi_creds,			"credentials"),
};

static const aws_lws_struct_map_t lsm_netdev_schema[] = {
        LSM_SCHEMA      (aws_lws_netdevs_t, NULL, lsm_netdev_credentials,
                                              "lws-netdev-creds"),
};


//LSM_CHILD_PTR	(aws_lws_netdev_instance_wifi_t, ap_cred, aws_lws_wifi_creds_t,
//		 NULL, lsm_wifi_creds,			"ap_cred"),
//LSM_STRING_PTR	(aws_lws_netdev_instance_wifi_t, ap_ip,	"ap_ip"),

int
aws_lws_netdev_credentials_settings_set(aws_lws_netdevs_t *nds)
{
	aws_lws_struct_serialize_t *js;
	size_t w = 0, max = 2048;
	int n, r = 1;
	uint8_t *buf;

	buf = aws_lws_malloc(max, __func__); /* length should be computed */

	js = aws_lws_struct_json_serialize_create(lsm_netdev_schema,
			LWS_ARRAY_SIZE(lsm_netdev_schema), 0, nds);
	if (!js)
		goto bail;

	n = aws_lws_struct_json_serialize(js, buf, max, &w);
	aws_lws_struct_json_serialize_destroy(&js);
	if (n != LSJS_RESULT_FINISH)
		goto bail;

	aws_lwsl_notice("%s: setting %s\n", __func__, buf);

	if (!aws_lws_settings_plat_set(nds->si, "netdev.creds", buf, w))
		r = 0;

bail:
	if (r)
		aws_lwsl_err("%s: failed\n", __func__);
	aws_lws_free(buf);

	return r;
}

int
aws_lws_netdev_credentials_settings_get(aws_lws_netdevs_t *nds)
{
	struct lejp_ctx ctx;
	aws_lws_struct_args_t a;
	size_t l = 0;
	uint8_t *buf;
	int m;

	memset(&a, 0, sizeof(a));

	if (aws_lws_settings_plat_get(nds->si, "netdev.creds", NULL, &l)) {
		aws_lwsl_notice("%s: not in settings\n", __func__);
		return 1;
	}

	buf = aws_lws_malloc(l, __func__);
	if (!buf)
		return 1;

	if (aws_lws_settings_plat_get(nds->si, "netdev.creds", buf, &l)) {
		aws_lwsl_err("%s: unexpected settings get fail\n", __func__);
		goto bail;
	}

	a.map_st[0] = lsm_netdev_schema;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_netdev_schema);
	a.ac_block_size = 512;

	aws_lws_struct_json_init_parse(&ctx, NULL, &a);
	m = lejp_parse(&ctx, (uint8_t *)buf, l);
	aws_lws_free(buf);
	if (m < 0 || !a.dest) {
		aws_lwsl_notice("%s: JSON decode failed '%s'\n",
			    __func__, lejp_error_to_string(m));
		goto bail1;
	}

	/*
	 * Forcibly set the state of the nds creds owner to the synthesized
	 * one in the ac, and keep the ac for as long as we keep the creds out
	 */
	nds->owner_creds = ((aws_lws_netdevs_t *)a.dest)->owner_creds;
	nds->ac_creds = a.ac;

	return 0;

bail:
	aws_lws_free(buf);
bail1:
	aws_lwsac_free(&a.ac);

	return 1;
}

aws_lws_wifi_creds_t *
aws_lws_netdev_credentials_find(aws_lws_netdevs_t *netdevs, const char *ssid,
			    const uint8_t *bssid)
{
	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, aws_lws_dll2_get_head(
	                                               &netdevs->owner_creds)) {
		aws_lws_wifi_creds_t *w = aws_lws_container_of(p, aws_lws_wifi_creds_t, list);

		if (!strcmp(ssid, (const char *)&w[1]) &&
		    !memcmp(bssid, w->bssid, 6))
			return w;

	} aws_lws_end_foreach_dll(p);

	return NULL;
}

aws_lws_netdev_instance_t *
aws_lws_netdev_find(aws_lws_netdevs_t *netdevs, const char *ifname)
{
	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, aws_lws_dll2_get_head(
	                                               &netdevs->owner)) {
		aws_lws_netdev_instance_t *ni = aws_lws_container_of(p,
						aws_lws_netdev_instance_t, list);

		if (!strcmp(ifname, ni->name))
			return ni;

	} aws_lws_end_foreach_dll(p);

	return NULL;
}

/*
 * Context forwards NETWORK related smd here, in lws thread context
 */

int
aws_lws_netdev_smd_cb(void *opaque, aws_lws_smd_class_t _class, aws_lws_usec_t timestamp,
		  void *buf, size_t len)
{
	struct aws_lws_context *ctx = (struct aws_lws_context *)opaque;
	const char *iface;
	char setname[16];
	size_t al = 0;

	/* deal with anything from whole-network perspective */

	/* pass through netdev-specific messages to correct platform handler */

	iface = aws_lws_json_simple_find(buf, len, "\"if\":", &al);
	if (!iface)
		return 0;

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, aws_lws_dll2_get_head(
	                                                 &ctx->netdevs.owner)) {
		aws_lws_netdev_instance_t *ni = aws_lws_container_of(
						p, aws_lws_netdev_instance_t, list);

		if (!strncmp(ni->name, iface, al)) {

			/*
			 * IP assignment on our netif?  We can deal with marking
			 * the last successful association generically...
			 */

			if (ni->type == LWSNDTYP_WIFI &&
			    !aws_lws_json_simple_strcmp(buf, len, "\"type\":",
							"ipacq")) {
				const char *ev = aws_lws_json_simple_find(buf, len,
							"\"ipv4\":", &al);
				aws_lws_netdev_instance_wifi_t *wnd =
					       (aws_lws_netdev_instance_wifi_t *)ni;

				if (!ev)
					return 0;

				aws_lws_snprintf(setname, sizeof(setname),
						"netdev.last.%s", iface);

				aws_lws_settings_plat_printf(ctx->netdevs.si,
					setname, "{\"ssid\":\"%s\",\"bssid\":"
					"\"%02X%02X%02X%02X%02X%02X\"}",
					wnd->current_attempt_ssid,
					wnd->current_attempt_bssid[0],
					wnd->current_attempt_bssid[1],
					wnd->current_attempt_bssid[2],
					wnd->current_attempt_bssid[3],
					wnd->current_attempt_bssid[4],
					wnd->current_attempt_bssid[5]);
			}

			/*
			 * Pass it through to related netdev instance for
			 * private actions
			 */

			return ni->ops->event(ni, timestamp, buf, len);
		}

	} aws_lws_end_foreach_dll(p);

	return 0;
}

/*
 * This is the generic part of the netdev instance initialization that's always
 * the same, regardless of the netdev type
 */

void
aws_lws_netdev_instance_create(aws_lws_netdev_instance_t *ni, struct aws_lws_context *ctx,
			   const aws_lws_netdev_ops_t *ops, const char *name,
			   void *platinfo)
{
	ni->ops		= ops;
	ni->name	= name;
	ni->platinfo	= platinfo;

	/* add us to the list of active netdevs */

	aws_lws_dll2_add_tail(&ni->list, &ctx->netdevs.owner);
}

void
aws_lws_netdev_instance_remove_destroy(struct aws_lws_netdev_instance *ni)
{
	aws_lws_dll2_remove(&ni->list);
	aws_lws_free(ni);
}

aws_lws_netdevs_t *
aws_lws_netdevs_from_ctx(struct aws_lws_context *ctx)
{
	return &ctx->netdevs;
}

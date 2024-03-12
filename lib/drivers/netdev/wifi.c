/*
 * libwebsockets - aws_lws_netdev_wifi generic state handling
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
 *
 * The generic wifi netdevs follow a
 */

#include "private-lib-core.h"

int
aws_lws_netdev_wifi_rssi_sort_compare(const aws_lws_dll2_t *d, const aws_lws_dll2_t *i)
{
	const aws_lws_wifi_sta_t *wsd = (const aws_lws_wifi_sta_t *)d,
			     *wsi = (const aws_lws_wifi_sta_t *)i;
	return rssi_averaged(wsd) > rssi_averaged(wsi);
}

void
aws_lws_netdev_wifi_scan_empty(aws_lws_netdev_instance_wifi_t *wnd)
{
	aws_lws_start_foreach_dll_safe(struct aws_lws_dll2 *, p, p1, aws_lws_dll2_get_head(
	                                                       &wnd->scan)) {
		aws_lws_wifi_sta_t *s = aws_lws_container_of(p, aws_lws_wifi_sta_t, list);

		aws_lws_dll2_remove(p);
		aws_lws_free(s);

	} aws_lws_end_foreach_dll_safe(p, p1);
}

void
aws_lws_netdev_wifi_scan(aws_lws_sorted_usec_list_t *sul)
{
	aws_lws_netdev_instance_wifi_t *wnd = aws_lws_container_of(sul,
					aws_lws_netdev_instance_wifi_t, sul_scan);

	wnd->inst.ops->scan(&wnd->inst);
}

aws_lws_wifi_sta_t *
aws_lws_netdev_wifi_scan_find(aws_lws_netdev_instance_wifi_t *wnd, const char *ssid,
			  const uint8_t *bssid)
{
	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, aws_lws_dll2_get_head(
	                                                       &wnd->scan)) {
		aws_lws_wifi_sta_t *w = aws_lws_container_of(p, aws_lws_wifi_sta_t, list);

		if (!strcmp(ssid, (const char *)&w[1]) &&
		    !memcmp(bssid, w->bssid, 6))
			return w;

	} aws_lws_end_foreach_dll(p);

	return NULL;
}

int
aws_lws_netdev_wifi_scan_select(aws_lws_netdev_instance_wifi_t *wnd)
{
	aws_lws_netdevs_t *netdevs = aws_lws_netdevs_from_ndi(&wnd->inst);
	struct aws_lws_context *cx = aws_lws_context_from_netdevs(netdevs);
	uint32_t least_recent = 0xffffffff;
	aws_lws_wifi_creds_t *pc = NULL;
	aws_lws_wifi_sta_t *pw = NULL;

	/*
	 * Trim enough of the lowest RSSI guys in order to get us below the
	 * limit we are allowed to keep track of...
	 */

	while (wnd->scan.count > LWS_WIFI_MAX_SCAN_TRACK) {
		struct aws_lws_dll2 *p = aws_lws_dll2_get_tail(&wnd->scan);
		aws_lws_wifi_sta_t *w = aws_lws_container_of(p, aws_lws_wifi_sta_t, list);

		aws_lws_dll2_remove(p);
		aws_lws_free(w);
	}

	/*
	 * ... let's dump what's left
	 */

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p, aws_lws_dll2_get_head(
	                                                       &wnd->scan)) {
		aws_lws_wifi_sta_t *w = aws_lws_container_of(p, aws_lws_wifi_sta_t, list);

		aws_lwsl_notice("%s: %s, %02X:%02X:%02X:%02X:%02X:%02X, ch %d, rssi %d\n",
			    __func__, (const char *)&w[1], w->bssid[0],
			    w->bssid[1], w->bssid[2], w->bssid[3], w->bssid[4],
			    w->bssid[5], w->ch, rssi_averaged(w));

	} aws_lws_end_foreach_dll(p);

	/*
	 * make sure we have our device's connection credentials at hand
	 */

	if (!netdevs->ac_creds &&
	    aws_lws_netdev_credentials_settings_get(netdevs))
		return 0;
	netdevs->refcount_creds++;

	/*
	 * Let's go through each starting from the best RSSI seeing if we
	 * have credentials... if we do, pick the one we least-recently tried
	 */

	aws_lws_start_foreach_dll(struct aws_lws_dll2 *, p1, wnd->scan.head) {
		aws_lws_wifi_sta_t *w = aws_lws_container_of(p1, aws_lws_wifi_sta_t, list);

		aws_lws_start_foreach_dll(struct aws_lws_dll2 *, q,
				      netdevs->owner_creds.head) {
			aws_lws_wifi_creds_t *c = aws_lws_container_of(q,
							       aws_lws_wifi_creds_t,
							       list);

			if (!strcmp((const char *)&w[1], c->ssid) &&
			    w->last_seen < least_recent) {
				/*
				 * Not <= so we stick with higher RSSI when
				 * all 0
				 */
				pc = c;
				pw = w;
				least_recent = w->last_seen;
			}

		} aws_lws_end_foreach_dll(q);

	} aws_lws_end_foreach_dll(p1);


	if (least_recent != 0xffffffff) {
		/*
		 * We picked one to try... note what we're trying so we can
		 * record it in settings as last successful
		 */
		aws_lws_strncpy(wnd->current_attempt_ssid, (const char *)&pw[1],
			    sizeof(wnd->current_attempt_ssid));
		memcpy(wnd->current_attempt_bssid, pw->bssid, LWS_ETH_ALEN);
		wnd->inst.ops->connect(&wnd->inst, pc->ssid, pc->passphrase,
					pw->bssid);
	} else {
		/*
		 * We couldn't see anyone we recognized on this scan, let's
		 * rescan in a bit
		 */

		aws_lwsl_notice("%s: nothing usable in scan, redoing in 3s\n", __func__);
		aws_lws_sul_schedule(cx, 0, &wnd->sul_scan, aws_lws_netdev_wifi_scan,
				 3 * LWS_US_PER_SEC);
	}

	if (!--netdevs->refcount_creds) {
		aws_lws_dll2_owner_clear(&netdevs->owner_creds);
		aws_lwsac_free(&netdevs->ac_creds);
	}

	return 0;
}

/*
 * Initially our best bet is just try to reconnect to whatever we last
 * succeeded to connect to
 */

int
aws_lws_netdev_wifi_redo_last(aws_lws_netdev_instance_wifi_t *wnd)
{
	aws_lws_netdevs_t *netdevs = aws_lws_netdevs_from_ndi(&wnd->inst);
	uint8_t buf[256], bssid[LWS_ETH_ALEN];
	const char *ssid, *pp = "", *pb;
	char setname[16], ssid_copy[33];
	size_t l = sizeof(buf), al;
	aws_lws_wifi_creds_t *cred;

	/*
	 * Let's try to retreive the last successful connect info for this
	 * netdev
	 */

	aws_lws_snprintf(setname, sizeof(setname), "netdev.last.%s", wnd->inst.name);
	if (aws_lws_settings_plat_get(netdevs->si, setname, buf, &l))
		return 1;

	aws_lwsl_notice("%s: last successful %s\n", __func__, buf);

	ssid = aws_lws_json_simple_find((const char *)buf, l, "\"ssid\":", &al);
	if (!ssid || al > 32)
		return 1;

	memcpy(ssid_copy, ssid, al);
	ssid_copy[al + 1] = '\0';

	pb = aws_lws_json_simple_find((const char *)buf, l, "\"bssid\":", &al);
	if (!pb)
		return 1;
	aws_lws_hex_to_byte_array(pb, bssid, sizeof(bssid));

	/*
	 * make sure we have our device's connection credentials at hand
	 */

	if (!netdevs->ac_creds &&
	    aws_lws_netdev_credentials_settings_get(netdevs))
		return 1;
	netdevs->refcount_creds++;

	cred = aws_lws_netdev_credentials_find(netdevs, ssid_copy, bssid);
	if (cred)
		pp = cred->passphrase;

	aws_lws_strncpy(wnd->current_attempt_ssid, ssid_copy,
		    sizeof(wnd->current_attempt_ssid));
	memcpy(wnd->current_attempt_bssid, bssid, LWS_ETH_ALEN);
	wnd->inst.ops->connect(&wnd->inst, ssid_copy, pp, bssid);

	if (!--netdevs->refcount_creds) {
		aws_lws_dll2_owner_clear(&netdevs->owner_creds);
		aws_lwsac_free(&netdevs->ac_creds);
	}

	return 0;
}

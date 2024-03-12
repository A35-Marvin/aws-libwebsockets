/*
 * devices for ESP32 C3 dev board
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#define LWIP_PROVIDE_ERRNO 1
#define _ESP_PLATFORM_ERRNO_H_

#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include <driver/gpio.h>

#include <libwebsockets.h>

struct aws_lws_led_state *lls;
aws_lws_display_state_t lds;
struct aws_lws_button_state *bcs;
aws_lws_netdev_instance_wifi_t *wnd;

/*
 * Button controller
 */

static const aws_lws_button_map_t bcm[] = {
	{
		.gpio			= GPIO_NUM_0,
		.smd_interaction_name	= "user"
	},
};

static const aws_lws_button_controller_t bc = {
	.smd_bc_name			= "bc",
	.gpio_ops			= &aws_lws_gpio_plat,
	.button_map			= &bcm[0],
	.active_state_bitmap		= 0,
	.count_buttons			= LWS_ARRAY_SIZE(bcm),
};

/*
 * pwm controller
 */

static const aws_lws_pwm_map_t pwm_map[] = {
	{ .gpio = GPIO_NUM_8, .index = 0, .active_level = 1 }
};

static const aws_lws_pwm_ops_t pwm_ops = {
	aws_lws_pwm_plat_ops,
	.pwm_map			= &pwm_map[0],
	.count_pwm_map			= LWS_ARRAY_SIZE(pwm_map)
};

#if 0
static const aws_lws_display_ssd1306_t disp = {
	.disp = {
		aws_lws_display_ssd1306_ops,
		.w			= 128,
		.h			= 64
	},
	.i2c				= (aws_lws_i2c_ops_t *)&li2c,
	.gpio				= &aws_lws_gpio_plat,
	.reset_gpio			= GPIO_NUM_16,
	.i2c7_address			= SSD1306_I2C7_ADS1
};
#endif

/*
 * led controller
 */

static const aws_lws_led_gpio_map_t lgm[] = {
	{
		.name			= "alert",
		.gpio			= GPIO_NUM_8,
		.pwm_ops		= &pwm_ops, /* managed by pwm */
		.active_level		= 1,
	},
};

static const aws_lws_led_gpio_controller_t lgc = {
	.led_ops			= aws_lws_led_gpio_ops,
	.gpio_ops			= &aws_lws_gpio_plat,
	.led_map			= &lgm[0],
	.count_leds			= LWS_ARRAY_SIZE(lgm)
};

/*
 * Settings stored in platform nv
 */

static const aws_lws_settings_ops_t sett = {
	aws_lws_settings_ops_plat
};

/*
 * Wifi
 */

static const aws_lws_netdev_ops_t wifi_ops = {
	aws_lws_netdev_wifi_plat_ops
};

int
init_plat_devices(struct aws_lws_context *ctx)
{
	aws_lws_settings_instance_t *si;
	aws_lws_netdevs_t *netdevs = aws_lws_netdevs_from_ctx(ctx);

	si = aws_lws_settings_init(&sett, (void *)"nvs");
	if (!si) {
		aws_lwsl_err("%s: failed to create settings instance\n", __func__);
		return 1;
	}
	netdevs->si = si;

#if 0
	/*
	 * This is a temp hack to bootstrap the settings to contain the test
	 * AP ssid and passphrase for one time, so the settings can be stored
	 * while there's no UI atm
	 */
	{
		aws_lws_wifi_creds_t creds;

		memset(&creds, 0, sizeof(creds));

		aws_lws_strncpy(creds.ssid, "xxx", sizeof(creds.ssid));
		aws_lws_strncpy(creds.passphrase, "xxx", sizeof(creds.passphrase));
		aws_lws_dll2_add_tail(&creds.list, &netdevs->owner_creds);

		if (aws_lws_netdev_credentials_settings_set(netdevs)) {
			aws_lwsl_err("%s: failed to write bootstrap creds\n",
					__func__);
			return 1;
		}
	}
#endif

	/* create the wifi network device and configure it */

	wnd = (aws_lws_netdev_instance_wifi_t *)
			wifi_ops.create(ctx, &wifi_ops, "wl0", NULL);
	if (!wnd) {
		aws_lwsl_err("%s: failed to create wifi object\n", __func__);
		return 1;
	}

	wnd->flags |= LNDIW_MODE_STA;

	if (wifi_ops.configure(&wnd->inst, NULL)) {
		aws_lwsl_err("%s: failed to configure wifi object\n", __func__);
		return 1;
	}

	wifi_ops.up(&wnd->inst);
	esp_wifi_set_mode(WIFI_MODE_STA);
aws_lws_netdev_wifi_scan_plat(&wnd->inst);
	lls = lgc.led_ops.create(&lgc.led_ops);
	if (!lls) {
		aws_lwsl_err("%s: could not create led\n", __func__);
		return 1;
	}

	/* pwm init must go after the led controller init */

//	pwm_ops.init(&pwm_ops);

	bcs = aws_lws_button_controller_create(ctx, &bc);
	if (!bcs) {
		aws_lwsl_err("%s: could not create buttons\n", __func__);
		return 1;
	}

	aws_lws_button_enable(bcs, 0, aws_lws_button_get_bit(bcs, "user"));
//	aws_lws_led_transition(lls, "alert", &aws_lws_pwmseq_static_off,
//					 &aws_lws_pwmseq_static_on);

	aws_lwsl_notice("%s: exiting device init\n", __func__);
	return 0;
}

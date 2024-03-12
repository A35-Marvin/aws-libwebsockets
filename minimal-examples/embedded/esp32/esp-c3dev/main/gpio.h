/*
 * lws genric gpio
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * You should typedef aws__lws_plat_gpio_t to int or whatever before
 * including this.  It's better to wrap this in a platform-specific
 * include that does that and then include the platform-specific
 * include in your code.
 */

#if !defined(__LWS_GPIO_H__)
#define __LWS_GPIO_H__

typedef struct aws_lws_gpio_ops {
	void (*mode_write)(aws__lws_plat_gpio_t gpio);
	void (*mode_read)(aws__lws_plat_gpio_t gpio);
	int (*read)(aws__lws_plat_gpio_t gpio);
	void (*set)(aws__lws_plat_gpio_t gpio, int val);
} aws_lws_gpio_ops_t;

#endif

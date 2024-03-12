/*
 * Generic i2c ops
 *
 * These ops always appear first in an implementation-specific
 * object, so the generic ops can be cast to the implementation-
 * specific object in the handlers.
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#if !defined(__LWS_I2C_H__)
#define __LWS_I2C_H__

#include <stdint.h>
#include <stddef.h>

typedef struct aws_lws_i2c_ops {
	int  (*start)(struct aws_lws_i2c_ops *ctx);
	void (*stop)(struct aws_lws_i2c_ops *ctx);
	int  (*write)(struct aws_lws_i2c_ops *ctx, uint8_t data);
	int  (*read)(struct aws_lws_i2c_ops *ctx);
	void (*set_ack)(struct aws_lws_i2c_ops *octx, int ack);
} aws_lws_i2c_ops_t;

int
aws_lws_i2c_command(aws_lws_i2c_ops_t *ctx, uint8_t ads, uint8_t c);

int
aws_lws_i2c_command_list(aws_lws_i2c_ops_t *ctx, uint8_t ads, const uint8_t *buf, size_t len);

#endif


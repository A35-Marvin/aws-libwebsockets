/*
 * lws-minimal-esp32
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <stdint.h>
#include <stddef.h>
#include "i2c.h"
#include "gpio-esp32.h"

typedef struct aws_lws_bb_i2c {
	aws_lws_i2c_ops_t		bb_ops; /* init to aws_lws_bb_i2c_ops */

	/* implementation-specific members */

	_lws_plat_gpio_t	scl;
	_lws_plat_gpio_t	sda;

	const aws_lws_gpio_ops_t	*gpio;
	void (*delay)(void);
} aws_lws_bb_i2c_t;

#define aws_lws_bb_i2c_ops \
	{ \
		.start = aws_lws_bb_i2c_start, \
		.stop = aws_lws_bb_i2c_stop, \
		.write = aws_lws_bb_i2c_write, \
		.read = aws_lws_bb_i2c_read, \
		.set_ack = aws_lws_bb_i2c_set_ack, \
	}

int
aws_lws_bb_i2c_start(aws_lws_i2c_ops_t *octx);

void
aws_lws_bb_i2c_stop(aws_lws_i2c_ops_t *octx);

int
aws_lws_bb_i2c_write(aws_lws_i2c_ops_t *octx, uint8_t data);

int
aws_lws_bb_i2c_read(aws_lws_i2c_ops_t *octx);

void
aws_lws_bb_i2c_set_ack(aws_lws_i2c_ops_t *octx, int ack);



#include <driver/gpio.h>
#include "gpio-esp32.h"
	
static void
aws_lws_gpio_esp32_mode_write(_lws_plat_gpio_t gpio)
{
	gpio_reset_pin(gpio);
	gpio_set_pull_mode(gpio, GPIO_PULLUP_ONLY);
	gpio_set_direction(gpio, GPIO_MODE_INPUT_OUTPUT);
	gpio_set_level(gpio, 1);
}
static void
aws_lws_gpio_esp32_mode_read(_lws_plat_gpio_t gpio)
{
	gpio_set_pull_mode(gpio, GPIO_PULLUP_ONLY);
	gpio_set_direction(gpio, GPIO_MODE_INPUT);
	gpio_set_level(gpio, 1);
}
static int
aws_lws_gpio_esp32_read(_lws_plat_gpio_t gpio)
{
	return gpio_get_level(gpio);
}
static void
aws_lws_gpio_esp32_set(_lws_plat_gpio_t gpio, int val)
{
	gpio_set_level(gpio, val);
}

const aws_lws_gpio_ops_t aws_lws_gpio_esp32 = {
	.mode_write		= aws_lws_gpio_esp32_mode_write,
	.mode_read		= aws_lws_gpio_esp32_mode_read,
	.read			= aws_lws_gpio_esp32_read,
	.set			= aws_lws_gpio_esp32_set,
};


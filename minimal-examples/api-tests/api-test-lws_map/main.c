/*
 * lws-api-test-aws_lws_map
 *
 * Written in 2010-2021 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * unit tests for aws_lws_map
 */

#include <libwebsockets.h>

/* custom key and comparator for test 3 */

typedef struct mykey {
	int			key;
} mykey_t;

static int
compare_mykey_t(const aws_lws_map_key_t key1, size_t kl1,
		const aws_lws_map_value_t key2, size_t kl2)
{
	const mykey_t *m1 = (mykey_t *)key1, *m2 = (mykey_t *)key2;

	return m1->key != m2->key;
}

int main(int argc, const char **argv)
{
	int e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE,
			expected = 4, pass = 0;
	mykey_t k1 = { .key = 123 }, k2 = { .key = 234 }, k3 = { .key = 999 };
	struct aws_lwsac *ac = NULL;
	aws_lws_map_item_t *item;
	aws_lws_map_info_t info;
	aws_lws_map_t *map;
	const char *p;

	if ((p = aws_lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	aws_lws_set_log_level(logs, NULL);
	aws_lwsl_user("LWS API selftest: lws_map\n");

	/* Test 1: string keys */

	aws_lwsl_user("%s: test1\n", __func__);
	memset(&info, 0, sizeof(info));
	map = aws_lws_map_create(&info);
	if (!map) {
		e++;
		goto end_t1;
	}
	if (!aws_lws_map_item_create_ks(map, "abc", (aws_lws_map_value_t)"def", 3)) {
		e++;
		goto end_t1;
	}
	if (!aws_lws_map_item_create_ks(map, "123", (aws_lws_map_value_t)"4567", 4)) {
		e++;
		goto end_t1;
	}
	item = aws_lws_map_item_lookup_ks(map, "abc");
	if (!item) {
		e++;
		goto end_t1;
	}

	if (aws_lws_map_item_value_len(item) != 3 ||
	    memcmp(aws_lws_map_item_value(item), "def", 3)) {
		e++;
		goto end_t1;
	}

	item = aws_lws_map_item_lookup_ks(map, "123");
	if (!item) {
		e++;
		goto end_t1;
	}

	if (aws_lws_map_item_value_len(item) != 4 ||
	    memcmp(aws_lws_map_item_value(item), "4567", 4)) {
		e++;
		goto end_t1;
	}

	item = aws_lws_map_item_lookup_ks(map, "nope");
	if (item) {
		e++;
		goto end_t1;
	}

	pass++;

end_t1:
	aws_lws_map_destroy(&map);

	/* Test 2: Use aws_lwsac item allocators */

	aws_lwsl_user("%s: test2\n", __func__);
	memset(&info, 0, sizeof(info));
	info._alloc = aws_lws_map_alloc_lwsac;
	info._free = aws_lws_map_free_lwsac;
	info.opaque = (void *)&ac;

	map = aws_lws_map_create(&info);
	if (!map) {
		e++;
		goto end_t2;
	}
	if (!aws_lws_map_item_create_ks(map, "abc", "def", 3)) {
		e++;
		goto end_t2;
	}
	if (!aws_lws_map_item_create_ks(map, "123", "4567", 4)) {
		e++;
		goto end_t2;
	}
	item = aws_lws_map_item_lookup_ks(map, "abc");
	if (!item) {
		e++;
		goto end_t2;
	}

	if (aws_lws_map_item_value_len(item) != 3 ||
	    memcmp(aws_lws_map_item_value(item), "def", 3)) {
		e++;
		goto end_t2;
	}

	item = aws_lws_map_item_lookup_ks(map, "123");
	if (!item) {
		e++;
		goto end_t2;
	}

	if (aws_lws_map_item_value_len(item) != 4 ||
	    memcmp(aws_lws_map_item_value(item), "4567", 4)) {
		e++;
		goto end_t2;
	}

	item = aws_lws_map_item_lookup_ks(map, "nope");
	if (item) {
		e++;
		goto end_t2;
	}

	pass++;

end_t2:
	aws_lws_map_destroy(&map);
	aws_lwsac_free(&ac);

	/* Test 3: custom key object and comparator */

	aws_lwsl_user("%s: test3\n", __func__);
	memset(&info, 0, sizeof(info));
	info._compare = compare_mykey_t;

	map = aws_lws_map_create(&info);
	if (!map) {
		e++;
		goto end_t3;
	}
	if (!aws_lws_map_item_create(map, (aws_lws_map_key_t)&k1, sizeof(k1),
				      (aws_lws_map_value_t)"def", 3)) {
		aws_lwsl_err("%s: t3; a\n", __func__);
		e++;
		goto end_t3;
	}
	if (!aws_lws_map_item_create(map, (aws_lws_map_key_t)&k2, sizeof(k2),
				      (aws_lws_map_value_t)"4567", 4)) {
		aws_lwsl_err("%s: t3; b\n", __func__);
		e++;
		goto end_t3;
	}
	item = aws_lws_map_item_lookup(map, (aws_lws_map_key_t)&k1, sizeof(k1));
	if (!item) {
		aws_lwsl_err("%s: t3; c\n", __func__);
		e++;
		goto end_t3;
	}

	if (aws_lws_map_item_value_len(item) != 3 ||
	    memcmp(aws_lws_map_item_value(item), "def", 3)) {
		aws_lwsl_err("%s: t3; d\n", __func__);
		e++;
		goto end_t3;
	}

	item = aws_lws_map_item_lookup(map, (aws_lws_map_key_t)&k2, sizeof(k2));
	if (!item) {
		aws_lwsl_err("%s: t3; e\n", __func__);
		e++;
		goto end_t3;
	}

	if (aws_lws_map_item_value_len(item) != 4 ||
	    memcmp(aws_lws_map_item_value(item), "4567", 4)) {
		aws_lwsl_err("%s: t3; f\n", __func__);
		e++;
		goto end_t3;
	}

	item = aws_lws_map_item_lookup(map, (aws_lws_map_key_t)&k3, sizeof(k3));
	if (item) {
		aws_lwsl_err("%s: t3; g\n", __func__);
		e++;
		goto end_t3;
	}

	pass++;

end_t3:
	aws_lws_map_destroy(&map);

	/* Test 4: same key items */

	aws_lwsl_user("%s: test4\n", __func__);
	memset(&info, 0, sizeof(info));
	map = aws_lws_map_create(&info);
	if (!map) {
		e++;
		goto end_t4;
	}
	if (!aws_lws_map_item_create_ks(map, "abc", (aws_lws_map_value_t)"def", 3)) {
		e++;
		goto end_t4;
	}
	if (!aws_lws_map_item_create_ks(map, "abc", (aws_lws_map_value_t)"4567", 4)) {
		e++;
		goto end_t4;
	}
	item = aws_lws_map_item_lookup_ks(map, "abc");
	if (!item) {
		e++;
		goto end_t4;
	}

	if (aws_lws_map_item_value_len(item) != 4 ||
	    memcmp(aws_lws_map_item_value(item), "4567", 4)) {
		e++;
		goto end_t4;
	}

	pass++;

end_t4:
	aws_lws_map_destroy(&map);

	if (e)
		goto bail;

	aws_lwsl_user("Completed: PASS %d / %d\n", pass, expected);

	return 0;

bail:
	aws_lwsl_user("Completed: FAIL, passed %d / %d (e %d)\n", pass,
				expected, e);

	return 1;
}

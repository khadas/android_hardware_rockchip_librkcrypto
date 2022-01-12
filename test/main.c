/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "librkcrypto.h"
#include "test_otp_key_crypto.h"
#include "test_cipher.h"
#include "test_hash.h"

typedef enum {
	FUNC = 0,
	SPEED,
	SETKEY,
	CIPHER,
	HASH,
	HMAC,
	TEST_NULL,
} enum_func;

static const struct {
	const char *word;
	enum_func main_cmd;
} keyword[] = {
	{"func",	FUNC},
	{"speed",	SPEED},
	{"setkey",	SETKEY},
	{"cipher",	CIPHER},
	{"hash",	HASH},
	{"hmac",	HMAC},
	{NULL,		TEST_NULL},
};

static void printf_main_cmd(void)
{
	printf("Please entry one correct parameter when excuting the app!\n");
	printf("The correct parameters list:\n");

	for (int i = 0; keyword[i].word; i++)
		printf("	%s\n", keyword[i].word);

	printf("!!! NOTE: for 'setkey', it will write test keys to OTP area.\n");
}

static enum_func config_main_cmd(const char *cp)
{
	for (int i = 0; keyword[i].word; i++)
		if (strcasecmp(cp, keyword[i].word) == 0)
			return keyword[i].main_cmd;

	printf_main_cmd();
	return TEST_NULL;
}

int main(int argc, char *argv[])
{
	uint32_t invokeCommand = TEST_NULL;
	uint32_t count = 1000;

	if (argc < 2) {
		printf_main_cmd();
		return 0;
	}

	invokeCommand = config_main_cmd(argv[1]);
	printf("##### Test begin #####\n");

	switch (invokeCommand) {
	case FUNC:
		test_func_otp_key_cipher();
		break;
	case SPEED:
		if (argc < 3)
			count = 100; //default
		else
			count = strtol(argv[2], NULL, 10);

		test_speed_otp_key_cipher(count);
		break;
	case SETKEY:
		test_write_otp_key();
		break;
	case CIPHER:
		test_cipher();
		break;
	case HASH:
		test_hash();
		break;
	case HMAC:
		test_hmac();
		break;
	default:
		break;
	}

	printf("##### Test done #####\n");
	return 0;
}

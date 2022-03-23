/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_cipher.h"
#include "test_hash.h"
#include "test_stress.h"

void stress_test(int test_cnt)
{
	int i;
	int verbose = 0;
	RK_RES res;

	printf("===================== stress test begin =====================\n");
	for (i = 0; i < test_cnt; i++) {
		printf("stress test %d/%d...\n", i + 1, test_cnt);

		res = test_cipher(verbose);
		if (res) {
			printf("test_cipher error[%x]\n", res);
			goto exit;
		}

		res = test_hash(verbose);
		if (res) {
			printf("test_hash error[%x]\n", res);
			goto exit;
		}

		res = test_hmac(verbose);
		if (res) {
			printf("test_hmac error[%x]\n", res);
			goto exit;
		}
	}

	printf("===================== stress test finish =====================\n");
exit:
	return;
}


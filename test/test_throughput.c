/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rkcrypto_core.h"
#include "rkcrypto_mem.h"
#include "rkcrypto_otp_key.h"
#include "test_utils.h"

#define BLOCK_SIZE	1024 * 1024	/* 1MB */
#define DURATION	1		/* 1s */

static int test_otp_key_item_tp(bool is_virt, uint32_t key_id, uint32_t key_len,
				uint32_t algo, uint32_t mode, uint32_t operation,
				rk_crypto_mem *fd, uint32_t data_len)
{
	uint32_t res = 0;
	rk_cipher_config config;
	uint8_t iv[16];
	uint8_t in_out[RK_CRYPTO_MAX_DATA_LEN];
	struct timespec start, end;
	uint64_t total_nsec, nsec;
	uint32_t rounds;

	nsec = DURATION * 1000000000;

	memset(iv, 0x00, sizeof(iv));
	test_get_rng(iv, sizeof(iv));

	if (is_virt) {
		memset(in_out, 0x00, sizeof(in_out));
		test_get_rng(in_out, data_len);
	}

	memcpy(config.iv, iv, sizeof(iv));

	config.algo      = algo;
	config.mode      = mode;
	config.key_len   = key_len;
	config.reserved  = NULL;
	config.operation = operation;
	total_nsec = 0;
	rounds = 0;

	while (total_nsec < nsec) {
		clock_gettime(CLOCK_REALTIME, &start);

		if (is_virt)
			res = rk_oem_otp_key_cipher_virt(key_id, &config, in_out, in_out, data_len);
		else
			res = rk_oem_otp_key_cipher(key_id, &config, fd->dma_fd, fd->dma_fd, data_len);

		if (res) {
			printf("test rk_oem_otp_key_cipher failed! 0x%08x\n", res);
			return res;
		}

		clock_gettime(CLOCK_REALTIME, &end);
		total_nsec += (end.tv_sec - start.tv_sec) * 1000000000 +
			      (end.tv_nsec - start.tv_nsec);
		rounds ++;
	}

	if (is_virt)
		printf("virt:\totpkey\t[%s-%u]\t%s\t%s\t%dMB/s.\n",
		       test_algo_name(algo), key_len * 8, test_mode_name(mode),
		       test_op_name(operation), (data_len / (1024 * 1024)) * rounds);
	else
		printf("dma_fd:\totpkey\t[%s-%u]\t%s\t%s\t%dMB/s.\n",
		       test_algo_name(algo), key_len * 8, test_mode_name(mode),
		       test_op_name(operation), (data_len / (1024 * 1024)) * rounds);

	return res;
}

static int test_otp_key_virt_tp(void)
{
	uint32_t h, j, k;
	uint32_t algo, key_id, mode, operation, len, key_len;

	const uint32_t algo_tab[] = {
		RK_ALGO_AES,
		RK_ALGO_SM4,
	};
	const uint32_t mode_tab[] = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CTR,
	};
	const uint32_t op_tab[] = {
		RK_OP_CIPHER_ENC,
		RK_OP_CIPHER_DEC,
	};

	for (h = 0; h < ARRAY_SIZE(algo_tab); h++) {
		for (j = 0; j < ARRAY_SIZE(mode_tab); j++) {
			for (k = 0; k < ARRAY_SIZE(op_tab); k++) {
				algo = algo_tab[h];
				mode = mode_tab[j];
				operation = op_tab[k];
				key_id = RK_OEM_OTP_KEY3;
				len = BLOCK_SIZE;

				if (algo == RK_ALGO_AES) {
					key_len = 32;
				} else {
					key_len = 16;
				}

				if (test_otp_key_item_tp(true, key_id, key_len, algo,
							 mode, operation, NULL, len))
					goto error;
			}
		}
	}

	printf("virt:\ttest otp_key throughput SUCCESS.\n");
	return 0;

error:
	printf("virt:\ttest otp_key throughput FAILED!!!\n");
	return -1;
}

static int test_otp_key_fd_tp(void)
{
	int res = 0;
	uint32_t h, j, k;
	uint32_t algo, key_id, mode, operation, len, key_len;
	rk_crypto_mem *in_out = NULL;

	const uint32_t algo_tab[] = {
		RK_ALGO_AES,
		RK_ALGO_SM4,
	};
	const uint32_t mode_tab[] = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CTR,
	};
	const uint32_t op_tab[] = {
		RK_OP_CIPHER_ENC,
		RK_OP_CIPHER_DEC,
	};

	if (rk_crypto_init()) {
		printf("rk_crypto_init error!\n");
		return -1;
	}

	in_out = rk_crypto_mem_alloc(BLOCK_SIZE);
	if (!in_out) {
		printf("rk_crypto_mem_alloc %uByte error!\n", BLOCK_SIZE);
		res = -1;
		goto out;
	}

	for (h = 0; h < ARRAY_SIZE(algo_tab); h++) {
		for (j = 0; j < ARRAY_SIZE(mode_tab); j++) {
			for (k = 0; k < ARRAY_SIZE(op_tab); k++) {
				algo      = algo_tab[h];
				mode      = mode_tab[j];
				operation = op_tab[k];
				key_id = RK_OEM_OTP_KEY3;
				len = BLOCK_SIZE;

				if (algo == RK_ALGO_AES) {
					key_len = 32;
				} else {
					key_len = 16;
				}

				if (test_otp_key_item_tp(false, key_id, key_len, algo,
							 mode, operation, in_out, len)) {
					printf("dma_fd:\ttest otp_key throughput FAILED!!!\n");
					res = -1;
					goto out;
				}
			}
		}
	}

	printf("dma_fd:\ttest otp_key throughput SUCCESS.\n");

out:
	if (!in_out)
		rk_crypto_mem_free(in_out);

	rk_crypto_deinit();
	return res;
}

static int test_otp_key_tp(void)
{
	if (test_otp_key_fd_tp())
		return -1;

	if (test_otp_key_virt_tp())
		return -1;

	return 0;
}

RK_RES test_throughput(void)
{
	if (test_otp_key_tp())
		goto error;


	printf("Test throughput SUCCESS.\n");
	return RK_CRYPTO_SUCCESS;

error:
	printf("Test throughput FAILED!!!\n");
	return RK_CRYPTO_ERR_GENERIC;
}
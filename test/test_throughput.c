/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rkcrypto_core.h"
#include "rkcrypto_mem.h"
#include "rkcrypto_otp_key.h"
#include "test_utils.h"

#define TEST_BLOCK_SIZE		1024 * 1024	/* 1MB */
#define TEST_OTP_BLOCK_SIZE	500 * 1024
#define DURATION		1		/* 1s */
#define DATA_BUTT		0xFFFFFFFF

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

		if (res == RK_CRYPTO_ERR_NOT_SUPPORTED) {
			if (is_virt)
				printf("virt:\totpkey\t[%s-%u]\t%s\t%s\tN/A.\n",
				       test_algo_name(algo), key_len * 8, test_mode_name(mode),
				       test_op_name(operation));
			else
				printf("dma_fd:\totpkey\t[%s-%u]\t%s\t%s\tN/A.\n",
				       test_algo_name(algo), key_len * 8, test_mode_name(mode),
				       test_op_name(operation));

			res = RK_CRYPTO_SUCCESS;
			continue;
		} else if (res) {
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
		       test_op_name(operation), (data_len * rounds / (1024 * 1024)));
	else
		printf("dma_fd:\totpkey\t[%s-%u]\t%s\t%s\t%dMB/s.\n",
		       test_algo_name(algo), key_len * 8, test_mode_name(mode),
		       test_op_name(operation), (data_len * rounds / (1024 * 1024)));

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
				algo      = algo_tab[h];
				mode      = mode_tab[j];
				operation = op_tab[k];
				key_id    = RK_OEM_OTP_KEY3;
				len       = TEST_OTP_BLOCK_SIZE;

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

	in_out = rk_crypto_mem_alloc(TEST_OTP_BLOCK_SIZE);
	if (!in_out) {
		printf("rk_crypto_mem_alloc %uByte error!\n", TEST_OTP_BLOCK_SIZE);
		res = -1;
		goto out;
	}

	for (h = 0; h < ARRAY_SIZE(algo_tab); h++) {
		for (j = 0; j < ARRAY_SIZE(mode_tab); j++) {
			for (k = 0; k < ARRAY_SIZE(op_tab); k++) {
				algo      = algo_tab[h];
				mode      = mode_tab[j];
				operation = op_tab[k];
				key_id    = RK_OEM_OTP_KEY3;
				len       = TEST_OTP_BLOCK_SIZE;

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

static int test_cipher_item_tp(bool is_virt, uint32_t key_len, uint32_t algo,
			       uint32_t mode, uint32_t operation,
			       void *in_out, uint32_t data_len)
{
	uint32_t res = 0;
	rk_handle handle = 0;
	rk_cipher_config config;
	struct timespec start, end;
	uint64_t total_nsec, nsec;
	uint32_t rounds;

	nsec = DURATION * 1000000000;

	test_get_rng(config.iv, sizeof(config.iv));
	test_get_rng(config.key, key_len);

	if (is_virt)
		test_get_rng(in_out, data_len);

	config.algo      = algo;
	config.mode      = mode;
	config.key_len   = key_len;
	config.reserved  = NULL;
	config.operation = operation;
	total_nsec = 0;
	rounds = 0;

	while (total_nsec < nsec) {
		clock_gettime(CLOCK_REALTIME, &start);

		res = rk_cipher_init(&config, &handle);
		if (res) {
			if (res != RK_CRYPTO_ERR_NOT_SUPPORTED) {
				printf("test rk_cipher_init failed! 0x%08x\n", res);
				goto error;
			}

			if (is_virt)
				printf("virt:\t[%s-%u]\t%s\tN/A\n",
				       test_algo_name(algo), key_len * 8, test_mode_name(mode));
			else
				printf("dma_fd:\t[%s-%u]\t%s\tN/A\n",
				       test_algo_name(algo), key_len * 8, test_mode_name(mode));
			return 0;
		}

		if (is_virt)
			res = rk_cipher_crypt_virt(handle, in_out, in_out, data_len);
		else
			res = rk_cipher_crypt(handle,
					      ((rk_crypto_mem *)in_out)->dma_fd,
					      ((rk_crypto_mem *)in_out)->dma_fd,
					      data_len);

		if (res) {
			rk_cipher_final(handle);
			printf("test rk_cipher_crypt failed! 0x%08x\n", res);
			goto error;
		}

		rk_cipher_final(handle);

		clock_gettime(CLOCK_REALTIME, &end);
		total_nsec += (end.tv_sec - start.tv_sec) * 1000000000 +
			      (end.tv_nsec - start.tv_nsec);
		rounds ++;
	}

	if (is_virt)
		printf("virt:\t[%s-%u]\t%s\t%s\t%dMB/s.\n",
		       test_algo_name(algo), key_len * 8, test_mode_name(mode),
		       test_op_name(operation), (data_len * rounds / (1024 * 1024)));
	else
		printf("dma_fd:\t[%s-%u]\t%s\t%s\t%dMB/s.\n",
		       test_algo_name(algo), key_len * 8, test_mode_name(mode),
		       test_op_name(operation), (data_len * rounds / (1024 * 1024)));

	return res;
error:
	if (is_virt)
		printf("virt:\t[%s-%u]\t%s\tFailed.\n",
		       test_algo_name(algo), key_len * 8, test_mode_name(mode));
	else
		printf("dma_fd:\t[%s-%u]\t%s\tFailed.\n",
		       test_algo_name(algo), key_len * 8, test_mode_name(mode));
	return res;
}

static int test_cipher_tp(void)
{
	int res = 0;
	uint32_t h, j, k;
	uint32_t algo, mode, operation, len, key_len;
	rk_crypto_mem *in_out_fd = NULL;
	uint8_t *in_out_virt = NULL;
	size_t page_size = getpagesize();

	struct test_cipher_item_tp {
		uint32_t algo;
		uint32_t modes[RK_CIPHER_MODE_MAX];
		uint32_t key_len;
		uint32_t op[2];
	};

	static struct test_cipher_item_tp test_item_tbl[] = {
		{
			.algo  = RK_ALGO_DES,
			.modes = {
				RK_CIPHER_MODE_ECB,
				RK_CIPHER_MODE_CBC,
				DATA_BUTT,
			},
			.key_len = 8,
			.op = {RK_OP_CIPHER_ENC, RK_OP_CIPHER_DEC},
		},

		{
			.algo  = RK_ALGO_TDES,
			.modes = {
				RK_CIPHER_MODE_ECB,
				RK_CIPHER_MODE_CBC,
				DATA_BUTT,
			},
			.key_len = 24,
			.op = {RK_OP_CIPHER_ENC, RK_OP_CIPHER_DEC},
		},

		{
			.algo  = RK_ALGO_AES,
			.modes = {
				RK_CIPHER_MODE_ECB,
				RK_CIPHER_MODE_CBC,
				RK_CIPHER_MODE_CTS,
				RK_CIPHER_MODE_CTR,
				DATA_BUTT,
			},
			.key_len = 32,
			.op = {RK_OP_CIPHER_ENC, RK_OP_CIPHER_DEC},
		},

		{
			.algo  = RK_ALGO_SM4,
			.modes = {
				RK_CIPHER_MODE_ECB,
				RK_CIPHER_MODE_CBC,
				RK_CIPHER_MODE_CTS,
				RK_CIPHER_MODE_CTR,
				DATA_BUTT,
			},
			.key_len = 16,
			.op = {RK_OP_CIPHER_ENC, RK_OP_CIPHER_DEC},
		},

	};

	if (rk_crypto_init()) {
		printf("rk_crypto_init error!\n");
		return -1;
	}

	in_out_fd = rk_crypto_mem_alloc(TEST_BLOCK_SIZE);
	if (!in_out_fd) {
		printf("rk_crypto_mem_alloc %uByte error!\n", TEST_BLOCK_SIZE);
		res = -1;
		goto out;
	}

	if (posix_memalign((void *)&in_out_virt, page_size, TEST_BLOCK_SIZE) || !in_out_virt) {
		printf("malloc %uByte error!\n", TEST_BLOCK_SIZE);
		res = -1;
		goto out;
	}

	/* Test dma_fd cipher */
	for (h = 0; h < ARRAY_SIZE(test_item_tbl); h++) {
		for (j = 0; j < ARRAY_SIZE(test_item_tbl[h].modes); j++) {
			if (test_item_tbl[h].modes[j] == DATA_BUTT)
				break;

			for (k = 0; k < ARRAY_SIZE(test_item_tbl[h].op); k++) {
				algo      = test_item_tbl[h].algo;
				key_len   = test_item_tbl[h].key_len;
				mode      = test_item_tbl[h].modes[j];
				operation = test_item_tbl[h].op[k];
				len       = TEST_BLOCK_SIZE;

				if (test_cipher_item_tp(false, key_len, algo, mode,
							operation, in_out_fd, len)) {
					printf("dma_fd:\ttest cipher throughput FAILED!!!\n");
					res = -1;
					goto out;
				}
			}
		}
	}

	printf("dma_fd:\ttest cipher throughput SUCCESS.\n");

	/* Test virt cipher */
	for (h = 0; h < ARRAY_SIZE(test_item_tbl); h++) {
		for (j = 0; j < ARRAY_SIZE(test_item_tbl[h].modes); j++) {
			if (test_item_tbl[h].modes[j] == DATA_BUTT)
				break;

			for (k = 0; k < ARRAY_SIZE(test_item_tbl[h].op); k++) {
				algo      = test_item_tbl[h].algo;
				key_len   = test_item_tbl[h].key_len;
				mode      = test_item_tbl[h].modes[j];
				operation = test_item_tbl[h].op[k];
				len       = TEST_BLOCK_SIZE;

				if (test_cipher_item_tp(true, key_len, algo, mode,
							operation, in_out_virt, len)) {
					printf("virt:\ttest cipher throughput FAILED!!!\n");
					res = -1;
					goto out;
				}
			}
		}
	}

	printf("virt:\ttest cipher throughput SUCCESS.\n");

out:
	if (in_out_fd)
		rk_crypto_mem_free(in_out_fd);

	if (in_out_virt)
		free(in_out_virt);

	rk_crypto_deinit();
	return res;
}

static int test_hash_item_tp(bool is_virt, bool is_hmac, uint32_t algo,
			     uint32_t blocksize, void *input, uint32_t data_len)
{
	int res = 0;
	uint32_t data_block = data_len;
	uint32_t tmp_len;
	uint8_t hash[64];
	uint8_t key[MAX_HASH_BLOCK_SIZE];
	uint8_t *tmp_data;
	rk_handle hash_hdl = 0;
	rk_hash_config hash_cfg;
	uint32_t key_len;
	struct timespec start, end;
	uint64_t total_nsec, nsec;
	uint32_t rounds;

	nsec = DURATION * 1000000000;

	if (is_virt)
		test_get_rng(input, data_len);

	memset(hash, 0x00, sizeof(hash));

	memset(&hash_cfg, 0x00, sizeof(hash_cfg));
	hash_cfg.algo = algo;

	if (is_hmac) {
		key_len = blocksize;
		test_get_rng(key, key_len);
		hash_cfg.key     = key;
		hash_cfg.key_len = key_len;
	}

	total_nsec = 0;
	rounds = 0;

	res = rk_hash_init(&hash_cfg, &hash_hdl);
	if (res) {
		if (is_virt)
			printf("virt:\t[%12s]\tN/A\n", test_algo_name(algo));
		else
			printf("dma_fd:\t[%12s]\tN/A\n", test_algo_name(algo));
		return 0;
	}

	while (total_nsec < nsec) {
		clock_gettime(CLOCK_REALTIME, &start);

		data_block = data_len;

		if (is_virt) {
			tmp_len    = data_len;
			tmp_data   = input;

			while (tmp_len) {
				data_block = tmp_len > data_block ? data_block : tmp_len;

				res = rk_hash_update_virt(hash_hdl, tmp_data, data_block);
				if (res) {
					rk_hash_final(hash_hdl, NULL);
					printf("rk_hash_update_virt[%lu/%u] error = %d\n",
					       (unsigned long)(tmp_data - (uint8_t *)input), tmp_len, res);
					goto error;
				}

				tmp_len -= data_block;
				tmp_data += data_block;
			}
		} else {
			res = rk_hash_update(hash_hdl, ((rk_crypto_mem *)input)->dma_fd, data_block);
			if (res) {
				rk_hash_final(hash_hdl, NULL);
				printf("rk_hash_update error = %d\n", res);
				goto error;
			}
		}

		clock_gettime(CLOCK_REALTIME, &end);
		total_nsec += (end.tv_sec - start.tv_sec) * 1000000000 +
			      (end.tv_nsec - start.tv_nsec);
		rounds ++;
	}

	res = rk_hash_final(hash_hdl, hash);
	if (res) {
		printf("rk_hash_final error = %d\n", res);
		return -1;
	}

	if (is_virt)
		printf("virt:\t[%12s]\t%dMB/s.\n",
		       test_algo_name(algo), (data_len * rounds / (1024 * 1024)));
	else
		printf("dma_fd:\t[%12s]\t%dMB/s.\n",
		       test_algo_name(algo), (data_len * rounds / (1024 * 1024)));

	return res;
error:
	return res;
}

static int test_hash_tp(void)
{
	int res;
	uint32_t buffer_len = TEST_BLOCK_SIZE;;
	rk_crypto_mem *input_fd = NULL;
	uint8_t *input_virt = NULL;
	uint32_t i;
	size_t page_size = getpagesize();

	struct test_hash_item {
		uint32_t algo;
		uint32_t blocksize;
	};

	static struct test_hash_item test_hash_tbl[] = {
		{RK_ALGO_MD5,        MD5_BLOCK_SIZE},
		{RK_ALGO_SHA1,       SHA1_BLOCK_SIZE},
		{RK_ALGO_SHA256,     SHA256_BLOCK_SIZE},
		{RK_ALGO_SHA224,     SHA224_BLOCK_SIZE},
		{RK_ALGO_SHA512,     SHA512_BLOCK_SIZE},
		{RK_ALGO_SHA384,     SHA384_BLOCK_SIZE},
		{RK_ALGO_SHA512_224, SHA512_224_BLOCK_SIZE},
		{RK_ALGO_SHA512_256, SHA512_256_BLOCK_SIZE},
		{RK_ALGO_SM3,        SM3_BLOCK_SIZE},
	};

	static struct test_hash_item test_hmac_tbl[] = {
		{RK_ALGO_HMAC_MD5,    MD5_BLOCK_SIZE},
		{RK_ALGO_HMAC_SHA1,   SHA1_BLOCK_SIZE},
		{RK_ALGO_HMAC_SHA256, SHA256_BLOCK_SIZE},
		{RK_ALGO_HMAC_SHA512, SHA512_BLOCK_SIZE},
		{RK_ALGO_HMAC_SM3,    SM3_BLOCK_SIZE},
	};

	if (rk_crypto_init()) {
		printf("rk_crypto_init error!\n");
		return -1;
	}

	input_fd = rk_crypto_mem_alloc(buffer_len);
	if (!input_fd) {
		printf("rk_crypto_mem_alloc %uByte error!\n", buffer_len);
		res = -1;
		goto out;
	}

	if (posix_memalign((void *)&input_virt, page_size, TEST_BLOCK_SIZE) || !input_virt) {
		printf("malloc %uByte error!\n", TEST_BLOCK_SIZE);
		res = -1;
		goto out;
	}

	/* Test virt hash */
	for (i = 0; i < ARRAY_SIZE(test_hash_tbl); i++) {
		res = test_hash_item_tp(true, false, test_hash_tbl[i].algo,
					test_hash_tbl[i].blocksize, input_virt, buffer_len);
		if (res) {
			printf("virt:\ttest hash throughput FAILED!!!\n");
			goto out;
		}
	}

	printf("virt:\ttest hash throughput SUCCESS.\n");

	/* Test dma_fd hash */
	for (i = 0; i < ARRAY_SIZE(test_hash_tbl); i++) {
		res = test_hash_item_tp(false, false, test_hash_tbl[i].algo,
					test_hash_tbl[i].blocksize, input_fd, buffer_len);
		if (res) {
			printf("dma_fd:\ttest hash throughput FAILED!!!\n");
			goto out;
		}
	}

	printf("dma_fd:\ttest hash throughput SUCCESS.\n");

	/* Test virt hmac */
	for (i = 0; i < ARRAY_SIZE(test_hmac_tbl); i++) {
		res = test_hash_item_tp(true, true, test_hmac_tbl[i].algo,
					test_hmac_tbl[i].blocksize, input_virt, buffer_len);
		if (res) {
			printf("virt:\ttest hmac throughput FAILED!!!\n");
			goto out;
		}
	}

	printf("virt:\ttest hmac throughput SUCCESS.\n");

	/* Test dma_fd hmac */
	for (i = 0; i < ARRAY_SIZE(test_hmac_tbl); i++) {
		res = test_hash_item_tp(false, true, test_hmac_tbl[i].algo,
					test_hmac_tbl[i].blocksize, input_fd, buffer_len);
		if (res) {
			printf("dma_fd:\ttest hmac throughput FAILED!!!\n");
			goto out;
		}
	}

	printf("dma_fd:\ttest hmac throughput SUCCESS.\n");

out:
	if (input_fd)
		rk_crypto_mem_free(input_fd);

	if (input_virt)
		free(input_virt);

	rk_crypto_deinit();

	return 0;
}

RK_RES test_throughput(void)
{
	if (test_otp_key_tp())
		goto error;

	if (test_cipher_tp())
		goto error;

	if (test_hash_tp())
		goto error;

	printf("Test throughput SUCCESS.\n");
	return RK_CRYPTO_SUCCESS;

error:
	printf("Test throughput FAILED!!!\n");
	return RK_CRYPTO_ERR_GENERIC;
}

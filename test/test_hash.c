/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "rkcrypto_common.h"
#include "rkcrypto_trace.h"
#include "cmode_adapter.h"
#include "librkcrypto.h"
#include "test_hash.h"
#include "test_utils.h"

#define HASH_MAX_LEN	64
#define TEST_DATA_MAX	256

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

static RK_RES test_hash_item_virt(const struct test_hash_item *item,
				  uint8_t *buffer, uint32_t buffer_len, bool is_hmac)
{
	RK_RES res = RK_ALG_ERR_GENERIC;
	uint32_t data_block = 128;
	uint32_t out_len, tmp_len;
	uint8_t hash_soft[HASH_MAX_LEN], hash_hard[HASH_MAX_LEN];
	uint8_t key[MAX_HASH_BLOCK_SIZE];
	uint8_t *tmp_data;
	const char *test_name = "hash";
	rk_handle hash_hdl = 0;
	rk_hash_config hash_cfg;
	uint32_t algo, key_len;

	test_get_rng(buffer, buffer_len);

	memset(hash_soft, 0x00, sizeof(hash_soft));
	memset(hash_hard, 0x00, sizeof(hash_hard));

	algo    = item->algo;
	key_len = item->blocksize;

	memset(&hash_cfg, 0x00, sizeof(hash_cfg));
	hash_cfg.algo = algo;

	if (is_hmac) {
		test_get_rng(key, sizeof(key_len));
		hash_cfg.key     = key;
		hash_cfg.key_len = key_len;
		test_name = "hmac";
	}

	res = rk_hash_init(&hash_cfg, &hash_hdl);
	if (res) {
		printf("virt  : [%-10s]\t: N/A\n", test_algo_name(algo));
		return RK_ALG_SUCCESS;
	}

	tmp_len  = buffer_len;
	tmp_data = buffer;

	while (tmp_len) {
		if (tmp_len > data_block) {
			res = rk_hash_update_virt(hash_hdl, tmp_data, data_block, false);
			if (res) {
				E_TRACE("rk_hash_update_virt[%lu/%u] error = %d\n",
					tmp_data - buffer, tmp_len, res);
				goto exit;
			}
		} else {
			data_block = tmp_len;
			res = rk_hash_update_virt(hash_hdl, tmp_data, tmp_len, true);
			if (res) {
				E_TRACE("rk_hash_update_virt[%lu/%u] error = %d\n",
					tmp_data - buffer, tmp_len, res);
				goto exit;
			}
		}
		tmp_len -= data_block;
		tmp_data += data_block;
	}

	rk_hash_final(hash_hdl, hash_hard, &out_len);

	if (is_hmac)
		res = soft_hmac(algo, key, key_len, buffer, buffer_len, hash_soft, &out_len);
	else
		res = soft_hash(algo, buffer, buffer_len, hash_soft, &out_len);
	if (res) {
		E_TRACE("soft_%s error[%x]\n", test_name, res);
		goto exit;
	}

	/* Verify the result */
	if (memcmp(hash_hard, hash_soft, out_len) != 0) {
		E_TRACE("test_%s_item_virt compare failed.\n", test_name);
		test_dump_hex("hash_hard", hash_hard, out_len);
		test_dump_hex("hash_soft", hash_soft, out_len);
		res = RK_ALG_ERR_GENERIC;
		goto exit;
	}


	hash_hdl = 0;
	printf("virt  : [%-10s]\t: PASS\n", test_algo_name(algo));

	res = RK_ALG_SUCCESS;
exit:
	if (res)
		printf("virt  : [%-10s]\t: FAIL\n", test_algo_name(algo));

	return res;
}

static RK_RES test_hash_item_fd(const struct test_hash_item *item,
				rk_crypto_mem *buffer, bool is_hmac)
{
	RK_RES res = RK_ALG_ERR_GENERIC;
	uint32_t out_len;
	uint8_t hash_soft[HASH_MAX_LEN], hash_hard[HASH_MAX_LEN];
	uint8_t key[MAX_HASH_BLOCK_SIZE];
	const char *test_name = "hash";
	rk_handle hash_hdl = 0;
	rk_hash_config hash_cfg;
	uint32_t algo, key_len;

	test_get_rng(buffer->vaddr, buffer->size);

	memset(hash_soft, 0x00, sizeof(hash_soft));
	memset(hash_hard, 0x00, sizeof(hash_hard));

	algo    = item->algo;
	key_len = item->blocksize;

	memset(&hash_cfg, 0x00, sizeof(hash_cfg));
	hash_cfg.algo = algo;

	if (is_hmac) {
		test_get_rng(key, sizeof(key_len));
		hash_cfg.key     = key;
		hash_cfg.key_len = key_len;
		test_name = "hmac";
	}

	res = rk_hash_init(&hash_cfg, &hash_hdl);
	if (res) {
		printf("dma_fd: [%-10s]\t: N/A\n", test_algo_name(algo));
		return RK_ALG_SUCCESS;
	}

	res = rk_hash_update(hash_hdl, buffer->dma_fd, buffer->size, true);
	if (res) {
		E_TRACE("rk_hash_update error = %d\n", res);
		goto exit;
	}

	rk_hash_final(hash_hdl, hash_hard, &out_len);

	if (is_hmac)
		res = soft_hmac(algo, key, key_len, buffer->vaddr, buffer->size,
				hash_soft, &out_len);
	else
		res = soft_hash(algo, buffer->vaddr, buffer->size, hash_soft, &out_len);
	if (res) {
		E_TRACE("soft_%s error[%x]\n", test_name, res);
		goto exit;
	}

	/* Verify the result */
	if (memcmp(hash_hard, hash_soft, out_len) != 0) {
		E_TRACE("test_%s_item_fd compare failed.\n", test_name);
		test_dump_hex("buffer", buffer->vaddr, buffer->size);
		test_dump_hex("hash_hard", hash_hard, out_len);
		test_dump_hex("hash_soft", hash_soft, out_len);
		res = RK_ALG_ERR_GENERIC;
		goto exit;
	}


	hash_hdl = 0;
	printf("dma_fd: [%-10s]\t: PASS\n", test_algo_name(algo));

	res = RK_ALG_SUCCESS;
exit:
	if (res)
		printf("dma_fd: [%-10s]\t: FAIL\n", test_algo_name(algo));

	return res;
}

RK_RES test_hash(void)
{
	RK_RES res = RK_ALG_ERR_GENERIC;
	uint8_t *buffer = NULL;
	uint32_t buffer_len = TEST_DATA_MAX;
	rk_crypto_mem *mem_buf = NULL;
	uint32_t i;

	rk_crypto_init();

	buffer = malloc(buffer_len);
	if (!buffer) {
		E_TRACE("test hash malloc buffer %uByte error!\n", buffer_len);
		goto exit;
	}

	mem_buf = rk_crypto_mem_alloc(buffer_len);
	if (!mem_buf) {
		E_TRACE("test hash rk_crypto_mem_alloc %uByte error!\n", buffer_len);
		goto exit;
	}

	for (i = 0; i < ARRAY_SIZE(test_hash_tbl); i++) {
		res = test_hash_item_virt(&test_hash_tbl[i], buffer, buffer_len, false);
		if (res)
			goto exit;

		res = test_hash_item_fd(&test_hash_tbl[i], mem_buf, false);
		if (res)
			goto exit;
	}
exit:
	rk_crypto_mem_free(mem_buf);
	rk_crypto_deinit();
	if (buffer)
		free(buffer);
	return 0;
}

RK_RES test_hmac(void)
{
	RK_RES res = RK_ALG_ERR_GENERIC;
	uint8_t *buffer = NULL;
	uint32_t buffer_len = TEST_DATA_MAX;
	rk_crypto_mem *mem_buf = NULL;
	uint32_t i;

	rk_crypto_init();

	buffer = malloc(buffer_len);
	if (!buffer) {
		E_TRACE("test hmac malloc buffer %uByte error!\n", buffer_len);
		goto exit;
	}

	mem_buf = rk_crypto_mem_alloc(buffer_len);
	if (!mem_buf) {
		E_TRACE("test hmac rk_crypto_mem_alloc %uByte error!\n", buffer_len);
		goto exit;
	}

	for (i = 0; i < ARRAY_SIZE(test_hmac_tbl); i++) {
		res = test_hash_item_virt(&test_hmac_tbl[i], buffer, buffer_len, true);
		if (res)
			goto exit;

		res = test_hash_item_fd(&test_hmac_tbl[i], mem_buf, true);
		if (res)
			goto exit;
	}
exit:
	rk_crypto_mem_free(mem_buf);
	rk_crypto_deinit();
	if (buffer)
		free(buffer);
	return 0;
}


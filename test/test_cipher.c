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
#include "test_cipher.h"
#include "test_utils.h"

#define DATA_BUTT	0xFFFFFFFF
#define TEST_DATA_MAX	256

struct test_cipher_item {
	uint32_t algo;
	uint32_t modes[RK_CIPHER_MODE_MAX];
	uint32_t key_lens[4];
	uint32_t iv_len;
};

static struct test_cipher_item test_item_tbl[] = {
{
	.algo  = RK_ALGO_DES,
	.modes = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CFB,
		RK_CIPHER_MODE_OFB,
		DATA_BUTT,
	},
	.key_lens = {8},
	.iv_len   = DES_BLOCK_SIZE,
},

{
	.algo  = RK_ALGO_TDES,
	.modes = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CFB,
		RK_CIPHER_MODE_OFB,
		DATA_BUTT,
	},
	.key_lens = {24},
	.iv_len   = DES_BLOCK_SIZE,
},

{
	.algo  = RK_ALGO_AES,
	.modes = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CTS,
		RK_CIPHER_MODE_CTR,
		RK_CIPHER_MODE_CFB,
		RK_CIPHER_MODE_OFB,
		DATA_BUTT,
	},
	.key_lens = {16, 24, 32},
	.iv_len   = AES_BLOCK_SIZE,
},

{
	.algo  = RK_ALGO_SM4,
	.modes = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CTS,
		RK_CIPHER_MODE_CTR,
		RK_CIPHER_MODE_CFB,
		RK_CIPHER_MODE_OFB,
		DATA_BUTT,
	},
	.key_lens = {16},
	.iv_len   = SM4_BLOCK_SIZE,
},

};

static RK_RES test_cipher_item_virt(const struct test_cipher_item *item)
{
	RK_RES res = RK_ALG_ERR_GENERIC;
	uint32_t i, j, k;
	uint32_t ops[] = {RK_OP_CIPHER_ENC, RK_OP_CIPHER_DEC};
	uint32_t data_len = TEST_DATA_MAX, out_len;
	rk_handle cipher_hdl = 0;
	rk_cipher_config cipher_cfg;
	uint8_t *plain = NULL, *cipher_soft = NULL, *cipher_hard = NULL;
	uint32_t algo = 0, mode = 0, key_len, iv_len, operation;

	plain = malloc(data_len);
	if (!plain) {
		E_TRACE("plain malloc %uByte error!\n", data_len);
		goto exit;
	}

	cipher_soft = malloc(data_len);
	if (!cipher_soft) {
		E_TRACE("cipher_soft malloc %uByte error!\n", data_len);
		goto exit;
	}

	cipher_hard = malloc(data_len);
	if (!cipher_hard) {
		E_TRACE("cipher_hard malloc %uByte error!\n", data_len);
		goto exit;
	}

	test_get_rng(plain, data_len);

	memset(cipher_soft, 0x00, data_len);
	memset(cipher_hard, 0x00, data_len);

	for (i = 0; i < ARRAY_SIZE(item->modes); i++) {
		algo = item->algo;
		mode = item->modes[i];

		if (mode == DATA_BUTT)
			break;

		for (j = 0; j < ARRAY_SIZE(item->key_lens); j++) {
			key_len = item->key_lens[j];
			iv_len  = item->iv_len;

			if (key_len == 0)
				break;

			for (k = 0; k < ARRAY_SIZE(ops); k++) {
				operation = ops[k];

				memset(&cipher_cfg, 0x00, sizeof(cipher_cfg));
				cipher_cfg.algo      = algo;
				cipher_cfg.mode      = mode;
				cipher_cfg.operation = operation;
				cipher_cfg.key_len   = key_len;

				test_get_rng(cipher_cfg.key, key_len);
				test_get_rng(cipher_cfg.iv, iv_len);

				res = rk_cipher_init(&cipher_cfg, &cipher_hdl);
				if (res) {
					printf("virt  : [%s-%u] %-8s%-8s N/A\n",
					       test_algo_name(algo), key_len * 8,
					       test_mode_name(mode), test_op_name(operation));
					continue;
				}

				res = rk_cipher_crypt_virt(cipher_hdl, plain, data_len,
							   cipher_hard, &out_len);
				if (res) {
					E_TRACE("rk_cipher_crypt_virt error[%x]\n", res);
					goto exit;
				}

				res = soft_cipher(algo, mode, operation,
						  cipher_cfg.key, cipher_cfg.key_len, cipher_cfg.iv,
						  plain, data_len, cipher_soft);
				if (res) {
					E_TRACE("soft_cipher error[%x]\n", res);
					goto exit;
				}

				/* Verify the result */
				if (memcmp(cipher_hard, cipher_soft, data_len) != 0) {
					E_TRACE("rkcrypto_test_cipher_virt compare failed.\n");
					test_dump_hex("cipher_hard", cipher_hard, data_len);
					test_dump_hex("cipher_soft", cipher_soft, data_len);
					res = RK_ALG_ERR_GENERIC;
					goto exit;
				}

				rk_cipher_final(cipher_hdl);
				cipher_hdl = 0;
				printf("virt  : [%s-%u] %-8s%-8s PASS\n",
				       test_algo_name(algo), key_len * 8,
				       test_mode_name(mode), test_op_name(operation));
			}
		}
	}

	res = RK_ALG_SUCCESS;
exit:
	if (plain)
		free(plain);

	if (cipher_soft)
		free(cipher_soft);

	if (cipher_hard)
		free(cipher_hard);

	if (res)
		printf("virt  : [%s-%u] %-8s%-8s FAIL\n",
		       test_algo_name(algo), key_len * 8,
		       test_mode_name(mode), test_op_name(operation));

	return res;
}

static RK_RES test_cipher_item_fd(const struct test_cipher_item *item)
{
	RK_RES res = RK_ALG_ERR_GENERIC;
	uint32_t i, j, k;
	uint32_t ops[] = {RK_OP_CIPHER_ENC, RK_OP_CIPHER_DEC};
	uint32_t data_len = TEST_DATA_MAX, out_len;
	rk_handle cipher_hdl = 0;
	rk_cipher_config cipher_cfg;
	rk_crypto_mem *plain = NULL, *cipher_soft = NULL, *cipher_hard = NULL;
	uint32_t algo = 0, mode = 0, key_len, iv_len, operation;

	plain = rk_crypto_mem_alloc(data_len);
	if (!plain) {
		E_TRACE("plain malloc %uByte error!\n", data_len);
		goto exit;
	}

	cipher_soft = rk_crypto_mem_alloc(data_len);
	if (!cipher_soft) {
		E_TRACE("cipher_soft malloc %uByte error!\n", data_len);
		goto exit;
	}

	cipher_hard = rk_crypto_mem_alloc(data_len);
	if (!cipher_hard) {
		E_TRACE("cipher_hard malloc %uByte error!\n", data_len);
		goto exit;
	}

	test_get_rng(plain->vaddr, data_len);

	for (i = 0; i < ARRAY_SIZE(item->modes); i++) {
		algo = item->algo;
		mode = item->modes[i];

		if (mode == DATA_BUTT)
			break;

		for (j = 0; j < ARRAY_SIZE(item->key_lens); j++) {
			key_len = item->key_lens[j];
			iv_len  = item->iv_len;

			if (key_len == 0)
				break;

			for (k = 0; k < ARRAY_SIZE(ops); k++) {
				operation = ops[k];

				memset(&cipher_cfg, 0x00, sizeof(cipher_cfg));
				cipher_cfg.algo      = algo;
				cipher_cfg.mode      = mode;
				cipher_cfg.operation = operation;
				cipher_cfg.key_len   = key_len;

				test_get_rng(cipher_cfg.key, key_len);
				test_get_rng(cipher_cfg.iv, iv_len);

				res = rk_cipher_init(&cipher_cfg, &cipher_hdl);
				if (res) {
					printf("virt  : [%s-%u] %-8s%-8s N/A\n",
					       test_algo_name(algo), key_len * 8,
					       test_mode_name(mode), test_op_name(operation));
					continue;
				}

				res = rk_cipher_crypt(cipher_hdl, plain->dma_fd, data_len,
						      cipher_hard->dma_fd, &out_len);
				if (res) {
					E_TRACE("rk_cipher_crypt_virt error[%x]\n", res);
					goto exit;
				}

				res = soft_cipher(algo, mode, operation,
						  cipher_cfg.key, cipher_cfg.key_len, cipher_cfg.iv,
						  plain->vaddr, data_len, cipher_soft->vaddr);
				if (res) {
					E_TRACE("soft_cipher error[%x]\n", res);
					goto exit;
				}

				/* Verify the result */
				if (memcmp(cipher_hard->vaddr, cipher_soft->vaddr, data_len) != 0) {
					E_TRACE("rkcrypto_test_cipher_virt compare failed.\n");
					test_dump_hex("cipher_hard", cipher_hard->vaddr, data_len);
					test_dump_hex("cipher_soft", cipher_soft->vaddr, data_len);
					res = RK_ALG_ERR_GENERIC;
					goto exit;
				}

				rk_cipher_final(cipher_hdl);
				cipher_hdl = 0;
				printf("dma_fd: [%s-%u] %-8s%-8s PASS\n",
				       test_algo_name(algo), key_len * 8,
				       test_mode_name(mode), test_op_name(operation));
			}
		}
	}

	res = RK_ALG_SUCCESS;
exit:
	rk_crypto_mem_free(plain);
	rk_crypto_mem_free(cipher_soft);
	rk_crypto_mem_free(cipher_hard);

	if (res)
		printf("dma_fd: [%s-%u] %-8s%-8s FAIL\n",
		       test_algo_name(algo), key_len * 8,
		       test_mode_name(mode), test_op_name(operation));

	return res;
}

RK_RES test_cipher(void)
{
	RK_RES res = RK_ALG_ERR_GENERIC;
	uint32_t i;

	rk_crypto_init();

	for (i = 0; i < ARRAY_SIZE(test_item_tbl); i++) {
		res = test_cipher_item_virt(&test_item_tbl[i]);
		if (res)
			goto exit;

		res = test_cipher_item_fd(&test_item_tbl[i]);
		if (res)
			goto exit;
		printf("\n");
	}
exit:
	rk_crypto_deinit();
	return 0;
}


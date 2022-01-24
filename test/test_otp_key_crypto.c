/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <stdlib.h>
#include <time.h>
#include "c_model.h"
#include "cmode_adapter.h"
#include "rkcrypto_common.h"
#include "rkcrypto_core.h"
#include "rkcrypto_mem.h"
#include "rkcrypto_otp_key.h"
#include "test_otp_key_crypto.h"
#include "test_utils.h"

uint8_t otp_key0[32] = {
	0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

uint8_t otp_key1[32] = {
	0xdf, 0x20, 0x5a, 0xb3, 0x88, 0x50, 0x9e, 0x4f,
	0x01, 0x21, 0xe7, 0xc9, 0x24, 0x00, 0x1b, 0x84,
	0x2a, 0xfb, 0x83, 0xac, 0xe4, 0x61, 0x4a, 0x94,
	0x1f, 0xf4, 0x84, 0xc3, 0x1f, 0xe5, 0x52, 0xc7,
};

uint8_t otp_key2[32] = {
	0xd5, 0x20, 0xaa, 0xb3, 0x88, 0x5f, 0x9e, 0x41,
	0x05, 0x21, 0x07, 0xc9, 0x44, 0x00, 0x1b, 0x80,
	0x23, 0xfb, 0x13, 0xac, 0xe4, 0x66, 0x4a, 0x93,
	0x13, 0xf4, 0x04, 0xc3, 0x3f, 0xe7, 0x52, 0xc0,
};

uint8_t otp_key3[32] = {
	0x10, 0x44, 0x80, 0xb3, 0x88, 0x5f, 0x02, 0x03,
	0x05, 0x21, 0x07, 0xc9, 0x44, 0x00, 0x1b, 0x80,
	0x5f, 0x9e, 0x41, 0xac, 0xe4, 0x64, 0x43, 0xa3,
	0x13, 0x06, 0x07, 0x08, 0x3f, 0xe7, 0x05, 0x06,
};

static const char *algo_name_tab[] = {
	[RK_ALGO_AES]  = "AES",
	[RK_ALGO_DES]  = "DES",
	[RK_ALGO_TDES] = "TDES",
	[RK_ALGO_SM4]  = "SM4"
};

static const char *mode_name_tab[] = {
	[RK_CIPHER_MODE_ECB]     = "ECB",
	[RK_CIPHER_MODE_CBC]     = "CBC",
	[RK_CIPHER_MODE_CTS]     = "CTS",
	[RK_CIPHER_MODE_CTR]     = "CTR",
	[RK_CIPHER_MODE_CFB]     = "CFB",
	[RK_CIPHER_MODE_OFB]     = "OFB",
	[RK_CIPHER_MODE_XTS]     = "XTS",
	[RK_CIPHER_MODE_CCM]     = "CCM",
	[RK_CIPHER_MODE_GCM]     = "GCM",
	[RK_CIPHER_MODE_CMAC]    = "CMAC",
	[RK_CIPHER_MODE_CBC_MAC] = "CBC_MAC"
};

void test_set_otp_tag(void)
{
	uint32_t res;

	res = rk_set_oem_hr_otp_read_lock(RK_OEM_OTP_KEY0);
	printf("trusty_set_oem_hr_otp_read_lock 0. res:%d\n", res);

	res = rk_set_oem_hr_otp_read_lock(RK_OEM_OTP_KEY1);
	printf("trusty_set_oem_hr_otp_read_lock 1. res:%d\n", res);

	res = rk_set_oem_hr_otp_read_lock(RK_OEM_OTP_KEY2);
	printf("trusty_set_oem_hr_otp_read_lock 2. res:%d\n", res);

	res = rk_set_oem_hr_otp_read_lock(RK_OEM_OTP_KEY3);
	printf("trusty_set_oem_hr_otp_read_lock 3. res:%d\n", res);

	return;
}

void test_write_otp_key(void)
{
	uint32_t res;

	res = rk_write_oem_otp_key(RK_OEM_OTP_KEY0,
				   otp_key0, sizeof(otp_key0));
	printf("write otp key 0. res:%d\n", res);

	res = rk_write_oem_otp_key(RK_OEM_OTP_KEY1,
				   otp_key1, sizeof(otp_key1));
	printf("write otp key 1. res:%d\n", res);

	res = rk_write_oem_otp_key(RK_OEM_OTP_KEY2,
				   otp_key2, sizeof(otp_key2));
	printf("write otp key 2. res:%d\n", res);

	res = rk_write_oem_otp_key(RK_OEM_OTP_KEY3,
				   otp_key3, sizeof(otp_key3));
	printf("write otp key 3. res:%d\n", res);

	return;
}

static int test_func_item_virt(uint32_t key_id, uint32_t key_len,
			       uint32_t algo, uint32_t mode,
			       uint32_t data_len)
{
	uint32_t res;
	rk_cipher_config config;
	uint8_t *key = NULL;
	uint8_t iv[16];
	uint8_t in[RK_CRYPTO_MAX_DATA_LEN];
	uint8_t out[RK_CRYPTO_MAX_DATA_LEN];
	uint8_t out_soft[RK_CRYPTO_MAX_DATA_LEN];

	printf("### virt: key_id:%d, algo:%s, mode:%s, key_len:%d, data_len:%d\n",
	       key_id, algo_name_tab[algo], mode_name_tab[mode], key_len, data_len);

	memset(iv, 0x00, sizeof(iv));
	memset(in, 0x00, sizeof(in));
	memset(out, 0x00, sizeof(out));
	memset(out_soft, 0x00, sizeof(out_soft));

	test_get_rng(iv, sizeof(iv));
	test_get_rng(in, data_len);

	switch (key_id) {
	case RK_OEM_OTP_KEY0:
		key = otp_key0;
		break;
	case RK_OEM_OTP_KEY1:
		key = otp_key1;
		break;
	case RK_OEM_OTP_KEY2:
		key = otp_key2;
		break;
	case RK_OEM_OTP_KEY3:
		key = otp_key3;
		break;
	default:
		return -1;
	}

	config.algo      = algo;
	config.mode      = mode;
	config.operation = RK_OP_CIPHER_ENC;
	config.key_len   = key_len;
	config.reserved  = NULL;

	memcpy(config.iv, iv, sizeof(iv));

	res = rk_oem_otp_key_cipher_virt(key_id, &config, in, out, data_len);
	if (res)
		printf("test rk_oem_otp_key_cipher_virt fail! 0x%08x\n", res);

	res = soft_cipher(algo, mode, RK_OP_CIPHER_ENC, key, key_len, iv,
			  in, data_len, out_soft);
	if (res) {
		printf("test cipher soft fail! 0x%08x\n", res);
		return res;
	}

	if (memcmp(out_soft, out, data_len)) {
		printf("compare ENC result faild!!!\n");
		test_dump_hex("key:", key, key_len);
		test_dump_hex("iv:", iv, sizeof(iv));
		test_dump_hex("in:", in, data_len > 128 ? 128 : data_len);
		test_dump_hex("out:", out, data_len > 128 ? 128 : data_len);
		test_dump_hex("expected:", out_soft, data_len > 128 ? 128 : data_len);
		return -1;
	} else
		printf("ENC result success.\n");

	config.operation = RK_OP_CIPHER_DEC;

	res = rk_oem_otp_key_cipher_virt(key_id, &config, out, out, data_len);
	if (res)
		printf("test rk_oem_otp_key_cipher_virt fail! 0x%08x\n", res);

	if (memcmp(out, in, data_len)) {
		printf("compare DEC result faild!!!\n");
		test_dump_hex("key:", key, key_len);
		test_dump_hex("iv:", iv, sizeof(iv));
		test_dump_hex("in:", out_soft, data_len > 128 ? 128 : data_len);
		test_dump_hex("out:", out, data_len > 128 ? 128 : data_len);
		test_dump_hex("expected:", in, data_len > 128 ? 128 : data_len);
		return -1;
	} else
		printf("DEC result success.\n");

	return 0;
}

static int test_func_item_fd(uint32_t key_id, uint32_t key_len,
			     uint32_t algo, uint32_t mode,
			     uint32_t data_len)
{
	uint32_t res = 0;
	rk_cipher_config config;
	uint8_t *key = NULL;
	uint8_t *out_soft = NULL;
	uint8_t iv[16];
	rk_crypto_mem *in = NULL;
	rk_crypto_mem *out = NULL;

	printf("### phys: key_id:%d, algo:%s, mode:%s, key_len:%d, data_len:%d\n",
	       key_id, algo_name_tab[algo], mode_name_tab[mode], key_len, data_len);

	switch (key_id) {
	case RK_OEM_OTP_KEY0:
		key = otp_key0;
		break;
	case RK_OEM_OTP_KEY1:
		key = otp_key1;
		break;
	case RK_OEM_OTP_KEY2:
		key = otp_key2;
		break;
	case RK_OEM_OTP_KEY3:
		key = otp_key3;
		break;
	default:
		return -1;
	}

	res = rk_crypto_init();
	if (res) {
		printf("rk_crypto_init error! res: 0x%08x\n", res);
		return res;
	}

	in = rk_crypto_mem_alloc(data_len);
	if (!in) {
		printf("rk_crypto_mem_alloc %uByte error!\n", data_len);
		res = -1;
		goto exit;
	}

	out = rk_crypto_mem_alloc(data_len);
	if (!out) {
		printf("rk_crypto_mem_alloc %uByte error!\n", data_len);
		res = -1;
		goto exit;
	}

	out_soft = malloc(data_len);
	if (!out_soft) {
		printf("malloc %uByte error!\n", data_len);
		res = -1;
		goto exit;
	}

	test_get_rng(iv, sizeof(iv));
	test_get_rng(in->vaddr, data_len);

	config.algo      = algo;
	config.mode      = mode;
	config.operation = RK_OP_CIPHER_ENC;
	config.key_len   = key_len;
	config.reserved  = NULL;

	memcpy(config.iv, iv, sizeof(iv));

	res = rk_oem_otp_key_cipher(key_id, &config, in->dma_fd, out->dma_fd, data_len);
	if (res) {
		printf("test rk_oem_otp_key_cipher fail! 0x%08x\n", res);
		goto exit;
	}

	res = soft_cipher(algo, mode, RK_OP_CIPHER_ENC, key, key_len, iv,
			  in->vaddr, data_len, out_soft);
	if (res) {
		printf("test cipher soft fail! 0x%08x\n", res);
		goto exit;
	}

	if (memcmp(out->vaddr, out_soft, data_len)) {
		printf("compare ENC result faild!!!\n");
		test_dump_hex("key:", key, key_len);
		test_dump_hex("iv:", iv, sizeof(iv));
		test_dump_hex("in:", in->vaddr, data_len > 128 ? 128 : data_len);
		test_dump_hex("out:", out->vaddr, data_len > 128 ? 128 : data_len);
		test_dump_hex("expected:", out_soft, data_len > 128 ? 128 : data_len);
		res = -1;
		goto exit;
	} else
		printf("ENC result success.\n");

	config.operation = RK_OP_CIPHER_DEC;

	res = rk_oem_otp_key_cipher(key_id, &config, out->dma_fd, out->dma_fd, data_len);
	if (res) {
		printf("test rk_oem_otp_key_cipher fail! 0x%08x\n", res);
		goto exit;
	}

	if (memcmp(out->vaddr, in->vaddr, data_len)) {
		printf("compare DEC result faild!!!\n");
		test_dump_hex("key:", key, key_len);
		test_dump_hex("iv:", iv, sizeof(iv));
		test_dump_hex("in:", out_soft, data_len > 128 ? 128 : data_len);
		test_dump_hex("out:", out->vaddr, data_len > 128 ? 128 : data_len);
		test_dump_hex("expected:", in->vaddr, data_len > 128 ? 128 : data_len);
		res = -1;
		goto exit;
	} else
		printf("DEC result success.\n");

	res = 0;
exit:
	if (!in)
		rk_crypto_mem_free(in);

	if (!out)
		rk_crypto_mem_free(out);

	if (!out_soft)
		free(out_soft);

	rk_crypto_deinit();
	return res;
}

static int test_speed_item_virt(uint32_t key_id, uint32_t key_len,
				uint32_t algo, uint32_t mode,
				uint32_t data_len, uint32_t count)
{
	uint32_t res;
	uint32_t i;
	rk_cipher_config config;
	uint8_t iv[16];
	uint8_t in_out[RK_CRYPTO_MAX_DATA_LEN];
	struct timespec start, end;
	unsigned long long millisecond = 0;

	printf("### virt: key_id:%d, algo:%s, mode:%s, key_len:%d, data_len:%d, count:%d\n",
	       key_id, algo_name_tab[algo], mode_name_tab[mode], key_len, data_len, count);

	memset(iv, 0x00, sizeof(iv));
	memset(in_out, 0x00, sizeof(in_out));

	test_get_rng(iv, sizeof(iv));
	test_get_rng(in_out, data_len);

	config.algo      = algo;
	config.mode      = mode;
	config.operation = RK_OP_CIPHER_ENC;
	config.key_len   = key_len;
	config.reserved  = NULL;

	memcpy(config.iv, iv, sizeof(iv));

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (i = 0; i < count; i++) {
		res = rk_oem_otp_key_cipher_virt(key_id, &config, in_out, in_out, data_len);
		if (res) {
			printf("test rk_oem_otp_key_cipher_virt fail! 0x%08x\n", res);
			return res;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	millisecond = (end.tv_sec - start.tv_sec) * 1000 +
		      (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("ENC speed: [%lldms/%d]\n", millisecond, count);

	config.operation = RK_OP_CIPHER_DEC;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (i = 0; i < count; i++) {
		res = rk_oem_otp_key_cipher_virt(key_id, &config, in_out, in_out, data_len);
		if (res) {
			printf("test rk_oem_otp_key_cipher_virt fail! 0x%08x\n", res);
			return res;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	millisecond = (end.tv_sec - start.tv_sec) * 1000 +
		      (end.tv_nsec - start.tv_nsec) / 1000000;

	printf("DEC speed: [%lldms/%d]\n\n", millisecond, count);

	return res;
}

static int test_speed_item_fd(uint32_t key_id, uint32_t key_len,
			      uint32_t algo, uint32_t mode,
			      uint32_t data_len, uint32_t count)
{
	uint32_t res;
	uint32_t i;
	rk_cipher_config config;
	uint8_t iv[16];
	rk_crypto_mem *in_out = NULL;
	struct timespec start, end;
	unsigned long long millisecond = 0;

	printf("### phys: key_id:%d, algo:%s, mode:%s, key_len:%d, data_len:%d, count:%d\n",
	       key_id, algo_name_tab[algo], mode_name_tab[mode], key_len, data_len, count);

	res = rk_crypto_init();
	if (res) {
		printf("rk_crypto_init error! res: 0x%08x\n", res);
		return res;
	}

	in_out = rk_crypto_mem_alloc(data_len);
	if (!in_out) {
		printf("rk_crypto_mem_alloc %uByte error!\n", data_len);
		res = -1;
		goto exit;
	}

	memset(iv, 0x00, sizeof(iv));
	test_get_rng(iv, sizeof(iv));
	test_get_rng(in_out->vaddr, data_len);

	config.algo      = algo;
	config.mode      = mode;
	config.operation = RK_OP_CIPHER_ENC;
	config.key_len   = key_len;
	config.reserved  = NULL;

	memcpy(config.iv, iv, sizeof(iv));

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (i = 0; i < count; i++) {
		res = rk_oem_otp_key_cipher(key_id, &config, in_out->dma_fd, in_out->dma_fd, data_len);
		if (res) {
			printf("test rk_oem_otp_key_cipher fail! 0x%08x\n", res);
			goto exit;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	millisecond = (end.tv_sec - start.tv_sec) * 1000 +
		      (end.tv_nsec - start.tv_nsec) / 1000000;
	printf("ENC speed: [%lldms/%d]\n", millisecond, count);

	config.operation = RK_OP_CIPHER_DEC;
	clock_gettime(CLOCK_MONOTONIC, &start);

	for (i = 0; i < count; i++) {
		res = rk_oem_otp_key_cipher(key_id, &config, in_out->dma_fd, in_out->dma_fd, data_len);
		if (res) {
			printf("test rk_oem_otp_key_cipher fail! 0x%08x\n", res);
			goto exit;
		}
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	millisecond = (end.tv_sec - start.tv_sec) * 1000 +
		      (end.tv_nsec - start.tv_nsec) / 1000000;

	printf("DEC speed: [%lldms/%d]\n\n", millisecond, count);

exit:
	if (!in_out)
		rk_crypto_mem_free(in_out);

	rk_crypto_deinit();

	return res;
}

int test_speed_otp_key_cipher(uint32_t count)
{
	uint32_t h, j, l;
	uint32_t algo, key_id, mode, len, key_len;

	const uint32_t algo_tab[] = {
		RK_ALGO_AES,
		RK_ALGO_SM4,
	};
	const uint32_t mode_tab[] = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CTS,
		RK_CIPHER_MODE_CTR,
		RK_CIPHER_MODE_CFB,
		RK_CIPHER_MODE_OFB,
	};
	const uint32_t key_len_tab[] = {
		16,
		24,
		32
	};

	for (h = 0; h < ARRAY_SIZE(algo_tab); h++) {
		for (j = 0; j < ARRAY_SIZE(mode_tab); j++) {
			for (l = 0; l < ARRAY_SIZE(key_len_tab); l++) {
				algo = algo_tab[h];
				mode = mode_tab[j];
				key_id = RK_OEM_OTP_KEY0;
				key_len = key_len_tab[l];
				len = 1024 * 1024;

				if (algo == RK_ALGO_SM4 && key_len != 16)
					break;

				if (test_speed_item_virt(key_id, key_len, algo, mode, len, count))
					goto error;

				if (test_speed_item_fd(key_id, key_len, algo, mode, len, count))
					goto error;
			}
		}
	}

	printf("##### TEST SUCCESS.  #####\n");
	return 0;

error:
	printf("##### TEST FILED!!!  #####\n");
	return -1;
}

int test_func_otp_key_cipher(void)
{
	uint32_t h, i, j, k, l;
	uint32_t algo, key_id, mode, len, key_len;

	const uint32_t algo_tab[] = {
		RK_ALGO_AES,
		RK_ALGO_SM4,
	};
	const uint32_t key_tab[] = {
		RK_OEM_OTP_KEY0,
		RK_OEM_OTP_KEY1,
		RK_OEM_OTP_KEY2,
		RK_OEM_OTP_KEY3,
	};
	const uint32_t mode_tab[] = {
		RK_CIPHER_MODE_ECB,
		RK_CIPHER_MODE_CBC,
		RK_CIPHER_MODE_CTS,
		RK_CIPHER_MODE_CTR,
		RK_CIPHER_MODE_CFB,
		RK_CIPHER_MODE_OFB,
	};
	const uint32_t len_tab[] = {
		32,
		1024,
		512 * 1024,
		1024 * 1024
	};
	const uint32_t key_len_tab[] = {
		16,
		24,
		32
	};

	for (h = 0; h < ARRAY_SIZE(algo_tab); h++) {
		for (i = 0; i < ARRAY_SIZE(key_tab); i++) {
			for (j = 0; j < ARRAY_SIZE(mode_tab); j++) {
				for (k = 0; k < ARRAY_SIZE(len_tab); k++) {
					for (l = 0; l < ARRAY_SIZE(key_len_tab); l++) {
						algo = algo_tab[h];
						key_id = key_tab[i];
						mode = mode_tab[j];
						len = len_tab[k];
						key_len = key_len_tab[l];

						if (algo == RK_ALGO_SM4 && key_len != 16)
							break;

						if (test_func_item_virt(key_id, key_len, algo, mode, len))
							goto error;

						if (test_func_item_fd(key_id, key_len, algo, mode, len))
							goto error;
					}
				}
			}
		}
	}

	printf("##### TEST SUCCESS.  #####\n");
	return 0;

error:
	printf("##### TEST FILED!!!  #####\n");
	return -1;
}

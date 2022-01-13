/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <stdio.h>
#include <string.h>
#include "librkcrypto.h"
#include "rkcrypto_common.h"

int main(void)
{
	int ret = -1;
	rk_cipher_config config;
	uint32_t key_id = RK_OEM_OTP_KEY0;
	uint32_t key_len = 16;
	uint32_t algo = RK_ALGO_AES;
	uint32_t mode = RK_CIPHER_MODE_CBC;
	uint8_t otp_key_0[32] = {
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	uint8_t iv[16] = {
		0x10, 0x44, 0x80, 0xb3, 0x88, 0x5f, 0x02, 0x03,
		0x05, 0x21, 0x07, 0xc9, 0x44, 0x00, 0x1b, 0x80,
	};
	uint8_t input[16] = {
		0xc9, 0x07, 0x21, 0x05, 0x80, 0x1b, 0x00, 0x44,
		0xac, 0x13, 0xfb, 0x23, 0x93, 0x4a, 0x66, 0xe4,
	};
	uint8_t expected_enc[16] = {
		0xeb, 0xe7, 0xde, 0x12, 0x8d, 0x77, 0xf4, 0xe8,
		0x83, 0x4a, 0x63, 0x1d, 0x0e, 0xcc, 0xdb, 0x1c,
	};
	uint8_t output[16];
	uint32_t data_len = sizeof(input);

	/* Write keys. If written before, it will returns failure. */
	if (rk_write_oem_otp_key(RK_OEM_OTP_KEY0, otp_key_0, sizeof(otp_key_0)))
		printf("Check if otp key 0 is already written!\n");
	else
		printf("Write otp key 0, success!\n");

	/* Do cipher. */
	memset(output, 0, sizeof(output));

	config.algo      = algo;
	config.mode      = mode;
	config.operation = RK_MODE_ENCRYPT;
	config.key_len   = key_len;
	config.reserved  = NULL;
	memcpy(config.iv, iv, sizeof(iv));

	if (rk_oem_otp_key_cipher(key_id, &config, input, output, data_len)) {
		printf("Do rk_oem_otp_key_cipher error!\n");
		goto exit;
	}

	if (memcmp(output, expected_enc, data_len)) {
		printf("ENC result not equal to expected value, error!\n");
		goto exit;
	}

	printf("Test rk_oem_otp_key_cipher ENC success!\n");

	config.operation = RK_MODE_DECRYPT;
	if (rk_oem_otp_key_cipher(key_id, &config, output, output, data_len)) {
		printf("Do rk_oem_otp_key_cipher error!\n");
		goto exit;
	}

	if (memcmp(output, input, data_len)) {
		printf("DEC result not equal to expected value, error!\n");
		goto exit;
	}

	printf("Test rk_oem_otp_key_cipher DEC success!\n");

	ret = 0;
exit:
	return ret;
}

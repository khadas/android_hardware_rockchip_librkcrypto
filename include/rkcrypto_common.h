/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#ifndef _RKCRYPTO_COMMON_H_
#define _RKCRYPTO_COMMON_H_

#include <stdint.h>

typedef uint32_t RK_RES;

/* API return codes */
#define RK_ALG_SUCCESS			0x00000000
#define RK_ALG_ERR_GENERIC		0xF0000000
#define RK_ALG_ERR_PARAMETER		0xF0000001
#define RK_ALG_ERR_STATE		0xF0000002
#define RK_ALG_ERR_NOT_SUPPORTED	0xF0000003

/* Algorithm operation */
#define RK_MODE_ENCRYPT			1
#define RK_MODE_DECRYPT			0

/* Algorithm block length */
#define DES_BLOCK_SIZE			8
#define AES_BLOCK_SIZE			16
#define SM4_BLOCK_SIZE			16
#define SHA1_HASH_SIZE			20
#define SHA224_HASH_SIZE		28
#define SHA256_HASH_SIZE		32
#define SHA384_HASH_SIZE		48
#define SHA512_HASH_SIZE		64
#define MD5_HASH_SIZE			16
#define SM3_HASH_SIZE			32
#define AES_AE_DATA_BLOCK		128
#define MAX_HASH_BLOCK_SIZE		128
#define MAX_TDES_KEY_SIZE		24
#define MAX_AES_KEY_SIZE		32

#define RK_CRYPTO_MAX_DATA_LEN		(1 * 1024 * 1024)

typedef struct {
	uint32_t	algo;
	uint32_t	mode;
	uint32_t	operation;
	uint8_t		key[64];
	uint32_t	key_len;
	uint8_t		iv[16];
	void		*reserved;
} rk_cipher_config;

/* Crypto algorithm */
enum RK_CRYPTO_ALGO {
	RK_ALGO_AES = 1,
	RK_ALGO_DES,
	RK_ALGO_TDES,
	RK_ALGO_SM4,
	RK_ALGO_ALGO_MAX
};

/* Crypto mode */
enum RK_CIPIHER_MODE {
	RK_CIPHER_MODE_ECB = 0,
	RK_CIPHER_MODE_CBC = 1,
	RK_CIPHER_MODE_CTS = 2,
	RK_CIPHER_MODE_CTR = 3,
	RK_CIPHER_MODE_CFB = 4,
	RK_CIPHER_MODE_OFB = 5,
	RK_CIPHER_MODE_XTS = 6,
	RK_CIPHER_MODE_CCM = 7,
	RK_CIPHER_MODE_GCM = 8,
	RK_CIPHER_MODE_CMAC = 9,
	RK_CIPHER_MODE_CBC_MAC = 10,
	RK_CIPHER_MODE_MAX
};

enum RK_OEM_OTP_KEYID {
	RK_OEM_OTP_KEY0 = 0,
	RK_OEM_OTP_KEY1 = 1,
	RK_OEM_OTP_KEY2 = 2,
	RK_OEM_OTP_KEY3 = 3,
	RK_OEM_OTP_KEY_FW = 10,	//keyid of fw_encryption_key
	RK_OEM_OTP_KEYMAX
};

#endif /* _RKCRYPTO_COMMON_H_ */


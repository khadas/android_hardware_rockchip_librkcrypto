/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <string.h>
#include "otp_key_crypto.h"
#include "rkcrypto_trace.h"
#include "tee_client_api.h"

#define STORAGE_UUID { 0x2d26d8a8, 0x5134, 0x4dd8, \
		{ 0xb3, 0x2f, 0xb3, 0x4b, 0xce, 0xeb, 0xc4, 0x71 } }
#define RK_CRYPTO_SERVICE_UUID	{ 0x0cacdb5d, 0x4fea, 0x466c, \
		{ 0x97, 0x16, 0x3d, 0x54, 0x16, 0x52, 0x83, 0x0f } }

#define STORAGE_CMD_WRITE_OEM_OTP_KEY			14
#define STORAGE_CMD_SET_OEM_HR_OTP_READ_LOCK		15
#define CRYPTO_SERVICE_CMD_OEM_OTP_KEY_CIPHER		0x00000001

RK_RES rk_write_oem_otp_key(enum RK_OEM_OTP_KEYID key_id, uint8_t *key,
			    uint32_t key_len)
{
	RK_RES res;
	TEEC_Context contex;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_UUID uuid = STORAGE_UUID;
	uint32_t error_origin = 0;

	RK_ALG_CHECK_PARAM(key_id != RK_OEM_OTP_KEY0 &&
			   key_id != RK_OEM_OTP_KEY1 &&
			   key_id != RK_OEM_OTP_KEY2 &&
			   key_id != RK_OEM_OTP_KEY3 &&
			   key_id != RK_OEM_OTP_KEY_FW);
	RK_ALG_CHECK_PARAM(!key);
	RK_ALG_CHECK_PARAM(key_len != 16 &&
			   key_len != 24 &&
			   key_len != 32);
	RK_ALG_CHECK_PARAM(key_id == RK_OEM_OTP_KEY_FW &&
			   key_len != 16);

	res = TEEC_InitializeContext(NULL, &contex);
	if (res != TEEC_SUCCESS) {
		E_TRACE("TEEC_InitializeContext failed with code TEEC res= 0x%x", res);
		res = RK_ALG_ERR_GENERIC;
		return res;
	}

	res = TEEC_OpenSession(&contex, &session, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &error_origin);
	if (res != TEEC_SUCCESS) {
		E_TRACE("TEEC_Opensession failed with code TEEC res= 0x%x origin 0x%x",
			res, error_origin);
		res = RK_ALG_ERR_GENERIC;
		goto out;
	}

	memset(&operation, 0, sizeof(TEEC_Operation));
	operation.params[0].value.a       = key_id;
	operation.params[1].tmpref.buffer = key;
	operation.params[1].tmpref.size   = key_len;
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						TEEC_MEMREF_TEMP_INPUT,
						TEEC_NONE,
						TEEC_NONE);

	res = TEEC_InvokeCommand(&session, STORAGE_CMD_WRITE_OEM_OTP_KEY,
				 &operation, &error_origin);
	if (res != TEEC_SUCCESS) {
		E_TRACE("InvokeCommand ERR! TEEC res= 0x%x, error_origin= 0x%x",
			res, error_origin);
		res = RK_ALG_ERR_GENERIC;
	}

	TEEC_CloseSession(&session);
out:
	TEEC_FinalizeContext(&contex);
	return res;
}

RK_RES rk_set_oem_hr_otp_read_lock(enum RK_OEM_OTP_KEYID key_id)
{
	RK_RES res;
	TEEC_Context contex;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_UUID uuid = STORAGE_UUID;
	uint32_t error_origin = 0;

	RK_ALG_CHECK_PARAM(key_id != RK_OEM_OTP_KEY0 &&
			   key_id != RK_OEM_OTP_KEY1 &&
			   key_id != RK_OEM_OTP_KEY2 &&
			   key_id != RK_OEM_OTP_KEY3);

	res = TEEC_InitializeContext(NULL, &contex);
	if (res != TEEC_SUCCESS) {
		E_TRACE("TEEC_InitializeContext failed with code TEEC res= 0x%x", res);
		res = RK_ALG_ERR_GENERIC;
		return res;
	}

	res = TEEC_OpenSession(&contex, &session, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &error_origin);
	if (res != TEEC_SUCCESS) {
		E_TRACE("TEEC_Opensession failed with code TEEC res= 0x%x origin 0x%x",
			res, error_origin);
		res = RK_ALG_ERR_GENERIC;
		goto out;
	}

	memset(&operation, 0, sizeof(TEEC_Operation));
	operation.params[0].value.a = key_id;
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						TEEC_NONE,
						TEEC_NONE,
						TEEC_NONE);

	res = TEEC_InvokeCommand(&session, STORAGE_CMD_SET_OEM_HR_OTP_READ_LOCK,
				 &operation, &error_origin);
	if (res != TEEC_SUCCESS) {
		E_TRACE("InvokeCommand ERR! TEEC res= 0x%x, error_origin= 0x%x",
			res, error_origin);
		res = RK_ALG_ERR_GENERIC;
	}

	TEEC_CloseSession(&session);
out:
	TEEC_FinalizeContext(&contex);
	return res;
}

RK_RES rk_oem_otp_key_cipher(enum RK_OEM_OTP_KEYID key_id, rk_cipher_config *config,
			     uint8_t *src, uint8_t *dst, uint32_t len)
{
	RK_RES res;
	TEEC_Context contex;
	TEEC_Session session;
	TEEC_Operation operation;
	TEEC_UUID uuid = RK_CRYPTO_SERVICE_UUID;
	uint32_t error_origin = 0;
	TEEC_SharedMemory sm;

	RK_ALG_CHECK_PARAM(key_id != RK_OEM_OTP_KEY0 &&
			   key_id != RK_OEM_OTP_KEY1 &&
			   key_id != RK_OEM_OTP_KEY2 &&
			   key_id != RK_OEM_OTP_KEY3 &&
			   key_id != RK_OEM_OTP_KEY_FW);
	RK_ALG_CHECK_PARAM(!config  || !src || !dst);
	RK_ALG_CHECK_PARAM(config->algo != RK_ALGO_AES &&
			   config->algo != RK_ALGO_SM4);
	RK_ALG_CHECK_PARAM(config->mode >= RK_CIPHER_MODE_XTS);
	RK_ALG_CHECK_PARAM(config->operation != RK_MODE_ENCRYPT &&
			   config->operation != RK_MODE_DECRYPT);
	RK_ALG_CHECK_PARAM(config->key_len != 16 &&
			   config->key_len != 24 &&
			   config->key_len != 32);
	RK_ALG_CHECK_PARAM(key_id == RK_OEM_OTP_KEY_FW &&
			   config->key_len != 16);
	RK_ALG_CHECK_PARAM(len % AES_BLOCK_SIZE ||
			   len > RK_CRYPTO_MAX_DATA_LEN ||
			   len == 0);

	res = TEEC_InitializeContext(NULL, &contex);
	if (res != TEEC_SUCCESS) {
		E_TRACE("TEEC_InitializeContext failed with code TEEC res= 0x%x", res);
		res = RK_ALG_ERR_GENERIC;
		return res;
	}

	res = TEEC_OpenSession(&contex, &session, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &error_origin);
	if (res != TEEC_SUCCESS) {
		E_TRACE("TEEC_Opensession failed with code TEEC res= 0x%x origin 0x%x",
			res, error_origin);
		res = RK_ALG_ERR_GENERIC;
		goto out;
	}

	sm.size = len;
	sm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	res = TEEC_AllocateSharedMemory(&contex, &sm);
	if (res != TEEC_SUCCESS) {
		E_TRACE("AllocateSharedMemory ERR! TEEC res= 0x%x", res);
		res = RK_ALG_ERR_GENERIC;
		goto out1;
	}

	memcpy(sm.buffer, src, len);

	memset(&operation, 0, sizeof(TEEC_Operation));
	operation.params[0].value.a       = key_id;
	operation.params[1].tmpref.buffer = config;
	operation.params[1].tmpref.size   = sizeof(rk_cipher_config);
	operation.params[2].memref.parent = &sm;
	operation.params[2].memref.offset = 0;
	operation.params[2].memref.size   = sm.size;

	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						TEEC_MEMREF_TEMP_INPUT,
						TEEC_MEMREF_PARTIAL_INOUT,
						TEEC_NONE);

	res = TEEC_InvokeCommand(&session, CRYPTO_SERVICE_CMD_OEM_OTP_KEY_CIPHER,
				 &operation, &error_origin);
	if (res != TEEC_SUCCESS) {
		E_TRACE("InvokeCommand ERR! TEEC res= 0x%x, error_origin= 0x%x",
			res, error_origin);
		res = RK_ALG_ERR_GENERIC;
	} else {
		memcpy(dst, sm.buffer, sm.size);
	}

	TEEC_ReleaseSharedMemory(&sm);

out1:
	TEEC_CloseSession(&session);

out:
	TEEC_FinalizeContext(&contex);
	return res;
}

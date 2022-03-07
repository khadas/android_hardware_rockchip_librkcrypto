/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */

#include <stdlib.h>
#include <string.h>

#include "rkcrypto_core.h"
#include "rkcrypto_trace.h"

#define ASN1_INTEGER			((uint8_t)0x02)
#define ASN1_BIT_STRING			((uint8_t)0x03)
#define ASN1_OCT_STRING			((uint8_t)0x04)
#define ASN1_NULL			((uint8_t)0x05)
#define ASN1_OBJ_IDENTIFIER		((uint8_t)0x06)
#define ASN1_SEQUENCE			((uint8_t)0x30)
#define ASN1_CONTEXT0			((uint8_t)0xA0)
#define ASN1_CONTEXT1			((uint8_t)0xA1)

typedef struct {
	const uint8_t	*data;		//the buffer of data
	uint16_t	*data_len;	//valid length of data
	uint8_t		tag;		//ASN1 data type
	uint8_t		need_plus;	//to identify weather the data is a positive number
} asn1_object_t;

static RK_RES asn1_compose_len(uint32_t len, uint8_t *field, uint32_t *field_len)
{
	uint8_t tmp_field[4], i, j;

	if (field == NULL || field_len == NULL)
		return RK_CRYPTO_ERR_PARAMETER;

	if (len < 0x80) {
		*field     = len;
		*field_len = 1;
	} else {
		tmp_field[0] = (len >> 24) & 0xff;
		tmp_field[1] = (len >> 16) & 0xff;
		tmp_field[2] = (len >> 8) & 0xff;
		tmp_field[3] = len & 0xff;

		for (i = 0; i < sizeof(tmp_field); i++) {
			if (tmp_field[i] == 0x00)
				continue;

			for (j = 0; j < sizeof(tmp_field) - i; j++)
				field[j + 1] = tmp_field[j + i];

			break;
		}
		field[0]   = 0X80 + sizeof(tmp_field) - i;
		*field_len = sizeof(tmp_field) - i + 1;
	}

	return RK_CRYPTO_SUCCESS;
}

static RK_RES asn1_set_object(const uint8_t *in, uint32_t in_len, uint8_t tag, uint8_t need_plus,
			      uint8_t *out, uint32_t out_max, uint32_t *out_len)
{
	RK_RES res;
	uint8_t *pout = out;
	uint32_t field_len;
	uint8_t tmp_field[5];

	if (in == NULL || out == NULL || out_len == NULL)
		return RK_CRYPTO_ERR_PARAMETER;

	*out_len = 0;

	//padding tag field
	if (out_max < 1) {
		res = RK_CRYPTO_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	*pout = tag;
	pout++;
	out_max--;

	//padding length field
	if (need_plus && *in >= 0x80)
		res = asn1_compose_len(in_len + 1, tmp_field, &field_len);
	else
		res = asn1_compose_len(in_len, tmp_field, &field_len);

	if (res != RK_CRYPTO_SUCCESS) {
		D_TRACE("asn1_compose_len error");
		return res;
	}

	if (out_max < field_len) {
		D_TRACE("out_max = %d, field_len = %d", out_max, field_len);
		res = RK_CRYPTO_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	memmove(pout, tmp_field, field_len);
	pout    += field_len;
	out_max -= field_len;

	//padding value field
	if (need_plus && *in >= 0x80) {
		if (out_max < 1) {
			res = RK_CRYPTO_ERR_OUT_OF_MEMORY;
			goto exit;
		}

		*pout = 0x00;
		pout++;
		out_max--;
	}

	if (out_max < in_len) {
		res = RK_CRYPTO_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	memmove(pout, in, in_len);
	pout += in_len;

	*out_len = pout-out;

exit:
	return res;
}

RK_RES rk_rsa_pubkey_encode(rk_rsa_pub_key_pack *pub,
			    uint8_t *asn1_key, uint16_t *asn1_key_len, uint16_t *key_bits)
{
	RK_RES res;
	rk_rsa_pub_key *rsa_key = &pub->key;
	uint8_t tmp_field[8];
	uint32_t total_len = 0, tmp_len = 0, out_max;

	RK_CRYPTO_CHECK_PARAM(!asn1_key || !asn1_key_len || !pub || !key_bits);
	RK_CRYPTO_CHECK_PARAM(!rsa_key->n || rsa_key->n_len == 0);
	RK_CRYPTO_CHECK_PARAM(!rsa_key->e || rsa_key->e_len == 0);
	RK_CRYPTO_CHECK_PARAM(rsa_key->n_len != 1024 / 8 &&
			      rsa_key->n_len != 2048 / 8 &&
			      rsa_key->n_len != 3072 / 8 &&
			      rsa_key->n_len != 4096 / 8);
	RK_CRYPTO_CHECK_PARAM(pub->key_type != RK_RSA_KEY_TYPE_PLAIN);

	out_max = *asn1_key_len;

	//padding n
	res = asn1_set_object(rsa_key->n, rsa_key->n_len, ASN1_INTEGER, 1,
			      asn1_key + total_len, out_max, &tmp_len);
	if (res != RK_CRYPTO_SUCCESS) {
		D_TRACE("set rsa_key->n object error!");
		goto exit;
	}

	total_len += tmp_len;
	out_max -= tmp_len;

	//padding e
	res = asn1_set_object(rsa_key->e, rsa_key->e_len, ASN1_INTEGER, 0,
			      asn1_key + total_len, out_max, &tmp_len);
	if (res != RK_CRYPTO_SUCCESS) {
		D_TRACE("set rsa_key->e object error!");
		goto exit;
	}
	total_len += tmp_len;
	out_max   -= tmp_len;

	//add SEQUENCE info in head
	res = asn1_compose_len(total_len, tmp_field, &tmp_len);
	if (res != RK_CRYPTO_SUCCESS) {
		D_TRACE("set asn1_compose_len error!");
		goto exit;
	}

	if (out_max < tmp_len + 1) {
		res = RK_CRYPTO_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	memmove(asn1_key + tmp_len + 1, asn1_key, total_len);
	*asn1_key = ASN1_SEQUENCE;
	total_len++;
	memmove(asn1_key + 1, tmp_field, tmp_len);
	total_len += tmp_len;

	*asn1_key_len = total_len;
	*key_bits = rsa_key->n_len * 8;
exit:
	return res;
}

RK_RES rk_rsa_privkey_encode(rk_rsa_priv_key_pack *priv,
			     uint8_t *asn1_key, uint16_t *asn1_key_len, uint16_t *key_bits)
{
	RK_RES res;
	uint8_t *empty_data = NULL;
	uint8_t tmp_field[5];
	uint32_t total_len = 0, tmp_len = 0;
	uint8_t version[1] = {0};
	uint16_t ver_len = 1;
	rk_rsa_priv_key *rsa_key = &priv->key;
	uint32_t i, out_max, empty_data_len;
	asn1_object_t object_list[] = {
		{version,     &ver_len,          ASN1_INTEGER, 0},
		{rsa_key->n,  &rsa_key->n_len,   ASN1_INTEGER, 1},
		{rsa_key->e,  &rsa_key->e_len,   ASN1_INTEGER, 0},
		{rsa_key->d,  &rsa_key->d_len,   ASN1_INTEGER, 1},
		{rsa_key->p,  &rsa_key->p_len,   ASN1_INTEGER, 1},
		{rsa_key->q,  &rsa_key->q_len,   ASN1_INTEGER, 1},
		{rsa_key->dp, &rsa_key->dp_len,  ASN1_INTEGER, 1},
		{rsa_key->dq, &rsa_key->dq_len,  ASN1_INTEGER, 1},
		{rsa_key->qp, &rsa_key->qp_len,  ASN1_INTEGER, 1},
	};

	RK_CRYPTO_CHECK_PARAM(!asn1_key || !asn1_key_len || !priv || !key_bits);
	RK_CRYPTO_CHECK_PARAM(!rsa_key->n || rsa_key->n_len == 0);
	RK_CRYPTO_CHECK_PARAM(!rsa_key->e || rsa_key->e_len == 0);
	RK_CRYPTO_CHECK_PARAM(rsa_key->n_len != 1024 / 8 &&
			      rsa_key->n_len != 2048 / 8 &&
			      rsa_key->n_len != 3072 / 8 &&
			      rsa_key->n_len != 4096 / 8);
	RK_CRYPTO_CHECK_PARAM(!rsa_key->d || rsa_key->d_len == 0);
	RK_CRYPTO_CHECK_PARAM(rsa_key->n_len != rsa_key->d_len);

	RK_CRYPTO_CHECK_PARAM(priv->key_type != RK_RSA_KEY_TYPE_PLAIN);

	out_max = *asn1_key_len;

	empty_data_len = rsa_key->n_len / 2;
	empty_data = malloc(empty_data_len);
	if (!empty_data)
		return RK_CRYPTO_ERR_OUT_OF_MEMORY;

	memset(empty_data, 0xff, empty_data_len);

	for (i = 0; i < sizeof(object_list) / sizeof(object_list[0]); i++) {
		const uint8_t *data = object_list[i].data;
		uint32_t data_len = *(object_list[i].data_len);

		data     = data ? data : empty_data;
		data_len = data ? data_len : empty_data_len;

		res = asn1_set_object(data, data_len,
				      object_list[i].tag,
				      object_list[i].need_plus,
				      asn1_key + total_len, out_max, &tmp_len);
		if (res != RK_CRYPTO_SUCCESS) {
			D_TRACE("set %d object error!", i);
			goto exit;
		}

		total_len += tmp_len;
		out_max   -= tmp_len;
	}

	res = asn1_compose_len(total_len, tmp_field, &tmp_len);
	if (res != RK_CRYPTO_SUCCESS) {
		D_TRACE("set asn1_compose_len error!");
		goto exit;
	}

	if (out_max < tmp_len + 1) {
		res = RK_CRYPTO_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	memmove(asn1_key + tmp_len + 1, asn1_key, total_len);
	*asn1_key = ASN1_SEQUENCE;
	total_len++;
	memmove(asn1_key + 1, tmp_field, tmp_len);
	total_len += tmp_len;

	*asn1_key_len = total_len;
	*key_bits = rsa_key->n_len * 8;
exit:
	if (empty_data)
		free(empty_data);

	return res;
}

RK_RES rk_rsa_crypt_do_padding(enum RK_RSA_CRYPT_PADDING padding, uint16_t key_len,
			       const uint8_t *data, uint32_t data_len,
			       uint8_t *pad, uint32_t *pad_len)
{
	RK_RES res = RK_CRYPTO_SUCCESS;

	switch (padding) {
	case RK_RSA_CRYPT_PADDING_NONE:
		if (data_len != key_len) {
			D_TRACE("length not match %u != %u", data_len, key_len);
			return RK_CRYPTO_ERR_PARAMETER;
		}

		memcpy(pad, data, data_len);
		break;
	default:
		D_TRACE("unknown padding %d", padding);
		res = RK_CRYPTO_ERR_PARAMETER;
		break;
	}

	*pad_len = key_len;

	return res;
}

RK_RES rk_rsa_crypt_undo_padding(enum RK_RSA_CRYPT_PADDING padding, uint16_t key_len,
				 const uint8_t *pad, uint32_t pad_len,
				 uint8_t *data, uint32_t *data_len)
{
	RK_RES res = RK_CRYPTO_SUCCESS;

	switch (padding) {
	case RK_RSA_CRYPT_PADDING_NONE:
		if (pad_len != key_len) {
			D_TRACE("length not match %u != %u", pad_len, key_len);
			return RK_CRYPTO_ERR_PARAMETER;
		}

		memcpy(data, pad, pad_len);
		break;
	default:
		D_TRACE("unknown padding %d", padding);
		res = RK_CRYPTO_ERR_PARAMETER;
		break;
	}

	*data_len = key_len;

	return res;
}

RK_RES rk_rsa_sign_do_padding(enum RK_RSA_SIGN_PADDING padding, uint16_t key_len,
			      const uint8_t *data, uint32_t data_len,
			      uint8_t *pad, uint32_t *pad_len)
{
	RK_RES res = RK_CRYPTO_SUCCESS;

	switch (padding) {
	case RK_RSA_SIGN_PADDING_NONE:
		if (data_len != key_len) {
			D_TRACE("length not match %u != %u", data_len, key_len);
			return RK_CRYPTO_ERR_PARAMETER;
		}

		memcpy(pad, data, data_len);
		break;
	default:
		D_TRACE("unknown padding %d", padding);
		res = RK_CRYPTO_ERR_PARAMETER;
		break;
	}

	*pad_len = key_len;

	return res;
}

RK_RES rk_rsa_sign_undo_padding(enum RK_RSA_SIGN_PADDING padding, uint16_t key_len,
				const uint8_t *pad, uint32_t pad_len,
				uint8_t *data, uint32_t *data_len)
{
	RK_RES res = RK_CRYPTO_SUCCESS;

	switch (padding) {
	case RK_RSA_SIGN_PADDING_NONE:
		if (pad_len != key_len) {
			D_TRACE("length not match %u != %u", pad_len, key_len);
			return RK_CRYPTO_ERR_PARAMETER;
		}

		memcpy(data, pad, pad_len);
		break;
	default:
		D_TRACE("unknown padding %d", padding);
		res = RK_CRYPTO_ERR_PARAMETER;
		break;
	}

	*data_len = key_len;

	return res;
}


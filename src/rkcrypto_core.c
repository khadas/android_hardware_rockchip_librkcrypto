/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <error.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>

#include "rk_cryptodev.h"
#include "rkcrypto_mem.h"
#include "rkcrypto_core.h"
#include "rk_list.h"
#include "rkcrypto_trace.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

enum RK_CRYPTO_CONFIG_TYPE {
	RK_CONFIG_TYPE_CIPHER = 0,
	RK_CONFIG_TYPE_AE,
	RK_CONFIG_TYPE_HASH,
};

struct algo_map_info {
	uint32_t	algo;
	uint32_t	mode;
	uint32_t	crypto_id;
};

struct hash_result {
	uint8_t		hash[AALG_MAX_RESULT_LEN];
	uint32_t	len;
};

struct sess_id_node {
	uint32_t		sess_id;
	uint32_t		config_type;
	void			*priv;

	union {
		rk_cipher_config	cipher;
		rk_ae_config		ae;
		rk_hash_config		hash;
	} config;

	struct list_head	list;
};

static int cryptodev_fd = -1;
static int cryptodev_refcnt;

static struct list_head sess_id_list;
pthread_mutex_t sess_mutex = PTHREAD_MUTEX_INITIALIZER;

#define IS_CRYPTO_INVALID()	(cryptodev_fd < 0)

const struct algo_map_info algo_map_tbl[] = {
	{RK_ALGO_DES,  RK_CIPHER_MODE_ECB,     CRYPTO_RK_DES_ECB},
	{RK_ALGO_DES,  RK_CIPHER_MODE_CBC,     CRYPTO_RK_DES_CBC},
	{RK_ALGO_DES,  RK_CIPHER_MODE_CFB,     CRYPTO_RK_DES_CFB},
	{RK_ALGO_DES,  RK_CIPHER_MODE_OFB,     CRYPTO_RK_DES_OFB},

	{RK_ALGO_TDES, RK_CIPHER_MODE_ECB,     CRYPTO_RK_3DES_ECB},
	{RK_ALGO_TDES, RK_CIPHER_MODE_CBC,     CRYPTO_RK_3DES_CBC},
	{RK_ALGO_TDES, RK_CIPHER_MODE_CFB,     CRYPTO_RK_3DES_CFB},
	{RK_ALGO_TDES, RK_CIPHER_MODE_OFB,     CRYPTO_RK_3DES_OFB},

	{RK_ALGO_SM4,  RK_CIPHER_MODE_ECB,     CRYPTO_RK_SM4_ECB},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_CBC,     CRYPTO_RK_SM4_CBC},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_CFB,     CRYPTO_RK_SM4_CFB},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_OFB,     CRYPTO_RK_SM4_OFB},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_CTS,     CRYPTO_RK_SM4_CTS},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_CTR,     CRYPTO_RK_SM4_CTR},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_XTS,     CRYPTO_RK_SM4_XTS},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_CCM,     CRYPTO_RK_SM4_CCM},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_GCM,     CRYPTO_RK_SM4_GCM},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_CMAC,    CRYPTO_RK_SM4_CMAC},
	{RK_ALGO_SM4,  RK_CIPHER_MODE_CBC_MAC, CRYPTO_RK_SM4_CBC_MAC},

	{RK_ALGO_AES,  RK_CIPHER_MODE_ECB,     CRYPTO_RK_AES_ECB},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CBC,     CRYPTO_RK_AES_CBC},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CFB,     CRYPTO_RK_AES_CFB},
	{RK_ALGO_AES,  RK_CIPHER_MODE_OFB,     CRYPTO_RK_AES_OFB},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CTS,     CRYPTO_RK_AES_CTS},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CTR,     CRYPTO_RK_AES_CTR},
	{RK_ALGO_AES,  RK_CIPHER_MODE_XTS,     CRYPTO_RK_AES_XTS},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CCM,     CRYPTO_RK_AES_CCM},
	{RK_ALGO_AES,  RK_CIPHER_MODE_GCM,     CRYPTO_RK_AES_GCM},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CMAC,    CRYPTO_RK_AES_CMAC},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CBC_MAC, CRYPTO_RK_AES_CBC_MAC},

	{RK_ALGO_MD5,         0, CRYPTO_RK_MD5},
	{RK_ALGO_SHA1,        0, CRYPTO_RK_SHA1},
	{RK_ALGO_SHA224,      0, CRYPTO_RK_SHA224},
	{RK_ALGO_SHA256,      0, CRYPTO_RK_SHA256},
	{RK_ALGO_SHA384,      0, CRYPTO_RK_SHA384},
	{RK_ALGO_SHA512,      0, CRYPTO_RK_SHA512},
	{RK_ALGO_SHA512_224,  0, CRYPTO_RK_SHA512_224},
	{RK_ALGO_SHA512_256,  0, CRYPTO_RK_SHA512_256},

	{RK_ALGO_HMAC_MD5,    0, CRYPTO_RK_MD5_HMAC},
	{RK_ALGO_HMAC_SHA1,   0, CRYPTO_RK_SHA1_HMAC},
	{RK_ALGO_HMAC_SHA256, 0, CRYPTO_RK_SHA256_HMAC},
	{RK_ALGO_HMAC_SHA512, 0, CRYPTO_RK_SHA512_HMAC},
};

static uint32_t rk_get_config_type(uint32_t algo, uint32_t mode)
{
	if (algo > RK_ALGO_CIPHER_TOP && algo < RK_ALGO_CIPHER_BUTT) {
		if (mode == RK_CIPHER_MODE_CCM || mode == RK_CIPHER_MODE_GCM)
			return RK_CONFIG_TYPE_AE;

		return RK_CONFIG_TYPE_CIPHER;
	}

	if (algo > RK_ALGO_HASH_TOP && algo < RK_ALGO_HASH_BUTT)
		return RK_CONFIG_TYPE_HASH;

	return RK_CONFIG_TYPE_CIPHER;
}

static uint32_t rk_get_hash_len(uint32_t algo)
{
	switch (algo) {
	case RK_ALGO_MD5:
	case RK_ALGO_HMAC_MD5:
		return MD5_HASH_SIZE;
	case RK_ALGO_SHA1:
	case RK_ALGO_HMAC_SHA1:
		return SHA1_HASH_SIZE;
	case RK_ALGO_SHA224:
	case RK_ALGO_SHA512_224:
		return SHA224_HASH_SIZE;
	case RK_ALGO_SHA256:
	case RK_ALGO_SHA512_256:
	case RK_ALGO_HMAC_SHA256:
		return SHA256_HASH_SIZE;
	case RK_ALGO_SHA384:
		return SHA384_HASH_SIZE;
	case RK_ALGO_SHA512:
	case RK_ALGO_HMAC_SHA512:
		return SHA512_HASH_SIZE;
	case RK_ALGO_SM3:
	case RK_ALGO_HMAC_SM3:
		return SM3_HASH_SIZE;
	default:
		return 0;
	}
}

static RK_RES rk_get_crypto_id(uint32_t algo, uint32_t mode, uint32_t *crypto_id)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(algo_map_tbl); i++) {
		if (algo == algo_map_tbl[i].algo && mode == algo_map_tbl[i].mode) {
			*crypto_id = algo_map_tbl[i].crypto_id;
			return RK_ALG_SUCCESS;
		}
	}

	return RK_ALG_ERR_GENERIC;
}

static RK_RES rk_add_sess_node(uint32_t sess_id, uint32_t config_type, const void *config, void *priv)
{
	struct sess_id_node *node;

	node = malloc(sizeof(*node));
	if (!node) {
		D_TRACE("malloc node error!\n");
		return RK_ALG_ERR_OUT_OF_MEMORY;
	}

	switch (config_type) {
	case RK_CONFIG_TYPE_CIPHER:
		memcpy(&node->config.cipher, config, sizeof(node->config.cipher));
		break;
	case RK_CONFIG_TYPE_AE:
		memcpy(&node->config.ae, config, sizeof(node->config.ae));
		break;
	case RK_CONFIG_TYPE_HASH:
		memcpy(&node->config.hash, config, sizeof(node->config.hash));
		break;
	default:
		return RK_ALG_ERR_PARAMETER;
	}

	node->sess_id = sess_id;
	node->priv    = priv;

	pthread_mutex_lock(&sess_mutex);

	list_add_tail(&node->list, &sess_id_list);

	pthread_mutex_unlock(&sess_mutex);

	return RK_ALG_SUCCESS;
}

static struct sess_id_node *rk_get_sess_node(uint32_t sess_id)
{
	struct list_head *pos = NULL;
	struct sess_id_node *node = NULL;

	pthread_mutex_lock(&sess_mutex);

	list_for_each(pos, &sess_id_list) {
		node = list_entry(pos, struct sess_id_node, list);

		if (node->sess_id == sess_id) {
			goto exit;
		}
	}

exit:
	pthread_mutex_unlock(&sess_mutex);
	return node;
}

static void *rk_get_sess_config(uint32_t sess_id)
{
	struct sess_id_node *node;

	node = rk_get_sess_node(sess_id);

	return node ? &node->config : NULL;
}

static RK_RES rk_del_sess_node(uint32_t sess_id)
{
	struct list_head *pos, *n = NULL;
	struct sess_id_node *node;
	RK_RES res = RK_ALG_ERR_GENERIC;

	pthread_mutex_lock(&sess_mutex);

	list_for_each_safe(pos, n, &sess_id_list) {
		node = list_entry(pos, struct sess_id_node, list);

		if (node->sess_id == sess_id) {
			list_del(pos);
			free(node);
			res = RK_ALG_SUCCESS;
			goto exit;
		}
	}

exit:
	pthread_mutex_unlock(&sess_mutex);
	return res;
}

RK_RES rk_crypto_init(void)
{
	if (cryptodev_fd < 0) {
		rk_crypto_mem_init();

		INIT_LIST_HEAD(&sess_id_list);

		/* Open the crypto device */
		cryptodev_fd = open("/dev/crypto", O_RDWR, 0);
		if (cryptodev_fd < 0) {
			D_TRACE("open cryptodev error!\n");
			return RK_ALG_ERR_GENERIC;
		}

		/* Set close-on-exec (not really neede here) */
		if (fcntl(cryptodev_fd, F_SETFD, 1) == -1) {
			D_TRACE("cryptodev F_SETFD error!\n");
			goto error;
		}
	}

	cryptodev_refcnt++;

	return RK_ALG_SUCCESS;
error:
	if (cryptodev_fd >= 0)
		close(cryptodev_fd);

	return RK_ALG_ERR_GENERIC;
}

void rk_crypto_deinit(void)
{
	if (--cryptodev_refcnt == 0 && cryptodev_fd >= 0) {
		/* free sess_id list */
		struct sess_id_node *node;
		struct list_head *pos, *n;

		pthread_mutex_lock(&sess_mutex);

		list_for_each_safe(pos, n, &sess_id_list) {
			node = list_entry(pos, struct sess_id_node, list);
			list_del(pos);
			free(node);
		}

		pthread_mutex_unlock(&sess_mutex);

		close(cryptodev_fd);
		cryptodev_fd = -1;
		rk_crypto_mem_deinit();

	}

	if (cryptodev_refcnt < 0)
		cryptodev_refcnt = 0;
}

RK_RES rk_cipher_init(const rk_cipher_config *config, rk_handle *handle)
{
	RK_RES res;
	struct session_op sess;
	uint32_t crypto_id = 0;

	if (!config || !handle)
		return RK_ALG_ERR_PARAMETER;

	memset(&sess, 0, sizeof(sess));

	res = rk_get_crypto_id(config->algo, config->mode, &crypto_id);
	if (res) {
		D_TRACE("rk_get_crypto_id error!\n");
		goto exit;
	}

	sess.cipher = crypto_id;
	sess.key    = (__u8 *)config->key;
	sess.keylen = config->key_len;

	if (ioctl(cryptodev_fd, CIOCGSESSION, &sess)) {
		D_TRACE("CIOCGSESSION error!\n");
		res = RK_ALG_ERR_GENERIC;
		goto exit;
	}

	rk_add_sess_node(sess.ses, rk_get_config_type(config->algo, config->mode), config, NULL);

	*handle = sess.ses;
exit:
	return res;
}

RK_RES rk_cipher_crypt(rk_handle handle, int in_fd, uint32_t in_len,
		       int out_fd, uint32_t *out_len)
{
	struct crypt_fd_op cryp;
	rk_cipher_config *cipher_cfg;

	if (IS_CRYPTO_INVALID())
		return RK_ALG_ERR_PARAMETER;

	cipher_cfg = rk_get_sess_config(handle);
	if (!cipher_cfg) {
		D_TRACE("rk_get_sess_config error!\n");
		return RK_ALG_ERR_STATE;
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses    = handle;
	cryp.len    = in_len;
	cryp.src_fd = in_fd;
	cryp.dst_fd = out_fd;
	cryp.iv     = (void *)cipher_cfg->iv;
	cryp.op     = (cipher_cfg->operation == RK_OP_CIPHER_ENC) ? COP_ENCRYPT : COP_DECRYPT;

	if (ioctl(cryptodev_fd, RIOCCRYPT_FD, &cryp)) {
		D_TRACE("RIOCCRYPT_FD error!\n");
		return RK_ALG_ERR_GENERIC;
	}

	*out_len = in_len;

	return RK_ALG_SUCCESS;
}

RK_RES rk_cipher_crypt_virt(rk_handle handle, const uint8_t *in, uint32_t in_len,
			    uint8_t *out, uint32_t *out_len)
{
	struct crypt_op cryp;
	rk_cipher_config *cipher_cfg;

	if (IS_CRYPTO_INVALID())
		return RK_ALG_ERR_PARAMETER;

	cipher_cfg = rk_get_sess_config(handle);
	if (!cipher_cfg) {
		D_TRACE("rk_get_sess_config error!\n");
		return RK_ALG_ERR_STATE;
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses = handle;
	cryp.len = in_len;
	cryp.src = (void *)in;
	cryp.dst = out;
	cryp.iv  = (void *)cipher_cfg->iv;
	cryp.op  = (cipher_cfg->operation == RK_OP_CIPHER_ENC) ? COP_ENCRYPT : COP_DECRYPT;

	if (ioctl(cryptodev_fd, CIOCCRYPT, &cryp)) {
		D_TRACE("CIOCCRYPT error!\n");
		return RK_ALG_ERR_GENERIC;
	}

	*out_len = in_len;

	return RK_ALG_SUCCESS;
}

RK_RES rk_cipher_final(rk_handle handle)
{
	if (IS_CRYPTO_INVALID())
		return RK_ALG_ERR_PARAMETER;

	if (ioctl(cryptodev_fd, CIOCFSESSION, &handle)) {
		D_TRACE("CIOCFSESSION error!");
		return RK_ALG_ERR_GENERIC;
	}

	return rk_del_sess_node(handle);
}

RK_RES rk_hash_init(const rk_hash_config *config, rk_handle *handle)
{
	RK_RES res;
	struct session_op sess;
	uint32_t crypto_id = 0;
	struct hash_result *result = NULL;

	if (IS_CRYPTO_INVALID())
		return RK_ALG_ERR_PARAMETER;

	if (!config || !handle)
		return RK_ALG_ERR_PARAMETER;

	result = malloc(sizeof(*result));
	if (!result) {
		D_TRACE("malloc result buffer error!\n");
		res = RK_ALG_ERR_OUT_OF_MEMORY;
		goto exit;
	}

	memset(result, 0x00, sizeof(*result));
	memset(&sess, 0, sizeof(sess));

	res = rk_get_crypto_id(config->algo, 0, &crypto_id);
	if (res) {
		D_TRACE("rk_get_crypto_id error!\n");
		goto exit;
	}

	sess.mac = crypto_id;
	if (config->key && config->key_len) {
		sess.mackey    = config->key;
		sess.mackeylen = config->key_len;
	}

	if (ioctl(cryptodev_fd, CIOCGSESSION, &sess)) {
		D_TRACE("CIOCGSESSION error!\n");
		res = RK_ALG_ERR_GENERIC;
		goto exit;
	}

	rk_add_sess_node(sess.ses, rk_get_config_type(config->algo, 0), config, result);

	*handle = sess.ses;
exit:
	return res;
}

RK_RES rk_hash_update(rk_handle handle, int data_fd, uint32_t data_len, bool is_last)
{
	struct crypt_fd_op cryp;
	struct sess_id_node *node;
	rk_hash_config *hash_cfg;
	struct hash_result *result;

	if (IS_CRYPTO_INVALID())
		return RK_ALG_ERR_PARAMETER;

	node = rk_get_sess_node(handle);
	if (!node) {
		D_TRACE("handle[%u] rk_get_sess_node  error!\n", handle);
		return RK_ALG_ERR_OUT_OF_MEMORY;
	}

	result = node->priv;
	hash_cfg = &node->config.hash;

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses    = handle;
	cryp.len    = data_len;
	cryp.src_fd = data_fd;
	cryp.mac    = result->hash;
	cryp.flags  = is_last ? COP_FLAG_FINAL : COP_FLAG_UPDATE;

	if (ioctl(cryptodev_fd, RIOCCRYPT_FD, &cryp)) {
		D_TRACE("RIOCCRYPT_FD error!\n");
		return RK_ALG_ERR_GENERIC;
	}

	if (is_last)
		result->len = rk_get_hash_len(hash_cfg->algo);

	return RK_ALG_SUCCESS;
}

RK_RES rk_hash_update_virt(rk_handle handle, const uint8_t *data, uint32_t data_len, bool is_last)
{
	struct crypt_op cryp;
	struct sess_id_node *node;
	rk_hash_config *hash_cfg;
	struct hash_result *result;

	if (IS_CRYPTO_INVALID())
		return RK_ALG_ERR_PARAMETER;

	node = rk_get_sess_node(handle);
	if (!node) {
		D_TRACE("handle[%u] rk_get_sess_node  error!\n", handle);
		return RK_ALG_ERR_OUT_OF_MEMORY;
	}

	result = node->priv;
	hash_cfg = &node->config.hash;

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses   = handle;
	cryp.len   = data_len;
	cryp.src   = (void *)data;
	cryp.mac   = result->hash;
	cryp.flags = is_last ? COP_FLAG_FINAL : COP_FLAG_UPDATE;

	if (ioctl(cryptodev_fd, CIOCCRYPT, &cryp)) {
		D_TRACE("CIOCCRYPT error!\n");
		return RK_ALG_ERR_GENERIC;
	}

	if (is_last)
		result->len = rk_get_hash_len(hash_cfg->algo);

	return RK_ALG_SUCCESS;
}

RK_RES rk_hash_final(rk_handle handle, uint8_t *hash, uint32_t *hash_len)
{
	RK_RES res = RK_ALG_SUCCESS;
	struct sess_id_node *node;
	struct hash_result *result;

	if (IS_CRYPTO_INVALID())
		return RK_ALG_ERR_PARAMETER;

	node = rk_get_sess_node(handle);
	if (!node) {
		D_TRACE("handle[%u] rk_get_sess_node  error!\n", handle);
		return RK_ALG_ERR_OUT_OF_MEMORY;
	}

	result = node->priv;

	D_TRACE("xxx debug");

	if (hash) {
		D_TRACE("xxx debug");
		if (result->len == 0) {
			D_TRACE("xxx debug");
			res = RK_ALG_ERR_GENERIC;
			goto exit;
		}

		memcpy(hash, result->hash, result->len);

		if (hash_len)
			*hash_len = result->len;
		D_TRACE("xxx debug");
	}
exit:
	if (ioctl(cryptodev_fd, CIOCFSESSION, &handle)) {
		D_TRACE("CIOCFSESSION error!");
		res = RK_ALG_ERR_GENERIC;
	}

	if (node->priv)
		free(node->priv);

	rk_del_sess_node(handle);

	return res;
}


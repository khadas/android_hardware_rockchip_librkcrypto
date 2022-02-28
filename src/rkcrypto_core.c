/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/ioctl.h>

#include "rk_cryptodev.h"
#include "rkcrypto_mem.h"
#include "rkcrypto_core.h"
#include "rkcrypto_core_int.h"
#include "rkcrypto_trace.h"
#include "rk_list.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
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

#define CHECK_CRYPTO_INITED()	do {\
					if (cryptodev_fd < 0) {\
						E_TRACE("RK_CRYPTO is uninitialized\n");\
						return RK_CRYPTO_ERR_UNINITED;\
					}\
				} while (0)

static const struct {
	const uint32_t kernel_code;
	const uint32_t rk_crypto_code;
} kernel_crypto_code[] = {
	{0,			RK_CRYPTO_SUCCESS},
	{-EINVAL,		RK_CRYPTO_ERR_PARAMETER},
	{-ENOENT,		RK_CRYPTO_ERR_NOT_SUPPORTED},
	{-ENOMEM,		RK_CRYPTO_ERR_OUT_OF_MEMORY},
	{-EACCES,		RK_CRYPTO_ERR_ACCESS_DENIED},
	{-EBUSY,		RK_CRYPTO_ERR_BUSY},
	{-ETIMEDOUT,		RK_CRYPTO_ERR_TIMEOUT},
};

static RK_RES kernel_to_crypto_code(uint32_t tee_code)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(kernel_crypto_code); i++) {
		if (tee_code == kernel_crypto_code[i].kernel_code)
			return kernel_crypto_code[i].rk_crypto_code;
	}

	/* Others convert to RK_CRYPTO_ERR_GENERIC. */
	return RK_CRYPTO_ERR_GENERIC;
}

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

	{RK_ALGO_AES,  RK_CIPHER_MODE_ECB,     CRYPTO_RK_AES_ECB},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CBC,     CRYPTO_RK_AES_CBC},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CFB,     CRYPTO_RK_AES_CFB},
	{RK_ALGO_AES,  RK_CIPHER_MODE_OFB,     CRYPTO_RK_AES_OFB},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CTS,     CRYPTO_RK_AES_CTS},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CTR,     CRYPTO_RK_AES_CTR},
	{RK_ALGO_AES,  RK_CIPHER_MODE_XTS,     CRYPTO_RK_AES_XTS},
	{RK_ALGO_AES,  RK_CIPHER_MODE_CCM,     CRYPTO_RK_AES_CCM},
	{RK_ALGO_AES,  RK_CIPHER_MODE_GCM,     CRYPTO_RK_AES_GCM},

	{RK_ALGO_MD5,         0, CRYPTO_RK_MD5},
	{RK_ALGO_SHA1,        0, CRYPTO_RK_SHA1},
	{RK_ALGO_SHA224,      0, CRYPTO_RK_SHA224},
	{RK_ALGO_SHA256,      0, CRYPTO_RK_SHA256},
	{RK_ALGO_SHA384,      0, CRYPTO_RK_SHA384},
	{RK_ALGO_SHA512,      0, CRYPTO_RK_SHA512},
	{RK_ALGO_SHA512_224,  0, CRYPTO_RK_SHA512_224},
	{RK_ALGO_SHA512_256,  0, CRYPTO_RK_SHA512_256},
	{RK_ALGO_SM3,         0, CRYPTO_RK_SM3},

	{RK_ALGO_HMAC_MD5,    0, CRYPTO_RK_MD5_HMAC},
	{RK_ALGO_HMAC_SHA1,   0, CRYPTO_RK_SHA1_HMAC},
	{RK_ALGO_HMAC_SHA256, 0, CRYPTO_RK_SHA256_HMAC},
	{RK_ALGO_HMAC_SHA512, 0, CRYPTO_RK_SHA512_HMAC},
	{RK_ALGO_HMAC_SM3,    0, CRYPTO_RK_SM3_HMAC},
	{RK_ALGO_CMAC_SM4,    0, CRYPTO_RK_SM4_CMAC},
	{RK_ALGO_CBCMAC_SM4,  0, CRYPTO_RK_SM4_CBC_MAC},
	{RK_ALGO_CMAC_AES,    0, CRYPTO_RK_AES_CMAC},
	{RK_ALGO_CBCMAC_AES,  0, CRYPTO_RK_AES_CBC_MAC},
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

static RK_RES xioctl(int fd, unsigned long int request, void *arg)
{
	return ioctl(fd, request, arg) ? kernel_to_crypto_code(-errno) : RK_CRYPTO_SUCCESS;
}

static RK_RES rk_get_crypto_id(uint32_t algo, uint32_t mode, uint32_t *crypto_id)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(algo_map_tbl); i++) {
		if (algo == algo_map_tbl[i].algo && mode == algo_map_tbl[i].mode) {
			*crypto_id = algo_map_tbl[i].crypto_id;
			return RK_CRYPTO_SUCCESS;
		}
	}

	return RK_CRYPTO_ERR_GENERIC;
}

static RK_RES rk_add_sess_node(uint32_t sess_id, uint32_t config_type, const void *config, void *priv)
{
	struct sess_id_node *node;

	node = malloc(sizeof(*node));
	if (!node) {
		E_TRACE("malloc node error!\n");
		return RK_CRYPTO_ERR_OUT_OF_MEMORY;
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
		return RK_CRYPTO_ERR_PARAMETER;
	}

	node->sess_id = sess_id;
	node->priv    = priv;

	pthread_mutex_lock(&sess_mutex);

	list_add_tail(&node->list, &sess_id_list);

	pthread_mutex_unlock(&sess_mutex);

	return RK_CRYPTO_SUCCESS;
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
	RK_RES res = RK_CRYPTO_ERR_GENERIC;

	pthread_mutex_lock(&sess_mutex);

	list_for_each_safe(pos, n, &sess_id_list) {
		node = list_entry(pos, struct sess_id_node, list);

		if (node->sess_id == sess_id) {
			list_del(pos);
			free(node);
			res = RK_CRYPTO_SUCCESS;
			goto exit;
		}
	}

exit:
	pthread_mutex_unlock(&sess_mutex);
	return res;
}

static RK_RES rk_update_user_iv(const rk_cipher_config *cfg)
{
	struct sess_id_node *node;

	node = container_of(cfg, struct sess_id_node, config.cipher);
	if (!node)
		return RK_CRYPTO_ERR_STATE;

	if (node->priv)
		memcpy(node->priv, cfg->iv, sizeof(cfg->iv));

	return RK_CRYPTO_SUCCESS;
}

RK_RES rk_crypto_init(void)
{
	I_TRACE("%s\n", RK_CRYPTO_API_FULL_VERSION);

	if (cryptodev_fd < 0) {
		rk_crypto_mem_init();

		INIT_LIST_HEAD(&sess_id_list);

		/* Open the crypto device */
		cryptodev_fd = open("/dev/crypto", O_RDWR, 0);
		if (cryptodev_fd < 0) {
			E_TRACE("open cryptodev error!\n");
			return kernel_to_crypto_code(-errno);
		}

		/* Set close-on-exec (not really neede here) */
		if (fcntl(cryptodev_fd, F_SETFD, 1) == -1) {
			E_TRACE("cryptodev F_SETFD error!\n");
			goto error;
		}
	}

	cryptodev_refcnt++;

	return RK_CRYPTO_SUCCESS;
error:
	if (cryptodev_fd >= 0)
		close(cryptodev_fd);

	return RK_CRYPTO_ERR_GENERIC;
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

	CHECK_CRYPTO_INITED();

	RK_CRYPTO_CHECK_PARAM(!config || !handle);

	memset(&sess, 0, sizeof(sess));

	res = rk_get_crypto_id(config->algo, config->mode, &crypto_id);
	if (res) {
		E_TRACE("rk_get_crypto_id error!\n");
		goto exit;
	}

	sess.cipher = crypto_id;
	sess.key    = (__u8 *)config->key;
	sess.keylen = config->key_len;

	res = xioctl(cryptodev_fd, CIOCGSESSION, &sess);
	if (res) {
		if (res != RK_CRYPTO_ERR_NOT_SUPPORTED)
			E_TRACE("CIOCGSESSION error %d!\n", errno);
		goto exit;
	}

	res = rk_add_sess_node(sess.ses, rk_get_config_type(config->algo, config->mode), config, (void *)config->iv);
	if (res == RK_CRYPTO_SUCCESS)
		*handle = sess.ses;
exit:
	return res;
}

RK_RES rk_cipher_crypt(rk_handle handle, int in_fd, int out_fd, uint32_t len)
{
	struct crypt_fd_op cryp;
	rk_cipher_config *cipher_cfg;
	RK_RES res = RK_CRYPTO_ERR_GENERIC;

	CHECK_CRYPTO_INITED();

	RK_CRYPTO_CHECK_PARAM(len == 0);

	cipher_cfg = rk_get_sess_config(handle);
	if (!cipher_cfg) {
		E_TRACE("rk_get_sess_config error!\n");
		return RK_CRYPTO_ERR_STATE;
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses    = handle;
	cryp.len    = len;
	cryp.src_fd = in_fd;
	cryp.dst_fd = out_fd;
	cryp.iv     = (void *)cipher_cfg->iv;
	cryp.op     = (cipher_cfg->operation == RK_OP_CIPHER_ENC) ? COP_ENCRYPT : COP_DECRYPT;
	cryp.flags  = COP_FLAG_WRITE_IV;

	res = xioctl(cryptodev_fd, RIOCCRYPT_FD, &cryp);
	if (res) {
		E_TRACE("RIOCCRYPT_FD error!\n");
		goto exit;
	}

	res = rk_update_user_iv(cipher_cfg);
	if (res) {
		E_TRACE("rk_update_user_iv error!\n");
		goto exit;
	}

exit:
	return res;
}

RK_RES rk_cipher_crypt_virt(rk_handle handle, const uint8_t *in, uint8_t *out, uint32_t len)
{
	struct crypt_op cryp;
	rk_cipher_config *cipher_cfg;
	RK_RES res = RK_CRYPTO_ERR_GENERIC;

	CHECK_CRYPTO_INITED();

	RK_CRYPTO_CHECK_PARAM(!in || !out || len == 0);

	cipher_cfg = rk_get_sess_config(handle);
	if (!cipher_cfg) {
		E_TRACE("rk_get_sess_config error!\n");
		return RK_CRYPTO_ERR_STATE;
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses   = handle;
	cryp.len   = len;
	cryp.src   = (void *)in;
	cryp.dst   = out;
	cryp.iv    = (void *)cipher_cfg->iv;
	cryp.op    = (cipher_cfg->operation == RK_OP_CIPHER_ENC) ? COP_ENCRYPT : COP_DECRYPT;
	cryp.flags = COP_FLAG_WRITE_IV;

	res = xioctl(cryptodev_fd, CIOCCRYPT, &cryp);
	if (res) {
		E_TRACE("CIOCCRYPT error!\n");
		goto exit;
	}

	res = rk_update_user_iv(cipher_cfg);
	if (res) {
		E_TRACE("rk_update_user_iv error!\n");
		goto exit;
	}

exit:
	return res;
}

RK_RES rk_cipher_final(rk_handle handle)
{
	RK_RES res;

	CHECK_CRYPTO_INITED();

	res = xioctl(cryptodev_fd, CIOCFSESSION, &handle);
	if (res) {
		E_TRACE("CIOCFSESSION error!");
		return res;
	}

	return rk_del_sess_node(handle);
}

RK_RES rk_hash_init(const rk_hash_config *config, rk_handle *handle)
{
	RK_RES res;
	struct session_op sess;
	uint32_t crypto_id = 0;

	CHECK_CRYPTO_INITED();

	RK_CRYPTO_CHECK_PARAM(!config || !handle);

	memset(&sess, 0, sizeof(sess));

	res = rk_get_crypto_id(config->algo, 0, &crypto_id);
	if (res) {
		E_TRACE("rk_get_crypto_id error!\n");
		goto exit;
	}

	sess.mac = crypto_id;
	if (config->key && config->key_len) {
		sess.mackey    = config->key;
		sess.mackeylen = config->key_len;
	}

	res = xioctl(cryptodev_fd, CIOCGSESSION, &sess);
	if (res) {
		if (res != RK_CRYPTO_ERR_NOT_SUPPORTED)
			E_TRACE("CIOCGSESSION error %d!\n", errno);
		goto exit;
	}

	rk_add_sess_node(sess.ses, rk_get_config_type(config->algo, 0), config, NULL);

	*handle = sess.ses;
exit:
	return res;
}

RK_RES rk_hash_update(rk_handle handle, int data_fd, uint32_t data_len)
{
	struct crypt_fd_op cryp;
	RK_RES res;

	CHECK_CRYPTO_INITED();

	RK_CRYPTO_CHECK_PARAM(data_len == 0);

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses    = handle;
	cryp.len    = data_len;
	cryp.src_fd = data_fd;
	cryp.mac    = NULL;
	cryp.flags  = COP_FLAG_UPDATE;

	res = xioctl(cryptodev_fd, RIOCCRYPT_FD, &cryp);
	if (res) {
		E_TRACE("RIOCCRYPT_FD error!\n");
		return res;
	}

	return RK_CRYPTO_SUCCESS;
}

RK_RES rk_hash_update_virt(rk_handle handle, const uint8_t *data, uint32_t data_len)
{
	struct crypt_op cryp;
	RK_RES res;

	CHECK_CRYPTO_INITED();

	RK_CRYPTO_CHECK_PARAM(!data || data_len == 0);

	memset(&cryp, 0, sizeof(cryp));

	cryp.ses   = handle;
	cryp.len   = data_len;
	cryp.src   = (void *)data;
	cryp.mac   = NULL;
	cryp.flags = COP_FLAG_UPDATE;

	res = xioctl(cryptodev_fd, CIOCCRYPT, &cryp);
	if (res) {
		E_TRACE("CIOCCRYPT error!\n");
		return res;
	}

	return RK_CRYPTO_SUCCESS;
}

RK_RES rk_hash_final(rk_handle handle, uint8_t *hash)
{
	RK_RES res = RK_CRYPTO_SUCCESS;
	struct crypt_op cryp;
	rk_hash_config *hash_cfg;
	uint8_t hash_tmp[SHA512_HASH_SIZE];
	uint32_t hash_tmp_len;

	CHECK_CRYPTO_INITED();

	hash_cfg = rk_get_sess_config(handle);
	if (!hash_cfg) {
		E_TRACE("handle[%u] rk_get_sess_config  error!\n", handle);
		return RK_CRYPTO_ERR_STATE;
	}

	hash_tmp_len = rk_get_hash_len(hash_cfg->algo);

	/* final update 0 Byte */
	memset(&cryp, 0, sizeof(cryp));

	cryp.ses   = handle;
	cryp.mac   = hash_tmp;
	cryp.flags = COP_FLAG_FINAL;

	res = xioctl(cryptodev_fd, CIOCCRYPT, &cryp);
	if (res) {
		E_TRACE("CIOCCRYPT error!\n");
		goto exit;
	}

	if (hash)
		memcpy(hash, hash_tmp, hash_tmp_len);

exit:
	res = xioctl(cryptodev_fd, CIOCFSESSION, &handle);
	if (res)
		E_TRACE("CIOCFSESSION error!");

	rk_del_sess_node(handle);

	return res;
}

RK_RES rk_crypto_fd_ioctl(uint32_t request, struct crypt_fd_map_op *mop)
{
	RK_RES res;

	CHECK_CRYPTO_INITED();

	RK_CRYPTO_CHECK_PARAM(request != RIOCCRYPT_FD_MAP &&
			   request != RIOCCRYPT_FD_UNMAP);
	RK_CRYPTO_CHECK_PARAM(!mop);

	res = xioctl(cryptodev_fd, request, mop);
	if (res) {
		E_TRACE("ioctl cryptodev_fd failed!");
		return res;
	}

	return RK_CRYPTO_SUCCESS;
}

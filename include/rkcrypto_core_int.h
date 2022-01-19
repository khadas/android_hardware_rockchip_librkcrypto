/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#ifndef _RKCRYPTO_CORE_INT_H_
#define _RKCRYPTO_CORE_INT_H_

#include <sys/ioctl.h>
#include "rkcrypto_common.h"
#include "rk_cryptodev.h"

RK_RES rk_crypto_fd_ioctl(uint32_t request, struct crypt_fd_map_op *mop);

#endif /* _RKCRYPTO_CORE_INT_H_ */

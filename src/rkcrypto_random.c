/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "rkcrypto_random.h"
#include "rkcrypto_trace.h"

RK_RES rk_get_random(uint32_t len, uint8_t *data)
{
	RK_RES res = RK_CRYPTO_SUCCESS;
	int hwrng_fd = -1;
	int read_len = 0;

	hwrng_fd = open("/dev/hwrng", O_RDONLY, 0);
	if (hwrng_fd < 0) {
		E_TRACE("open /dev/hwrng error!");
		return RK_CRYPTO_ERR_GENERIC;
	}

	read_len = read(hwrng_fd, data, len);
	if (read_len != len) {
		E_TRACE("read /dev/hwrng error!");
		res = RK_CRYPTO_ERR_GENERIC;
	}

	close(hwrng_fd);

	return res;
}

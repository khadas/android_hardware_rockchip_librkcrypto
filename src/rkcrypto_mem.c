/*
 * Copyright (c) 2022 Rockchip Electronics Co. Ltd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <xf86drm.h>
#include <rockchip_drm.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#include "rkcrypto_mem.h"
#include "rkcrypto_trace.h"
#include "rk_list.h"

#define DRM_MODULE_NAME "rockchip"
#define DRM_CARD_PATH "/dev/dri/card0"

#define IS_DRM_INVALID()	(drm_fd < 0)

struct mem_pool_node {
	rk_crypto_mem		mem;
	uint32_t		handle;
	uint32_t		flags;
	struct list_head	list;
};

static int drm_fd = -1;
static struct list_head mem_pool_list;
pthread_mutex_t drm_mutex = PTHREAD_MUTEX_INITIALIZER;
static int mem_init_cnt;

static struct mem_pool_node *crypto_alloc_node(uint32_t size)
{
	int ret = -1;
	struct mem_pool_node *node = NULL;
	struct drm_rockchip_gem_create req = {
		.size = size,
		.flags = 1,
	};
	struct drm_rockchip_gem_map_off map_req;

	node = malloc(sizeof(*node));
	if (!node)
		return NULL;

	memset(node, 0x00, sizeof(*node));
	memset(&map_req, 0x00, sizeof(map_req));

	ret = drmIoctl(drm_fd, DRM_IOCTL_ROCKCHIP_GEM_CREATE, &req);
	if (ret) {
		free(node);
		return NULL;
	}

	ret = drmPrimeHandleToFD(drm_fd, req.handle, 0, &node->mem.dma_fd);
	if (ret) {
		E_TRACE("failed to get dma fd.\n");
		goto error;
	}

	map_req.handle = req.handle;
	ret = drmIoctl(drm_fd, DRM_IOCTL_ROCKCHIP_GEM_MAP_OFFSET, &map_req);
	if (ret) {
		E_TRACE("failed to ioctl gem map offset.");
		goto error;
	}

#ifdef __ANDROID__
	node->mem.vaddr = mmap64(0, req.size, PROT_READ | PROT_WRITE, MAP_SHARED,
				 drm_fd, map_req.offset);
#else
	node->mem.vaddr = mmap(0, req.size, PROT_READ | PROT_WRITE, MAP_SHARED,
				 drm_fd, map_req.offset);
#endif
	if (node->mem.vaddr == MAP_FAILED) {
		E_TRACE("failed to mmap buffer.error = %d\n", errno);
		ret = -1;
		goto error;
	}

	node->handle   = req.handle;
	node->flags    = req.flags;
	node->mem.size = req.size;

	return node;
error:
	drmIoctl(drm_fd, DRM_IOCTL_GEM_CLOSE, &req);

	if (node)
		free(node);

	return NULL;
}

static void crypto_free_node(struct mem_pool_node *node)
{
	struct drm_gem_close req;

	if (!node || node->mem.size == 0)
		return;

	memset(&req, 0x00, sizeof(req));

	req.handle = node->handle;

	if (node->mem.vaddr)
		munmap(node->mem.vaddr, node->mem.size);

	if (node->mem.dma_fd >= 0)
		close(node->mem.dma_fd);

	drmIoctl(drm_fd, DRM_IOCTL_GEM_CLOSE, &req);

	free(node);
}

int rk_crypto_mem_init(void)
{
	int ret = -1;

	if (mem_init_cnt > 0) {
		ret = 0;
		goto exit;
	}

	pthread_mutex_lock(&drm_mutex);

	INIT_LIST_HEAD(&mem_pool_list);

	drm_fd = open(DRM_CARD_PATH, O_RDWR);
	if (drm_fd < 0) {
		E_TRACE("failed to open drm !\n");
		goto exit;
	}

	mem_init_cnt++;

	ret = 0;
exit:
	pthread_mutex_unlock(&drm_mutex);

	return ret;
}

void rk_crypto_mem_deinit(void)
{
	/* free list */
	struct mem_pool_node *node;
	struct list_head *pos, *n;

	pthread_mutex_lock(&drm_mutex);

	mem_init_cnt--;
	if (mem_init_cnt > 0)
		goto exit;

	if (IS_DRM_INVALID())
		goto exit;

	list_for_each_safe(pos, n, &mem_pool_list) {
		node = list_entry(pos, struct mem_pool_node, list);
		list_del(pos);
		crypto_free_node(node);
	}

	if (drm_fd >= 0)
		close(drm_fd);
exit:
	pthread_mutex_unlock(&drm_mutex);
}

rk_crypto_mem *rk_crypto_mem_alloc(size_t size)
{
	struct mem_pool_node *node;

	pthread_mutex_lock(&drm_mutex);

	if (IS_DRM_INVALID())
		goto error;

	node = crypto_alloc_node(size);
	if (!node)
		goto error;

	list_add_tail(&node->list, &mem_pool_list);

	pthread_mutex_unlock(&drm_mutex);

	return &node->mem;
error:
	pthread_mutex_unlock(&drm_mutex);

	return NULL;
}

void rk_crypto_mem_free(rk_crypto_mem *memory)
{
	struct mem_pool_node *node;
	struct list_head *pos, *n;

	pthread_mutex_lock(&drm_mutex);

	if (IS_DRM_INVALID())
		goto exit;

	if (!memory)
		goto exit;

	list_for_each_safe(pos, n, &mem_pool_list) {
		node = list_entry(pos, struct mem_pool_node, list);

		if (&node->mem == memory) {
			list_del(pos);
			crypto_free_node(node);
			goto exit;
		}
	}

exit:
	pthread_mutex_unlock(&drm_mutex);
}

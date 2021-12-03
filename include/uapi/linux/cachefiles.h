#ifndef _LINUX_CACHEFILES_H
#define _LINUX_CACHEFILES_H

#include <linux/limits.h>

struct cachefiles_req_in {
	uint64_t id;
	uint64_t off;
	uint64_t len;
	char path[NAME_MAX];
};

#endif

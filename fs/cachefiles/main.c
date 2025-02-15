// SPDX-License-Identifier: GPL-2.0-or-later
/* Network filesystem caching backend to use cache files on a premounted
 * filesystem
 *
 * Copyright (C) 2021 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/statfs.h>
#include <linux/sysctl.h>
#include <linux/miscdevice.h>
#include <linux/netfs.h>
#include <trace/events/netfs.h>
#define CREATE_TRACE_POINTS
#include "internal.h"

unsigned cachefiles_debug;
module_param_named(debug, cachefiles_debug, uint, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(cachefiles_debug, "CacheFiles debugging mask");

MODULE_DESCRIPTION("Mounted-filesystem based cache");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

struct kmem_cache *cachefiles_object_jar;

static struct miscdevice cachefiles_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "cachefiles",
	.fops	= &cachefiles_daemon_fops,
};

#ifdef CONFIG_CACHEFILES_ONDEMAND
static struct miscdevice cachefiles_ondemand_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "cachefiles_ondemand",
	.fops	= &cachefiles_ondemand_fops,
};

static inline int cachefiles_init_ondemand(void)
{
	return misc_register(&cachefiles_ondemand_dev);
}

static inline void cachefiles_exit_ondemand(void)
{
	misc_deregister(&cachefiles_ondemand_dev);
}
#else
static inline int cachefiles_init_ondemand(void) { return 0; }
static inline void cachefiles_exit_ondemand(void) {}
#endif

/*
 * initialise the fs caching module
 */
static int __init cachefiles_init(void)
{
	int ret;

	ret = cachefiles_register_error_injection();
	if (ret < 0)
		goto error_einj;
	ret = misc_register(&cachefiles_dev);
	if (ret < 0)
		goto error_dev;
	ret = cachefiles_init_ondemand();
	if (ret < 0)
		goto error_ondemand_dev;

	/* create an object jar */
	ret = -ENOMEM;
	cachefiles_object_jar =
		kmem_cache_create("cachefiles_object_jar",
				  sizeof(struct cachefiles_object),
				  0, SLAB_HWCACHE_ALIGN, NULL);
	if (!cachefiles_object_jar) {
		pr_notice("Failed to allocate an object jar\n");
		goto error_object_jar;
	}

	pr_info("Loaded\n");
	return 0;

error_object_jar:
	cachefiles_exit_ondemand();
error_ondemand_dev:
	misc_deregister(&cachefiles_dev);
error_dev:
	cachefiles_unregister_error_injection();
error_einj:
	pr_err("failed to register: %d\n", ret);
	return ret;
}

fs_initcall(cachefiles_init);

/*
 * clean up on module removal
 */
static void __exit cachefiles_exit(void)
{
	pr_info("Unloading\n");

	kmem_cache_destroy(cachefiles_object_jar);
	cachefiles_exit_ondemand();
	misc_deregister(&cachefiles_dev);
	cachefiles_unregister_error_injection();
}

module_exit(cachefiles_exit);

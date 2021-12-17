// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021, Alibaba Cloud
 */
#include "internal.h"

static struct fscache_volume *volume;

static int erofs_blob_begin_cache_operation(struct netfs_read_request *rreq)
{
	return fscache_begin_read_operation(&rreq->cache_resources,
					    rreq->netfs_priv);
}

/* .cleanup() is needed if rreq->netfs_priv is non-NULL */
static void erofs_noop_cleanup(struct address_space *mapping, void *netfs_priv)
{
}

static const struct netfs_read_request_ops erofs_blob_req_ops = {
	.begin_cache_operation  = erofs_blob_begin_cache_operation,
	.cleanup		= erofs_noop_cleanup,
};

static int erofs_fscache_blob_readpage(struct file *data, struct page *page)
{
	struct folio *folio = page_folio(page);
	struct erofs_fscache_context *ctx =
		(struct erofs_fscache_context *)data;

	return netfs_readpage(NULL, folio, &erofs_blob_req_ops, ctx->cookie);
}

static const struct address_space_operations erofs_fscache_blob_aops = {
	.readpage = erofs_fscache_blob_readpage,
};

struct page *erofs_fscache_read_cache_page(struct erofs_fscache_context *ctx,
					   pgoff_t index)
{
	DBG_BUGON(!ctx->inode);
	return read_mapping_page(ctx->inode->i_mapping, index, ctx);
}

static int erofs_fscache_init_cookie(struct erofs_fscache_context *ctx,
				     char *path)
{
	struct fscache_cookie *cookie;

	/*
	 * @object_size shall be non-zero to avoid
	 * FSCACHE_COOKIE_NO_DATA_TO_READ.
	 */
	cookie = fscache_acquire_cookie(volume, 0,
					path, strlen(path),
					NULL, 0, -1);
	if (!cookie)
		return -EINVAL;

	fscache_use_cookie(cookie, false);
	ctx->cookie = cookie;
	return 0;
}

static inline
void erofs_fscache_cleanup_cookie(struct erofs_fscache_context *ctx)
{
	struct fscache_cookie *cookie = ctx->cookie;

	fscache_unuse_cookie(cookie, NULL, NULL);
	fscache_relinquish_cookie(cookie, false);
	ctx->cookie = NULL;
}

static int erofs_fscache_get_inode(struct erofs_fscache_context *ctx,
				   struct super_block *sb)
{
	struct inode *const inode = new_inode(sb);

	if (!inode)
		return -ENOMEM;

	set_nlink(inode, 1);
	inode->i_size = OFFSET_MAX;

	inode->i_mapping->a_ops = &erofs_fscache_blob_aops;
	mapping_set_gfp_mask(inode->i_mapping,
			GFP_NOFS | __GFP_HIGHMEM | __GFP_MOVABLE);
	ctx->inode = inode;
	return 0;
}

static inline
void erofs_fscache_put_inode(struct erofs_fscache_context *ctx)
{
	iput(ctx->inode);
	ctx->inode = NULL;
}

static int erofs_fscahce_init_ctx(struct erofs_fscache_context *ctx,
				  struct super_block *sb, char *path,
				  bool need_inode)
{
	int ret;

	ret = erofs_fscache_init_cookie(ctx, path);
	if (ret) {
		erofs_err(sb, "failed to init cookie");
		return ret;
	}

	if (need_inode) {
		ret = erofs_fscache_get_inode(ctx, sb);
		if (ret) {
			erofs_err(sb, "failed to get anonymous inode");
			erofs_fscache_cleanup_cookie(ctx);
			return ret;
		}
	}

	return 0;
}

static inline
void erofs_fscache_cleanup_ctx(struct erofs_fscache_context *ctx)
{
	erofs_fscache_cleanup_cookie(ctx);
	erofs_fscache_put_inode(ctx);
}

struct erofs_fscache_context *erofs_fscache_get_ctx(struct super_block *sb,
						char *path, bool need_inode)
{
	struct erofs_fscache_context *ctx;
	int ret;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ret = erofs_fscahce_init_ctx(ctx, sb, path, need_inode);
	if (ret) {
		kfree(ctx);
		return ERR_PTR(ret);
	}

	return ctx;
}

void erofs_fscache_put_ctx(struct erofs_fscache_context *ctx)
{
	if (!ctx)
		return;

	erofs_fscache_cleanup_ctx(ctx);
	kfree(ctx);
}

int __init erofs_init_fscache(void)
{
	volume = fscache_acquire_volume("erofs", NULL, NULL, 0);
	if (!volume)
		return -EINVAL;

	return 0;
}

void erofs_exit_fscache(void)
{
	fscache_relinquish_volume(volume, NULL, false);
}

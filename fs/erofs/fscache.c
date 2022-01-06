// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021, Alibaba Cloud
 */
#include "internal.h"

struct erofs_fscache_map {
	struct erofs_fscache_context *m_ctx;
	erofs_off_t m_pa, m_la, o_la;
	u64 m_llen;
};

struct erofs_fscache_priv {
	struct fscache_cookie *cookie;
	loff_t offset;
};

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

static int erofs_begin_cache_operation(struct netfs_read_request *rreq)
{
	struct erofs_fscache_priv *priv = rreq->netfs_priv;

	rreq->p_start = priv->offset;
	return fscache_begin_read_operation(&rreq->cache_resources,
					    priv->cookie);
}

static bool erofs_clamp_length(struct netfs_read_subrequest *subreq)
{
	/*
	 * For non-inline layout, rreq->i_size is actually the size of upper
	 * file in erofs rather than that of blob file. Thus when cache miss,
	 * subreq->len can be restricted to the upper file size, while we hope
	 * blob file can be filled in a EROFS_BLKSIZ granule.
	 */
	subreq->len = round_up(subreq->len, EROFS_BLKSIZ);
	return true;
}

static const struct netfs_read_request_ops erofs_req_ops = {
	.begin_cache_operation  = erofs_begin_cache_operation,
	.cleanup		= erofs_noop_cleanup,
	.clamp_length		= erofs_clamp_length,
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

static int erofs_fscache_readpage_noinline(struct page *page,
					   struct erofs_fscache_map *fsmap)
{
	struct folio *folio = page_folio(page);
	struct erofs_fscache_priv priv;

	/*
	 * 1) For FLAT_PLAIN layout, the output map.m_la shall be equal to o_la,
	 * and the output map.m_pa is exactly the physical address of o_la.
	 * 2) For CHUNK_BASED layout, the output map.m_la is rounded down to the
	 * nearest chunk boundary, and the output map.m_pa is actually the
	 * physical address of this chunk boundary. So we need to recalculate
	 * the actual physical address of o_la.
	 */
	priv.offset = fsmap->m_pa + fsmap->o_la - fsmap->m_la;
	priv.cookie = fsmap->m_ctx->cookie;

	return netfs_readpage(NULL, folio, &erofs_req_ops, &priv);
}

static int erofs_fscache_readpage_inline(struct page *page,
					 struct erofs_fscache_map *fsmap)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	erofs_blk_t blknr;
	size_t offset, len;
	void *src, *dst;

	/*
	 * For inline (tail packing) layout, the offset may be non-zero, while
	 * the offset can be calculated from corresponding physical address
	 * directly.
	 * Currently only flat layout supports inline (FLAT_INLINE), and the
	 * output map.m_pa is exactly the physical address of o_la in this case.
	 */
	offset = erofs_blkoff(fsmap->m_pa);
	blknr = erofs_blknr(fsmap->m_pa);
	len = fsmap->m_llen;

	src = erofs_read_metabuf(&buf, sb, blknr, EROFS_KMAP);
	if (IS_ERR(src)) {
		SetPageError(page);
		unlock_page(page);
		return PTR_ERR(src);
	}

	dst = kmap(page);
	memcpy(dst, src + offset, len);
	kunmap(page);

	erofs_put_metabuf(&buf);

	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}

static int erofs_fscache_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct erofs_inode *vi = EROFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct erofs_sb_info *sbi = EROFS_SB(sb);
	struct erofs_map_blocks map;
	struct erofs_fscache_map fsmap;
	int ret;

	if (erofs_inode_is_data_compressed(vi->datalayout)) {
		erofs_info(sb, "compressed layout not supported yet");
		ret = -EOPNOTSUPP;
		goto err_out;
	}

	map.m_la = fsmap.o_la = page_offset(page);

	ret = erofs_map_blocks(inode, &map, EROFS_GET_BLOCKS_RAW);
	if (ret)
		goto err_out;

	if (!(map.m_flags & EROFS_MAP_MAPPED)) {
		zero_user(page, 0, PAGE_SIZE);
		SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	fsmap.m_ctx  = sbi->bootstrap;
	fsmap.m_la   = map.m_la;
	fsmap.m_pa   = map.m_pa;
	fsmap.m_llen = map.m_llen;

	switch (vi->datalayout) {
	case EROFS_INODE_FLAT_PLAIN:
	case EROFS_INODE_CHUNK_BASED:
		return erofs_fscache_readpage_noinline(page, &fsmap);
	case EROFS_INODE_FLAT_INLINE:
		return erofs_fscache_readpage_inline(page, &fsmap);
	default:
		DBG_BUGON(1);
		ret = -EOPNOTSUPP;
	}

err_out:
	SetPageError(page);
	unlock_page(page);
	return ret;
}

const struct address_space_operations erofs_fscache_access_aops = {
	.readpage = erofs_fscache_readpage,
};

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

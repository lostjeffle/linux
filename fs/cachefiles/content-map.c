#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/uio.h>
#include <linux/falloc.h>
#include "internal.h"

/*
 * Return the size of the content map in bytes.
 *
 * There's one bit per granule (CACHEFILES_GRAN_SIZE, i.e. 4K). We size it in
 * terms of block size chunks (e.g. 4K), so that the map file can be punched
 * hole when the content map is truncated or invalidated. In this case, each 4K
 * chunk spans (4096 * BITS_PER_BYTE * CACHEFILES_GRAN_SIZE, i.e. 128M) of file
 * space.
 */
static size_t cachefiles_map_size(loff_t i_size)
{
	i_size = round_up(i_size, PAGE_SIZE * BITS_PER_BYTE * CACHEFILES_GRAN_SIZE);
	return i_size / BITS_PER_BYTE / CACHEFILES_GRAN_SIZE;
}

/*
 * Zero the unused tail.
 *
 * @i_size indicates the size of the backing object.
 */
static void cachefiles_zero_content_map(void *map, size_t content_map_size,
					size_t i_size)
{
	unsigned long granules_needed = DIV_ROUND_UP(i_size, CACHEFILES_GRAN_SIZE);
	unsigned long bytes_needed = BITS_TO_BYTES(granules_needed);
	unsigned long byte_end = min_t(unsigned long, bytes_needed, content_map_size);
	int i;

	if (bytes_needed < content_map_size)
		memset(map + bytes_needed, 0, content_map_size - bytes_needed);

	for (i = granules_needed; i < byte_end * BITS_PER_BYTE; i++)
		clear_bit(i, map);
}

/*
 * Load the content map from the backing map file.
 */
int cachefiles_load_content_map(struct cachefiles_object *object)
{
	struct file *file = object->volume->content_map[(u8)object->cookie->key_hash];
	loff_t off = object->content_map_off;
	size_t size = object->content_map_size;
	void *map;
	int ret;

	if (object->content_info != CACHEFILES_CONTENT_MAP)
		return 0;

	map = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(size));
	if (!map)
		return -ENOMEM;

	ret = kernel_read(file, map, size, &off);
	if (ret != size) {
		free_pages((unsigned long)map, get_order(size));
		return ret < 0 ? ret : -EIO;
	}

	/*
	 * Zero the unused tail. Later when expanding the content map, the
	 * content map itself may keep the same size while i_size of the backing
	 * object is increased. In this case, the original content map is reused
	 * and part of the original unused tail is used now. Be noted that
	 * content_map_size stored in xattr may be smaller or larger than the
	 * actual size of the backing object.
	 */
	cachefiles_zero_content_map(map, size, object->cookie->object_size);

	object->content_map = map;
	return 0;
}

/*
 * Save the content map to the backing map file.
 */
void cachefiles_save_content_map(struct cachefiles_object *object)
{
	struct file *file = object->volume->content_map[(u8)object->cookie->key_hash];
	loff_t off;
	int ret;

	if (object->content_info != CACHEFILES_CONTENT_MAP ||
	    !object->content_map_size)
		return;

	/* allocate space from content map file */
	off = object->content_map_off;
	if (off == CACHEFILES_CONTENT_MAP_OFF_INVAL) {
		struct inode *inode = file_inode(file);

		inode_lock(inode);
		off = i_size_read(inode);
		i_size_write(inode, off + object->content_map_size);
		inode_unlock(inode);

		object->content_map_off = off;
	}

	ret = kernel_write(file, object->content_map, object->content_map_size, &off);
	if (ret != object->content_map_size)
		object->content_info = CACHEFILES_CONTENT_NO_DATA;
}

static loff_t cachefiles_expand_map_off(struct file *file, loff_t old_off,
					size_t old_size, size_t new_size)
{
	struct inode *inode = file_inode(file);
	loff_t new_off;
	bool punch = false;

	inode_lock(inode);
	new_off = i_size_read(inode);
	/*
	 * Simply expand the old content map range if possible; or discard the
	 * old content map range and create a new one.
	 */
	if (new_off == old_off + old_size) {
		i_size_write(inode, old_off + new_size);
		new_off = old_off;
	} else {
		i_size_write(inode, new_off + new_size);
		punch = true;
	}
	inode_unlock(inode);

	if (punch)
		vfs_fallocate(file, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
			      old_off, old_size);

	return new_off;
}

/*
 * Expand the content map to a larger file size.
 */
static void cachefiles_expand_content_map(struct cachefiles_object *object)
{
	struct file *file = object->volume->content_map[(u8)object->cookie->key_hash];
	size_t size, zap_size;
	void *map, *zap;
	loff_t off;

	size = cachefiles_map_size(object->cookie->object_size);
	if (size <= object->content_map_size)
		return;

	map = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, get_order(size));
	if (!map)
		return;

	write_lock_bh(&object->content_map_lock);
	if (size > object->content_map_size) {
		zap = object->content_map;
		zap_size = object->content_map_size;
		memcpy(map, zap, zap_size);
		object->content_map = map;
		object->content_map_size = size;

		/* expand the content map file */
		off = object->content_map_off;
		if (off != CACHEFILES_CONTENT_MAP_OFF_INVAL)
			object->content_map_off = cachefiles_expand_map_off(file,
				off, zap_size, size);
	} else {
		zap = map;
		zap_size = size;
	}
	write_unlock_bh(&object->content_map_lock);

	free_pages((unsigned long)zap, get_order(zap_size));
}

void cachefiles_mark_content_map(struct cachefiles_object *object,
				 loff_t start, loff_t len)
{
	pgoff_t granule;
	loff_t end = start + len;

	if (object->cookie->advice & FSCACHE_ADV_SINGLE_CHUNK) {
		if (start == 0) {
			object->content_info = CACHEFILES_CONTENT_SINGLE;
			set_bit(FSCACHE_COOKIE_NEEDS_UPDATE, &object->cookie->flags);
		}
		return;
	}

	if (object->content_info == CACHEFILES_CONTENT_NO_DATA)
		object->content_info = CACHEFILES_CONTENT_MAP;

	/* TODO: set CACHEFILES_CONTENT_BACKFS_MAP accordingly */

	if (object->content_info != CACHEFILES_CONTENT_MAP)
		return;

	read_lock_bh(&object->content_map_lock);
	start = round_down(start, CACHEFILES_GRAN_SIZE);
	do {
		granule = start / CACHEFILES_GRAN_SIZE;
		if (granule / BITS_PER_BYTE >= object->content_map_size) {
			read_unlock_bh(&object->content_map_lock);
			cachefiles_expand_content_map(object);
			read_lock_bh(&object->content_map_lock);
		}

		if (WARN_ON(granule / BITS_PER_BYTE >= object->content_map_size))
			break;

		set_bit(granule, object->content_map);
		start += CACHEFILES_GRAN_SIZE;
	} while (start < end);

	set_bit(FSCACHE_COOKIE_NEEDS_UPDATE, &object->cookie->flags);
	read_unlock_bh(&object->content_map_lock);
}

loff_t cachefiles_find_next_granule(struct cachefiles_object *object,
				    loff_t start)
{
	unsigned long size, granule = start / CACHEFILES_GRAN_SIZE;
	loff_t result;

	read_lock_bh(&object->content_map_lock);
	size = object->content_map_size * BITS_PER_BYTE;
	result = find_next_bit(object->content_map, size, granule);
	read_unlock_bh(&object->content_map_lock);

	if (result == size)
		return -ENXIO;
	return result * CACHEFILES_GRAN_SIZE;
}

loff_t cachefiles_find_next_hole(struct cachefiles_object *object,
				 loff_t start)
{
	unsigned long size, granule = start / CACHEFILES_GRAN_SIZE;
	loff_t result;

	read_lock_bh(&object->content_map_lock);
	size = object->content_map_size * BITS_PER_BYTE;
	result = find_next_zero_bit(object->content_map, size, granule);
	read_unlock_bh(&object->content_map_lock);

	return min_t(loff_t, result * CACHEFILES_GRAN_SIZE,
			     object->cookie->object_size);
}

void cachefiles_invalidate_content_map(struct cachefiles_object *object)
{
	struct file *file = object->volume->content_map[(u8)object->cookie->key_hash];

	if (object->content_info != CACHEFILES_CONTENT_MAP)
		return;

	write_lock_bh(&object->content_map_lock);
	free_pages((unsigned long)object->content_map,
		   get_order(object->content_map_size));
	object->content_map = NULL;
	object->content_map_size = 0;

	if (object->content_map_off != CACHEFILES_CONTENT_MAP_OFF_INVAL) {
		vfs_fallocate(file, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				object->content_map_off, object->content_map_size);
		object->content_map_off = CACHEFILES_CONTENT_MAP_OFF_INVAL;
	}
	write_unlock_bh(&object->content_map_lock);
}

/*
 * Adjust the content map when we shorten a backing object.
 */
void cachefiles_shorten_content_map(struct cachefiles_object *object,
				    loff_t new_size)
{
	if (object->content_info != CACHEFILES_CONTENT_MAP)
		return;

	read_lock_bh(&object->content_map_lock);
	/*
	 * Nothing needs to be done when content map has not been allocated yet.
	 */
	if (!object->content_map_size)
		goto out;

	if (cachefiles_map_size(new_size) <= object->content_map_size)
		cachefiles_zero_content_map(object->content_map,
				object->content_map_size, new_size);
out:
	read_unlock_bh(&object->content_map_lock);
}

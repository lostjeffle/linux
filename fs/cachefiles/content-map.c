#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/uio.h>
#include "internal.h"

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

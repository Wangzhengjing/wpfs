/*
 *  linux/fs/ext4/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <asm/byteorder.h>

#include "wpfs.h"
#include "wpfs_jbd2.h"
#include "xattr.h"
#include "acl.h"

#include <trace/events/ext4.h>

/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */

/*
 * To avoid calling the atomic setbit hundreds or thousands of times, we only
 * need to use it within a single byte (to ensure we get endianness right).
 * We can use memset for the rest of the bitmap as there are no other users.
 */
void wpfs_mark_bitmap_end(int start_bit, int end_bit, char *bitmap)
{
	int i;

	if (start_bit >= end_bit)
		return;

	wpfs_debug("mark end bits +%d through +%d used\n", start_bit, end_bit);
	for (i = start_bit; i < ((start_bit + 7) & ~7UL); i++)
		wpfs_set_bit(i, bitmap);
	if (i < end_bit)
		memset(bitmap + (i >> 3), 0xff, (end_bit - i) >> 3);
}

/* Initializes an uninitialized inode bitmap */
unsigned wpfs_init_inode_bitmap(struct super_block *sb, struct buffer_head *bh,
				wpfs_group_t block_group,
				struct wpfs_group_desc *gdp)
{
	struct wpfs_sb_info *sbi = WPFS_SB(sb);

	J_ASSERT_BH(bh, buffer_locked(bh));

	/* If checksum is bad mark all blocks and inodes use to prevent
	 * allocation, essentially implementing a per-group read-only flag. */
	if (!wpfs_group_desc_csum_verify(sbi, block_group, gdp)) {
		ext4_error(sb, "Checksum bad for group %u", block_group);
		wpfs_free_blks_set(sb, gdp, 0);
		wpfs_free_inodes_set(sb, gdp, 0);
		wpfs_itable_unused_set(sb, gdp, 0);
		memset(bh->b_data, 0xff, sb->s_blocksize);
		return 0;
	}

	memset(bh->b_data, 0, (WPFS_INODES_PER_GROUP(sb) + 7) / 8);
	wpfs_mark_bitmap_end(WPFS_INODES_PER_GROUP(sb), sb->s_blocksize * 8,
			bh->b_data);

	return WPFS_INODES_PER_GROUP(sb);
}

/*
 * Read the inode allocation bitmap for a given block_group, reading
 * into the specified slot in the superblock's bitmap cache.
 *
 * Return buffer_head of bitmap on success or NULL.
 */
static struct buffer_head *
wpfs_read_inode_bitmap(struct super_block *sb, wpfs_group_t block_group)
{
	struct wpfs_group_desc *desc;
	struct buffer_head *bh = NULL;
	wpfs_fsblk_t bitmap_blk;

	desc = wpfs_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return NULL;
	bitmap_blk = wpfs_inode_bitmap(sb, desc);
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext4_error(sb, "Cannot read inode bitmap - "
			    "block_group = %u, inode_bitmap = %llu",
			    block_group, bitmap_blk);
		return NULL;
	}
	if (wpfs_bitmap_uptodate(bh))
		return bh;

	lock_buffer(bh);
	if (wpfs_bitmap_uptodate(bh)) {
		unlock_buffer(bh);
		return bh;
	}
	wpfs_lock_group(sb, block_group);
	if (desc->bg_flags & cpu_to_le16(WPFS_BG_INODE_UNINIT)) {
		wpfs_init_inode_bitmap(sb, bh, block_group, desc);
		wpfs_set_bitmap_uptodate(bh);
		set_buffer_uptodate(bh);
		wpfs_unlock_group(sb, block_group);
		unlock_buffer(bh);
		return bh;
	}
	wpfs_unlock_group(sb, block_group);
	if (buffer_uptodate(bh)) {
		/*
		 * if not uninit if bh is uptodate,
		 * bitmap is also uptodate
		 */
		wpfs_set_bitmap_uptodate(bh);
		unlock_buffer(bh);
		return bh;
	}
	/*
	 * submit the buffer_head for read. We can
	 * safely mark the bitmap as uptodate now.
	 * We do it here so the bitmap uptodate bit
	 * get set with buffer lock held.
	 */
	wpfs_set_bitmap_uptodate(bh);
	if (bh_submit_read(bh) < 0) {
		put_bh(bh);
		ext4_error(sb, "Cannot read inode bitmap - "
			    "block_group = %u, inode_bitmap = %llu",
			    block_group, bitmap_blk);
		return NULL;
	}
	return bh;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void wpfs_free_inode(handle_t *handle, struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	wpfs_group_t block_group;
	unsigned long bit;
	struct wpfs_group_desc *gdp;
	struct wpfs_super_block *es;
	struct wpfs_sb_info *sbi;
	int fatal = 0, err, count, cleared;

	if (atomic_read(&inode->i_count) > 1) {
		printk(KERN_ERR "wpfs_free_inode: inode has count=%d\n",
		       atomic_read(&inode->i_count));
		return;
	}
	if (inode->i_nlink) {
		printk(KERN_ERR "wpfs_free_inode: inode has nlink=%d\n",
		       inode->i_nlink);
		return;
	}
	if (!sb) {
		printk(KERN_ERR "wpfs_free_inode: inode on "
		       "nonexistent device\n");
		return;
	}
	sbi = WPFS_SB(sb);

	ino = inode->i_ino;
	wpfs_debug("freeing inode %lu\n", ino);
	trace_ext4_free_inode(inode);

	/*
	 * Note: we must free any quota before locking the superblock,
	 * as writing the quota to disk may need the lock as well.
	 */
	vfs_dq_init(inode);
	wpfs_xattr_delete_inode(handle, inode);
	vfs_dq_free_inode(inode);
	vfs_dq_drop(inode);

	is_directory = S_ISDIR(inode->i_mode);

	/* Do this BEFORE marking the inode not in use or returning an error */
	clear_inode(inode);

	es = WPFS_SB(sb)->s_es;
	if (ino < WPFS_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		ext4_error(sb, "reserved or nonexistent inode %lu", ino);
		goto error_return;
	}
	block_group = (ino - 1) / WPFS_INODES_PER_GROUP(sb);
	bit = (ino - 1) % WPFS_INODES_PER_GROUP(sb);
	bitmap_bh = wpfs_read_inode_bitmap(sb, block_group);
	if (!bitmap_bh)
		goto error_return;

	BUFFER_TRACE(bitmap_bh, "get_write_access");
	fatal = wpfs_journal_get_write_access(handle, bitmap_bh);
	if (fatal)
		goto error_return;

	/* Ok, now we can actually update the inode bitmaps.. */
	wpfs_lock_group(sb, block_group);
	cleared = wpfs_clear_bit(bit, bitmap_bh->b_data);
	wpfs_unlock_group(sb, block_group);
	if (!cleared)
		ext4_error(sb, "bit already cleared for inode %lu", ino);
	else {
		gdp = wpfs_get_group_desc(sb, block_group, &bh2);

		BUFFER_TRACE(bh2, "get_write_access");
		fatal = wpfs_journal_get_write_access(handle, bh2);
		if (fatal) goto error_return;

		if (gdp) {
			wpfs_lock_group(sb, block_group);
			count = wpfs_free_inodes_count(sb, gdp) + 1;
			wpfs_free_inodes_set(sb, gdp, count);
			if (is_directory) {
				count = wpfs_used_dirs_count(sb, gdp) - 1;
				wpfs_used_dirs_set(sb, gdp, count);
				if (sbi->s_log_groups_per_flex) {
					wpfs_group_t f;

					f = wpfs_flex_group(sbi, block_group);
					atomic_dec(&sbi->s_flex_groups[f].used_dirs);
				}

			}
			gdp->bg_checksum = wpfs_group_desc_csum(sbi,
							block_group, gdp);
			wpfs_unlock_group(sb, block_group);
			percpu_counter_inc(&sbi->s_freeinodes_counter);
			if (is_directory)
				percpu_counter_dec(&sbi->s_dirs_counter);

			if (sbi->s_log_groups_per_flex) {
				wpfs_group_t f;

				f = wpfs_flex_group(sbi, block_group);
				atomic_inc(&sbi->s_flex_groups[f].free_inodes);
			}
		}
		BUFFER_TRACE(bh2, "call wpfs_handle_dirty_metadata");
		err = wpfs_handle_dirty_metadata(handle, NULL, bh2);
		if (!fatal) fatal = err;
	}
	BUFFER_TRACE(bitmap_bh, "call wpfs_handle_dirty_metadata");
	err = wpfs_handle_dirty_metadata(handle, NULL, bitmap_bh);
	if (!fatal)
		fatal = err;
	sb->s_dirt = 1;
error_return:
	brelse(bitmap_bh);
	wpfs_std_error(sb, fatal);
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory\'s block
 * group to find a free inode.
 */
static int find_group_dir(struct super_block *sb, struct inode *parent,
				wpfs_group_t *best_group)
{
	wpfs_group_t ngroups = wpfs_get_groups_count(sb);
	unsigned int freei, avefreei;
	struct wpfs_group_desc *desc, *best_desc = NULL;
	wpfs_group_t group;
	int ret = -1;

	freei = percpu_counter_read_positive(&WPFS_SB(sb)->s_freeinodes_counter);
	avefreei = freei / ngroups;

	for (group = 0; group < ngroups; group++) {
		desc = wpfs_get_group_desc(sb, group, NULL);
		if (!desc || !wpfs_free_inodes_count(sb, desc))
			continue;
		if (wpfs_free_inodes_count(sb, desc) < avefreei)
			continue;
		if (!best_desc ||
		    (wpfs_free_blks_count(sb, desc) >
		     wpfs_free_blks_count(sb, best_desc))) {
			*best_group = group;
			best_desc = desc;
			ret = 0;
		}
	}
	return ret;
}

#define free_block_ratio 10

static int find_group_flex(struct super_block *sb, struct inode *parent,
			   wpfs_group_t *best_group)
{
	struct wpfs_sb_info *sbi = WPFS_SB(sb);
	struct wpfs_group_desc *desc;
	struct wpfs_flex_groups *flex_group = sbi->s_flex_groups;
	wpfs_group_t parent_group = WPFS_I(parent)->i_block_group;
	wpfs_group_t parent_fbg_group = wpfs_flex_group(sbi, parent_group);
	wpfs_group_t ngroups = wpfs_get_groups_count(sb);
	int flex_size = wpfs_flex_bg_size(sbi);
	wpfs_group_t best_flex = parent_fbg_group;
	int blocks_per_flex = sbi->s_blocks_per_group * flex_size;
	int flexbg_free_blocks;
	int flex_freeb_ratio;
	wpfs_group_t n_fbg_groups;
	wpfs_group_t i;

	n_fbg_groups = (ngroups + flex_size - 1) >>
		sbi->s_log_groups_per_flex;

find_close_to_parent:
	flexbg_free_blocks = atomic_read(&flex_group[best_flex].free_blocks);
	flex_freeb_ratio = flexbg_free_blocks * 100 / blocks_per_flex;
	if (atomic_read(&flex_group[best_flex].free_inodes) &&
	    flex_freeb_ratio > free_block_ratio)
		goto found_flexbg;

	if (best_flex && best_flex == parent_fbg_group) {
		best_flex--;
		goto find_close_to_parent;
	}

	for (i = 0; i < n_fbg_groups; i++) {
		if (i == parent_fbg_group || i == parent_fbg_group - 1)
			continue;

		flexbg_free_blocks = atomic_read(&flex_group[i].free_blocks);
		flex_freeb_ratio = flexbg_free_blocks * 100 / blocks_per_flex;

		if (flex_freeb_ratio > free_block_ratio &&
		    (atomic_read(&flex_group[i].free_inodes))) {
			best_flex = i;
			goto found_flexbg;
		}

		if ((atomic_read(&flex_group[best_flex].free_inodes) == 0) ||
		    ((atomic_read(&flex_group[i].free_blocks) >
		      atomic_read(&flex_group[best_flex].free_blocks)) &&
		     atomic_read(&flex_group[i].free_inodes)))
			best_flex = i;
	}

	if (!atomic_read(&flex_group[best_flex].free_inodes) ||
	    !atomic_read(&flex_group[best_flex].free_blocks))
		return -1;

found_flexbg:
	for (i = best_flex * flex_size; i < ngroups &&
		     i < (best_flex + 1) * flex_size; i++) {
		desc = wpfs_get_group_desc(sb, i, NULL);
		if (wpfs_free_inodes_count(sb, desc)) {
			*best_group = i;
			goto out;
		}
	}

	return -1;
out:
	return 0;
}

struct orlov_stats {
	__u32 free_inodes;
	__u32 free_blocks;
	__u32 used_dirs;
};

/*
 * Helper function for Orlov's allocator; returns critical information
 * for a particular block group or flex_bg.  If flex_size is 1, then g
 * is a block group number; otherwise it is flex_bg number.
 */
void get_orlov_stats(struct super_block *sb, wpfs_group_t g,
		       int flex_size, struct orlov_stats *stats)
{
	struct wpfs_group_desc *desc;
	struct wpfs_flex_groups *flex_group = WPFS_SB(sb)->s_flex_groups;

	if (flex_size > 1) {
		stats->free_inodes = atomic_read(&flex_group[g].free_inodes);
		stats->free_blocks = atomic_read(&flex_group[g].free_blocks);
		stats->used_dirs = atomic_read(&flex_group[g].used_dirs);
		return;
	}

	desc = wpfs_get_group_desc(sb, g, NULL);
	if (desc) {
		stats->free_inodes = wpfs_free_inodes_count(sb, desc);
		stats->free_blocks = wpfs_free_blks_count(sb, desc);
		stats->used_dirs = wpfs_used_dirs_count(sb, desc);
	} else {
		stats->free_inodes = 0;
		stats->free_blocks = 0;
		stats->used_dirs = 0;
	}
}

/*
 * Orlov's allocator for directories.
 *
 * We always try to spread first-level directories.
 *
 * If there are blockgroups with both free inodes and free blocks counts
 * not worse than average we return one with smallest directory count.
 * Otherwise we simply return a random group.
 *
 * For the rest rules look so:
 *
 * It's OK to put directory into a group unless
 * it has too many directories already (max_dirs) or
 * it has too few free inodes left (min_inodes) or
 * it has too few free blocks left (min_blocks) or
 * Parent's group is preferred, if it doesn't satisfy these
 * conditions we search cyclically through the rest. If none
 * of the groups look good we just look for a group with more
 * free inodes than average (starting at parent's group).
 */

static int find_group_orlov(struct super_block *sb, struct inode *parent,
			    wpfs_group_t *group, int mode,
			    const struct qstr *qstr)
{
	wpfs_group_t parent_group = WPFS_I(parent)->i_block_group;
	struct wpfs_sb_info *sbi = WPFS_SB(sb);
	wpfs_group_t real_ngroups = wpfs_get_groups_count(sb);
	int inodes_per_group = WPFS_INODES_PER_GROUP(sb);
	unsigned int freei, avefreei;
	wpfs_fsblk_t freeb, avefreeb;
	unsigned int ndirs;
	int max_dirs, min_inodes;
	wpfs_grpblk_t min_blocks;
	wpfs_group_t i, grp, g, ngroups;
	struct wpfs_group_desc *desc;
	struct orlov_stats stats;
	int flex_size = wpfs_flex_bg_size(sbi);
	struct wpfs_dx_hash_info hinfo;

	ngroups = real_ngroups;
	if (flex_size > 1) {
		ngroups = (real_ngroups + flex_size - 1) >>
			sbi->s_log_groups_per_flex;
		parent_group >>= sbi->s_log_groups_per_flex;
	}

	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	avefreei = freei / ngroups;
	freeb = percpu_counter_read_positive(&sbi->s_freeblocks_counter);
	avefreeb = freeb;
	do_div(avefreeb, ngroups);
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if (S_ISDIR(mode) &&
	    ((parent == sb->s_root->d_inode) ||
	     (WPFS_I(parent)->i_flags & WPFS_TOPDIR_FL))) {
		int best_ndir = inodes_per_group;
		int ret = -1;

		if (qstr) {
			hinfo.hash_version = DX_HASH_HALF_MD4;
			hinfo.seed = sbi->s_hash_seed;
			wpfs_dirhash(qstr->name, qstr->len, &hinfo);
			grp = hinfo.hash;
		} else
			get_random_bytes(&grp, sizeof(grp));
		parent_group = (unsigned)grp % ngroups;
		for (i = 0; i < ngroups; i++) {
			g = (parent_group + i) % ngroups;
			get_orlov_stats(sb, g, flex_size, &stats);
			if (!stats.free_inodes)
				continue;
			if (stats.used_dirs >= best_ndir)
				continue;
			if (stats.free_inodes < avefreei)
				continue;
			if (stats.free_blocks < avefreeb)
				continue;
			grp = g;
			ret = 0;
			best_ndir = stats.used_dirs;
		}
		if (ret)
			goto fallback;
	found_flex_bg:
		if (flex_size == 1) {
			*group = grp;
			return 0;
		}

		/*
		 * We pack inodes at the beginning of the flexgroup's
		 * inode tables.  Block allocation decisions will do
		 * something similar, although regular files will
		 * start at 2nd block group of the flexgroup.  See
		 * wpfs_ext_find_goal() and ext4_find_near().
		 */
		grp *= flex_size;
		for (i = 0; i < flex_size; i++) {
			if (grp+i >= real_ngroups)
				break;
			desc = wpfs_get_group_desc(sb, grp+i, NULL);
			if (desc && wpfs_free_inodes_count(sb, desc)) {
				*group = grp+i;
				return 0;
			}
		}
		goto fallback;
	}

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group*flex_size / 4;
	if (min_inodes < 1)
		min_inodes = 1;
	min_blocks = avefreeb - WPFS_BLOCKS_PER_GROUP(sb)*flex_size / 4;

	/*
	 * Start looking in the flex group where we last allocated an
	 * inode for this parent directory
	 */
	if (WPFS_I(parent)->i_last_alloc_group != ~0) {
		parent_group = WPFS_I(parent)->i_last_alloc_group;
		if (flex_size > 1)
			parent_group >>= sbi->s_log_groups_per_flex;
	}

	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		get_orlov_stats(sb, grp, flex_size, &stats);
		if (stats.used_dirs >= max_dirs)
			continue;
		if (stats.free_inodes < min_inodes)
			continue;
		if (stats.free_blocks < min_blocks)
			continue;
		goto found_flex_bg;
	}

fallback:
	ngroups = real_ngroups;
	avefreei = freei / ngroups;
fallback_retry:
	parent_group = WPFS_I(parent)->i_block_group;
	for (i = 0; i < ngroups; i++) {
		grp = (parent_group + i) % ngroups;
		desc = wpfs_get_group_desc(sb, grp, NULL);
		if (desc && wpfs_free_inodes_count(sb, desc) &&
		    wpfs_free_inodes_count(sb, desc) >= avefreei) {
			*group = grp;
			return 0;
		}
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback_retry;
	}

	return -1;
}

static int find_group_other(struct super_block *sb, struct inode *parent,
			    wpfs_group_t *group, int mode)
{
	wpfs_group_t parent_group = WPFS_I(parent)->i_block_group;
	wpfs_group_t i, last, ngroups = wpfs_get_groups_count(sb);
	struct wpfs_group_desc *desc;
	int flex_size = wpfs_flex_bg_size(WPFS_SB(sb));

	/*
	 * Try to place the inode is the same flex group as its
	 * parent.  If we can't find space, use the Orlov algorithm to
	 * find another flex group, and store that information in the
	 * parent directory's inode information so that use that flex
	 * group for future allocations.
	 */
	if (flex_size > 1) {
		int retry = 0;

	try_again:
		parent_group &= ~(flex_size-1);
		last = parent_group + flex_size;
		if (last > ngroups)
			last = ngroups;
		for  (i = parent_group; i < last; i++) {
			desc = wpfs_get_group_desc(sb, i, NULL);
			if (desc && wpfs_free_inodes_count(sb, desc)) {
				*group = i;
				return 0;
			}
		}
		if (!retry && WPFS_I(parent)->i_last_alloc_group != ~0) {
			retry = 1;
			parent_group = WPFS_I(parent)->i_last_alloc_group;
			goto try_again;
		}
		/*
		 * If this didn't work, use the Orlov search algorithm
		 * to find a new flex group; we pass in the mode to
		 * avoid the topdir algorithms.
		 */
		*group = parent_group + flex_size;
		if (*group > ngroups)
			*group = 0;
		return find_group_orlov(sb, parent, group, mode, 0);
	}

	/*
	 * Try to place the inode in its parent directory
	 */
	*group = parent_group;
	desc = wpfs_get_group_desc(sb, *group, NULL);
	if (desc && wpfs_free_inodes_count(sb, desc) &&
			wpfs_free_blks_count(sb, desc))
		return 0;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	*group = (*group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some free
	 * blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		*group += i;
		if (*group >= ngroups)
			*group -= ngroups;
		desc = wpfs_get_group_desc(sb, *group, NULL);
		if (desc && wpfs_free_inodes_count(sb, desc) &&
				wpfs_free_blks_count(sb, desc))
			return 0;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	*group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++*group >= ngroups)
			*group = 0;
		desc = wpfs_get_group_desc(sb, *group, NULL);
		if (desc && wpfs_free_inodes_count(sb, desc))
			return 0;
	}

	return -1;
}

/*
 * claim the inode from the inode bitmap. If the group
 * is uninit we need to take the groups's ext4_group_lock
 * and clear the uninit flag. The inode bitmap update
 * and group desc uninit flag clear should be done
 * after holding ext4_group_lock so that wpfs_read_inode_bitmap
 * doesn't race with the wpfs_claim_inode
 */
static int wpfs_claim_inode(struct super_block *sb,
			struct buffer_head *inode_bitmap_bh,
			unsigned long ino, wpfs_group_t group, int mode)
{
	int free = 0, retval = 0, count;
	struct wpfs_sb_info *sbi = WPFS_SB(sb);
	struct wpfs_group_desc *gdp = wpfs_get_group_desc(sb, group, NULL);

	wpfs_lock_group(sb, group);
	if (wpfs_set_bit(ino, inode_bitmap_bh->b_data)) {
		/* not a free inode */
		retval = 1;
		goto err_ret;
	}
	ino++;
	if ((group == 0 && ino < WPFS_FIRST_INO(sb)) ||
			ino > WPFS_INODES_PER_GROUP(sb)) {
		wpfs_unlock_group(sb, group);
		ext4_error(sb, "reserved inode or inode > inodes count - "
			   "block_group = %u, inode=%lu", group,
			   ino + group * WPFS_INODES_PER_GROUP(sb));
		return 1;
	}
	/* If we didn't allocate from within the initialized part of the inode
	 * table then we need to initialize up to this inode. */
	if (WPFS_HAS_RO_COMPAT_FEATURE(sb, WPFS_FEATURE_RO_COMPAT_GDT_CSUM)) {

		if (gdp->bg_flags & cpu_to_le16(WPFS_BG_INODE_UNINIT)) {
			gdp->bg_flags &= cpu_to_le16(~WPFS_BG_INODE_UNINIT);
			/* When marking the block group with
			 * ~WPFS_BG_INODE_UNINIT we don't want to depend
			 * on the value of bg_itable_unused even though
			 * mke2fs could have initialized the same for us.
			 * Instead we calculated the value below
			 */

			free = 0;
		} else {
			free = WPFS_INODES_PER_GROUP(sb) -
				wpfs_itable_unused_count(sb, gdp);
		}

		/*
		 * Check the relative inode number against the last used
		 * relative inode number in this group. if it is greater
		 * we need to  update the bg_itable_unused count
		 *
		 */
		if (ino > free)
			wpfs_itable_unused_set(sb, gdp,
					(WPFS_INODES_PER_GROUP(sb) - ino));
	}
	count = wpfs_free_inodes_count(sb, gdp) - 1;
	wpfs_free_inodes_set(sb, gdp, count);
	if (S_ISDIR(mode)) {
		count = wpfs_used_dirs_count(sb, gdp) + 1;
		wpfs_used_dirs_set(sb, gdp, count);
		if (sbi->s_log_groups_per_flex) {
			wpfs_group_t f = wpfs_flex_group(sbi, group);

			atomic_inc(&sbi->s_flex_groups[f].used_dirs);
		}
	}
	gdp->bg_checksum = wpfs_group_desc_csum(sbi, group, gdp);
err_ret:
	wpfs_unlock_group(sb, group);
	return retval;
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory's block
 * group to find a free inode.
 */
struct inode *wpfs_new_inode(handle_t *handle, struct inode *dir, int mode,
			     const struct qstr *qstr, __u32 goal)
{
	struct super_block *sb;
	struct buffer_head *inode_bitmap_bh = NULL;
	struct buffer_head *group_desc_bh;
	wpfs_group_t ngroups, group = 0;
	unsigned long ino = 0;
	struct inode *inode;
	struct wpfs_group_desc *gdp = NULL;
	struct ext4_inode_info *ei;
	struct wpfs_sb_info *sbi;
	int ret2, err = 0;
	struct inode *ret;
	wpfs_group_t i;
	int free = 0;
	static int once = 1;
	wpfs_group_t flex_group;

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);

	sb = dir->i_sb;
	ngroups = wpfs_get_groups_count(sb);
	trace_ext4_request_inode(dir, mode);
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ei = WPFS_I(inode);
	sbi = WPFS_SB(sb);

	if (!goal)
		goal = sbi->s_inode_goal;

	if (goal && goal <= le32_to_cpu(sbi->s_es->s_inodes_count)) {
		group = (goal - 1) / WPFS_INODES_PER_GROUP(sb);
		ino = (goal - 1) % WPFS_INODES_PER_GROUP(sb);
		ret2 = 0;
		goto got_group;
	}

	if (sbi->s_log_groups_per_flex && test_opt(sb, OLDALLOC)) {
		ret2 = find_group_flex(sb, dir, &group);
		if (ret2 == -1) {
			ret2 = find_group_other(sb, dir, &group, mode);
			if (ret2 == 0 && once) {
				once = 0;
				printk(KERN_NOTICE "wpfs: find_group_flex "
				       "failed, fallback succeeded dir %lu\n",
				       dir->i_ino);
			}
		}
		goto got_group;
	}

	if (S_ISDIR(mode)) {
		if (test_opt(sb, OLDALLOC))
			ret2 = find_group_dir(sb, dir, &group);
		else
			ret2 = find_group_orlov(sb, dir, &group, mode, qstr);
	} else
		ret2 = find_group_other(sb, dir, &group, mode);

got_group:
	WPFS_I(dir)->i_last_alloc_group = group;
	err = -ENOSPC;
	if (ret2 == -1)
		goto out;

	for (i = 0; i < ngroups; i++, ino = 0) {
		err = -EIO;

		gdp = wpfs_get_group_desc(sb, group, &group_desc_bh);
		if (!gdp)
			goto fail;

		brelse(inode_bitmap_bh);
		inode_bitmap_bh = wpfs_read_inode_bitmap(sb, group);
		if (!inode_bitmap_bh)
			goto fail;

repeat_in_this_group:
		ino = wpfs_find_next_zero_bit((unsigned long *)
					      inode_bitmap_bh->b_data,
					      WPFS_INODES_PER_GROUP(sb), ino);

		if (ino < WPFS_INODES_PER_GROUP(sb)) {

			BUFFER_TRACE(inode_bitmap_bh, "get_write_access");
			err = wpfs_journal_get_write_access(handle,
							    inode_bitmap_bh);
			if (err)
				goto fail;

			BUFFER_TRACE(group_desc_bh, "get_write_access");
			err = wpfs_journal_get_write_access(handle,
								group_desc_bh);
			if (err)
				goto fail;
			if (!wpfs_claim_inode(sb, inode_bitmap_bh,
						ino, group, mode)) {
				/* we won it */
				BUFFER_TRACE(inode_bitmap_bh,
					"call wpfs_handle_dirty_metadata");
				err = wpfs_handle_dirty_metadata(handle,
								 NULL,
							inode_bitmap_bh);
				if (err)
					goto fail;
				/* zero bit is inode number 1*/
				ino++;
				goto got;
			}
			/* we lost it */
			wpfs_handle_release_buffer(handle, inode_bitmap_bh);
			wpfs_handle_release_buffer(handle, group_desc_bh);

			if (++ino < WPFS_INODES_PER_GROUP(sb))
				goto repeat_in_this_group;
		}

		/*
		 * This case is possible in concurrent environment.  It is very
		 * rare.  We cannot repeat the find_group_xxx() call because
		 * that will simply return the same blockgroup, because the
		 * group descriptor metadata has not yet been updated.
		 * So we just go onto the next blockgroup.
		 */
		if (++group == ngroups)
			group = 0;
	}
	err = -ENOSPC;
	goto out;

got:
	/* We may have to initialize the block bitmap if it isn't already */
	if (WPFS_HAS_RO_COMPAT_FEATURE(sb, WPFS_FEATURE_RO_COMPAT_GDT_CSUM) &&
	    gdp->bg_flags & cpu_to_le16(WPFS_BG_BLOCK_UNINIT)) {
		struct buffer_head *block_bitmap_bh;

		block_bitmap_bh = wpfs_read_block_bitmap(sb, group);
		BUFFER_TRACE(block_bitmap_bh, "get block bitmap access");
		err = wpfs_journal_get_write_access(handle, block_bitmap_bh);
		if (err) {
			brelse(block_bitmap_bh);
			goto fail;
		}

		free = 0;
		wpfs_lock_group(sb, group);
		/* recheck and clear flag under lock if we still need to */
		if (gdp->bg_flags & cpu_to_le16(WPFS_BG_BLOCK_UNINIT)) {
			free = wpfs_free_blocks_after_init(sb, group, gdp);
			gdp->bg_flags &= cpu_to_le16(~WPFS_BG_BLOCK_UNINIT);
			wpfs_free_blks_set(sb, gdp, free);
			gdp->bg_checksum = wpfs_group_desc_csum(sbi, group,
								gdp);
		}
		wpfs_unlock_group(sb, group);

		/* Don't need to dirty bitmap block if we didn't change it */
		if (free) {
			BUFFER_TRACE(block_bitmap_bh, "dirty block bitmap");
			err = wpfs_handle_dirty_metadata(handle,
							NULL, block_bitmap_bh);
		}

		brelse(block_bitmap_bh);
		if (err)
			goto fail;
	}
	BUFFER_TRACE(group_desc_bh, "call wpfs_handle_dirty_metadata");
	err = wpfs_handle_dirty_metadata(handle, NULL, group_desc_bh);
	if (err)
		goto fail;

	percpu_counter_dec(&sbi->s_freeinodes_counter);
	if (S_ISDIR(mode))
		percpu_counter_inc(&sbi->s_dirs_counter);
	sb->s_dirt = 1;

	if (sbi->s_log_groups_per_flex) {
		flex_group = wpfs_flex_group(sbi, group);
		atomic_dec(&sbi->s_flex_groups[flex_group].free_inodes);
	}

	inode->i_uid = current_fsuid();
	if (test_opt(sb, GRPID))
		inode->i_gid = dir->i_gid;
	else if (dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;
		if (S_ISDIR(mode))
			mode |= S_ISGID;
	} else
		inode->i_gid = current_fsgid();
	inode->i_mode = mode;

	inode->i_ino = ino + group * WPFS_INODES_PER_GROUP(sb);
	/* This is the optimal IO size (for stat), not the fs block size */
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = ei->i_crtime =
						       wpfs_current_time(inode);

	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_dir_start_lookup = 0;
	ei->i_disksize = 0;

	/*
	 * Don't inherit extent flag from directory, amongst others. We set
	 * extent flag on newly created directory and file only if -o extent
	 * mount option is specified
	 */
	ei->i_flags =
		wpfs_mask_flags(mode, WPFS_I(dir)->i_flags & WPFS_FL_INHERITED);
	ei->i_file_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_group = group;
	ei->i_last_alloc_group = ~0;

	wpfs_set_inode_flags(inode);
	if (IS_DIRSYNC(inode))
		wpfs_handle_sync(handle);
	if (insert_inode_locked(inode) < 0) {
		err = -EINVAL;
		goto fail_drop;
	}
	spin_lock(&sbi->s_next_gen_lock);
	inode->i_generation = sbi->s_next_generation++;
	spin_unlock(&sbi->s_next_gen_lock);

	ei->i_state_flags = 0;
	wpfs_set_inode_state(inode, WPFS_STATE_NEW);

	ei->i_extra_isize = WPFS_SB(sb)->s_want_extra_isize;

	ret = inode;
	if (vfs_dq_alloc_inode(inode)) {
		err = -EDQUOT;
		goto fail_drop;
	}

	err = wpfs_init_acl(handle, inode, dir);
	if (err)
		goto fail_free_drop;

	err = wpfs_init_security(handle, inode, dir);
	if (err)
		goto fail_free_drop;

	if (WPFS_HAS_INCOMPAT_FEATURE(sb, WPFS_FEATURE_INCOMPAT_EXTENTS)) {
		/* set extent flag only for directory, file and normal symlink*/
		if (S_ISDIR(mode) || S_ISREG(mode) || S_ISLNK(mode)) {
			WPFS_I(inode)->i_flags |= WPFS_EXTENTS_FL;
			wpfs_ext_tree_init(handle, inode);
		}
	}

	err = wpfs_mark_inode_dirty(handle, inode);
	if (err) {
		wpfs_std_error(sb, err);
		goto fail_free_drop;
	}

	wpfs_debug("allocating inode %lu\n", inode->i_ino);
	trace_ext4_allocate_inode(inode, dir, mode);
	goto really_out;
fail:
	wpfs_std_error(sb, err);
out:
	iput(inode);
	ret = ERR_PTR(err);
really_out:
	brelse(inode_bitmap_bh);
	return ret;

fail_free_drop:
	vfs_dq_free_inode(inode);

fail_drop:
	vfs_dq_drop(inode);
	inode->i_flags |= S_NOQUOTA;
	inode->i_nlink = 0;
	unlock_new_inode(inode);
	iput(inode);
	brelse(inode_bitmap_bh);
	return ERR_PTR(err);
}

/* Verify that we are loading a valid orphan from disk */
struct inode *wpfs_orphan_get(struct super_block *sb, unsigned long ino)
{
	unsigned long max_ino = le32_to_cpu(WPFS_SB(sb)->s_es->s_inodes_count);
	wpfs_group_t block_group;
	int bit;
	struct buffer_head *bitmap_bh;
	struct inode *inode = NULL;
	long err = -EIO;

	/* Error cases - e2fsck has already cleaned up for us */
	if (ino > max_ino) {
		wpfs_warning(sb, "bad orphan ino %lu!  e2fsck was run?", ino);
		goto error;
	}

	block_group = (ino - 1) / WPFS_INODES_PER_GROUP(sb);
	bit = (ino - 1) % WPFS_INODES_PER_GROUP(sb);
	bitmap_bh = wpfs_read_inode_bitmap(sb, block_group);
	if (!bitmap_bh) {
		wpfs_warning(sb, "inode bitmap error for orphan %lu", ino);
		goto error;
	}

	/* Having the inode bit set should be a 100% indicator that this
	 * is a valid orphan (no e2fsck run on fs).  Orphans also include
	 * inodes that were being truncated, so we can't check i_nlink==0.
	 */
	if (!wpfs_test_bit(bit, bitmap_bh->b_data))
		goto bad_orphan;

	inode = wpfs_iget(sb, ino);
	if (IS_ERR(inode))
		goto iget_failed;

	/*
	 * If the orphans has i_nlinks > 0 then it should be able to be
	 * truncated, otherwise it won't be removed from the orphan list
	 * during processing and an infinite loop will result.
	 */
	if (inode->i_nlink && !wpfs_can_truncate(inode))
		goto bad_orphan;

	if (NEXT_ORPHAN(inode) > max_ino)
		goto bad_orphan;
	brelse(bitmap_bh);
	return inode;

iget_failed:
	err = PTR_ERR(inode);
	inode = NULL;
bad_orphan:
	wpfs_warning(sb, "bad orphan inode %lu!  e2fsck was run?", ino);
	printk(KERN_NOTICE "wpfs_test_bit(bit=%d, block=%llu) = %d\n",
	       bit, (unsigned long long)bitmap_bh->b_blocknr,
	       wpfs_test_bit(bit, bitmap_bh->b_data));
	printk(KERN_NOTICE "inode=%p\n", inode);
	if (inode) {
		printk(KERN_NOTICE "is_bad_inode(inode)=%d\n",
		       is_bad_inode(inode));
		printk(KERN_NOTICE "NEXT_ORPHAN(inode)=%u\n",
		       NEXT_ORPHAN(inode));
		printk(KERN_NOTICE "max_ino=%lu\n", max_ino);
		printk(KERN_NOTICE "i_nlink=%u\n", inode->i_nlink);
		/* Avoid freeing blocks if we got a bad deleted inode */
		if (inode->i_nlink == 0)
			inode->i_blocks = 0;
		iput(inode);
	}
	brelse(bitmap_bh);
error:
	return ERR_PTR(err);
}

unsigned long wpfs_count_free_inodes(struct super_block *sb)
{
	unsigned long desc_count;
	struct wpfs_group_desc *gdp;
	wpfs_group_t i, ngroups = wpfs_get_groups_count(sb);
#ifdef WPFS_FS_DEBUG
	struct wpfs_super_block *es;
	unsigned long bitmap_count, x;
	struct buffer_head *bitmap_bh = NULL;

	es = WPFS_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	gdp = NULL;
	for (i = 0; i < ngroups; i++) {
		gdp = wpfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += wpfs_free_inodes_count(sb, gdp);
		brelse(bitmap_bh);
		bitmap_bh = wpfs_read_inode_bitmap(sb, i);
		if (!bitmap_bh)
			continue;

		x = wpfs_count_free(bitmap_bh, WPFS_INODES_PER_GROUP(sb) / 8);
		printk(KERN_DEBUG "group %lu: stored = %d, counted = %lu\n",
			(unsigned long) i, wpfs_free_inodes_count(sb, gdp), x);
		bitmap_count += x;
	}
	brelse(bitmap_bh);
	printk(KERN_DEBUG "wpfs_count_free_inodes: "
	       "stored = %u, computed = %lu, %lu\n",
	       le32_to_cpu(es->s_free_inodes_count), desc_count, bitmap_count);
	return desc_count;
#else
	desc_count = 0;
	for (i = 0; i < ngroups; i++) {
		gdp = wpfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		desc_count += wpfs_free_inodes_count(sb, gdp);
		cond_resched();
	}
	return desc_count;
#endif
}

/* Called at mount-time, super-block is locked */
unsigned long wpfs_count_dirs(struct super_block * sb)
{
	unsigned long count = 0;
	wpfs_group_t i, ngroups = wpfs_get_groups_count(sb);

	for (i = 0; i < ngroups; i++) {
		struct wpfs_group_desc *gdp = wpfs_get_group_desc(sb, i, NULL);
		if (!gdp)
			continue;
		count += wpfs_used_dirs_count(sb, gdp);
	}
	return count;
}

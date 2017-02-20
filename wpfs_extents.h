/*
 * Copyright (c) 2003-2006, Cluster File Systems, Inc, info@clusterfs.com
 * Written by Alex Tomas <alex@clusterfs.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public Licens
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-
 */

#ifndef _WPFS_EXTENTS
#define _WPFS_EXTENTS

#include "wpfs.h"

/*
 * With AGGRESSIVE_TEST defined, the capacity of index/leaf blocks
 * becomes very small, so index split, in-depth growing and
 * other hard changes happen much more often.
 * This is for debug purposes only.
 */
#define AGGRESSIVE_TEST_

/*
 * With EXTENTS_STATS defined, the number of blocks and extents
 * are collected in the truncate path. They'll be shown at
 * umount time.
 */
#define EXTENTS_STATS__

/*
 * If CHECK_BINSEARCH is defined, then the results of the binary search
 * will also be checked by linear search.
 */
#define CHECK_BINSEARCH__

/*
 * Turn on EXT_DEBUG to get lots of info about extents operations.
 */
#define EXT_DEBUG__
#ifdef EXT_DEBUG
#define ext_debug(a...)		printk(a)
#else
#define ext_debug(a...)
#endif

/*
 * If EXT_STATS is defined then stats numbers are collected.
 * These number will be displayed at umount time.
 */
#define EXT_STATS_


/*
 * wpfs_inode has i_block array (60 bytes total).
 * The first 12 bytes store wpfs_extent_header;
 * the remainder stores an array of wpfs_extent.
 */

/*
 * This is the extent on-disk structure.
 * It's used at the bottom of the tree.
 */
struct wpfs_extent {
	__le32	ee_block;	/* first logical block extent covers */
	__le16	ee_len;		/* number of blocks covered by extent */
	__le16	ee_start_hi;	/* high 16 bits of physical block */
	__le32	ee_start_lo;	/* low 32 bits of physical block */
};

/*
 * This is index on-disk structure.
 * It's used at all the levels except the bottom.
 */
struct wpfs_extent_idx {
	__le32	ei_block;	/* index covers logical blocks from 'block' */
	__le32	ei_leaf_lo;	/* pointer to the physical block of the next *
				 * level. leaf or next index could be there */
	__le16	ei_leaf_hi;	/* high 16 bits of physical block */
	__u16	ei_unused;
};

/*
 * Each block (leaves and indexes), even inode-stored has header.
 */
struct wpfs_extent_header {
	__le16	eh_magic;	/* probably will support different formats */
	__le16	eh_entries;	/* number of valid entries */
	__le16	eh_max;		/* capacity of store in entries */
	__le16	eh_depth;	/* has tree real underlying blocks? */
	__le32	eh_generation;	/* generation of the tree */
};

#define WPFS_EXT_MAGIC		cpu_to_le16(0xf30a)

/*
 * Array of wpfs_ext_path contains path to some extent.
 * Creation/lookup routines use it for traversal/splitting/etc.
 * Truncate uses it to simulate recursive walking.
 */
struct wpfs_ext_path {
	wpfs_fsblk_t			p_block;
	__u16				p_depth;
	struct wpfs_extent		*p_ext;
	struct wpfs_extent_idx		*p_idx;
	struct wpfs_extent_header	*p_hdr;
	struct buffer_head		*p_bh;
};

/*
 * structure for external API
 */

#define EXT4_EXT_CACHE_NO	0
#define EXT4_EXT_CACHE_GAP	1
#define EXT4_EXT_CACHE_EXTENT	2

/*
 * to be called by wpfs_ext_walk_space()
 * negative retcode - error
 * positive retcode - signal for wpfs_ext_walk_space(), see below
 * callback must return valid extent (passed or newly created)
 */
typedef int (*ext_prepare_callback)(struct inode *, struct wpfs_ext_path *,
					struct wpfs_ext_cache *,
					struct wpfs_extent *, void *);

#define EXT_CONTINUE   0
#define EXT_BREAK      1
#define EXT_REPEAT     2

/* Maximum logical block in a file; wpfs_extent's ee_block is __le32 */
#define EXT_MAX_BLOCK	0xffffffff

/*
 * EXT_INIT_MAX_LEN is the maximum number of blocks we can have in an
 * initialized extent. This is 2^15 and not (2^16 - 1), since we use the
 * MSB of ee_len field in the extent datastructure to signify if this
 * particular extent is an initialized extent or an uninitialized (i.e.
 * preallocated).
 * EXT_UNINIT_MAX_LEN is the maximum number of blocks we can have in an
 * uninitialized extent.
 * If ee_len is <= 0x8000, it is an initialized extent. Otherwise, it is an
 * uninitialized one. In other words, if MSB of ee_len is set, it is an
 * uninitialized extent with only one special scenario when ee_len = 0x8000.
 * In this case we can not have an uninitialized extent of zero length and
 * thus we make it as a special case of initialized extent with 0x8000 length.
 * This way we get better extent-to-group alignment for initialized extents.
 * Hence, the maximum number of blocks we can have in an *initialized*
 * extent is 2^15 (32768) and in an *uninitialized* extent is 2^15-1 (32767).
 */
#define EXT_INIT_MAX_LEN	(1UL << 15)
#define EXT_UNINIT_MAX_LEN	(EXT_INIT_MAX_LEN - 1)


#define EXT_FIRST_EXTENT(__hdr__) \
	((struct wpfs_extent *) (((char *) (__hdr__)) +		\
				 sizeof(struct wpfs_extent_header)))
#define EXT_FIRST_INDEX(__hdr__) \
	((struct wpfs_extent_idx *) (((char *) (__hdr__)) +	\
				     sizeof(struct wpfs_extent_header)))
#define EXT_HAS_FREE_INDEX(__path__) \
	(le16_to_cpu((__path__)->p_hdr->eh_entries) \
				     < le16_to_cpu((__path__)->p_hdr->eh_max))
#define EXT_LAST_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_LAST_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_entries) - 1)
#define EXT_MAX_EXTENT(__hdr__) \
	(EXT_FIRST_EXTENT((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)
#define EXT_MAX_INDEX(__hdr__) \
	(EXT_FIRST_INDEX((__hdr__)) + le16_to_cpu((__hdr__)->eh_max) - 1)

static inline struct wpfs_extent_header *ext_inode_hdr(struct inode *inode)
{
	return (struct wpfs_extent_header *) WPFS_I(inode)->i_data;
}

static inline struct wpfs_extent_header *ext_block_hdr(struct buffer_head *bh)
{
	return (struct wpfs_extent_header *) bh->b_data;
}

static inline unsigned short ext_depth(struct inode *inode)
{
	return le16_to_cpu(ext_inode_hdr(inode)->eh_depth);
}

static inline void
wpfs_ext_invalidate_cache(struct inode *inode)
{
	WPFS_I(inode)->i_cached_extent.ec_type = EXT4_EXT_CACHE_NO;
}

static inline void wpfs_ext_mark_uninitialized(struct wpfs_extent *ext)
{
	/* We can not have an uninitialized extent of zero length! */
	BUG_ON((le16_to_cpu(ext->ee_len) & ~EXT_INIT_MAX_LEN) == 0);
	ext->ee_len |= cpu_to_le16(EXT_INIT_MAX_LEN);
}

static inline int wpfs_ext_is_uninitialized(struct wpfs_extent *ext)
{
	/* Extent with ee_len of 0x8000 is treated as an initialized extent */
	return (le16_to_cpu(ext->ee_len) > EXT_INIT_MAX_LEN);
}

static inline int wpfs_ext_get_actual_len(struct wpfs_extent *ext)
{
	return (le16_to_cpu(ext->ee_len) <= EXT_INIT_MAX_LEN ?
		le16_to_cpu(ext->ee_len) :
		(le16_to_cpu(ext->ee_len) - EXT_INIT_MAX_LEN));
}

static inline void wpfs_ext_mark_initialized(struct wpfs_extent *ext)
{
	ext->ee_len = cpu_to_le16(wpfs_ext_get_actual_len(ext));
}

extern int wpfs_ext_calc_metadata_amount(struct inode *inode,
					 sector_t lblocks);
extern wpfs_fsblk_t ext_pblock(struct wpfs_extent *ex);
extern wpfs_fsblk_t idx_pblock(struct wpfs_extent_idx *);
extern void wpfs_ext_store_pblock(struct wpfs_extent *, wpfs_fsblk_t);
extern int ext4_extent_tree_init(handle_t *, struct inode *);
extern int wpfs_ext_calc_credits_for_single_extent(struct inode *inode,
						   int num,
						   struct wpfs_ext_path *path);
extern int wpfs_can_extents_be_merged(struct inode *inode,
				      struct wpfs_extent *ex1,
				      struct wpfs_extent *ex2);
extern int wpfs_ext_try_to_merge(struct inode *inode,
				 struct wpfs_ext_path *path,
				 struct wpfs_extent *);
extern unsigned int wpfs_ext_check_overlap(struct inode *, struct wpfs_extent *, struct wpfs_ext_path *);
extern int wpfs_ext_insert_extent(handle_t *, struct inode *, struct wpfs_ext_path *, struct wpfs_extent *, int);
extern int wpfs_ext_walk_space(struct inode *, wpfs_lblk_t, wpfs_lblk_t,
							ext_prepare_callback, void *);
extern struct wpfs_ext_path *wpfs_ext_find_extent(struct inode *, wpfs_lblk_t,
							struct wpfs_ext_path *);
extern int wpfs_ext_search_left(struct inode *, struct wpfs_ext_path *,
						wpfs_lblk_t *, wpfs_fsblk_t *);
extern int wpfs_ext_search_right(struct inode *, struct wpfs_ext_path *,
						wpfs_lblk_t *, wpfs_fsblk_t *);
extern void wpfs_ext_drop_refs(struct wpfs_ext_path *);
extern int wpfs_ext_check_inode(struct inode *inode);
#endif /* _WPFS_EXTENTS */


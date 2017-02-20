/*
 * ext4_jbd2.h
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1998--1999 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Ext4-specific journaling extensions.
 */

#ifndef _WPFS_JBD2_H
#define _WPFS_JBD2_H

#include <linux/fs.h>
#include <linux/jbd2.h>
#include "wpfs.h"

#define WPFS_JOURNAL(inode)	(WPFS_SB((inode)->i_sb)->s_journal)

/* Define the number of blocks we need to account to a transaction to
 * modify one block of data.
 *
 * We may have to touch one inode, one bitmap buffer, up to three
 * indirection blocks, the group and superblock summaries, and the data
 * block to complete the transaction.
 *
 * For extents-enabled fs we may have to allocate and modify up to
 * 5 levels of tree + root which are stored in the inode. */

#define WPFS_SINGLEDATA_TRANS_BLOCKS(sb)				\
	(WPFS_HAS_INCOMPAT_FEATURE(sb, WPFS_FEATURE_INCOMPAT_EXTENTS)   \
	 ? 27U : 8U)

/* Extended attribute operations touch at most two data buffers,
 * two bitmap buffers, and two group summaries, in addition to the inode
 * and the superblock, which are already accounted for. */

#define WPFS_XATTR_TRANS_BLOCKS		6U

/* Define the minimum size for a transaction which modifies data.  This
 * needs to take into account the fact that we may end up modifying two
 * quota files too (one for the group, one for the user quota).  The
 * superblock only gets updated once, of course, so don't bother
 * counting that again for the quota updates. */

#define WPFS_DATA_TRANS_BLOCKS(sb)	(WPFS_SINGLEDATA_TRANS_BLOCKS(sb) + \
					 WPFS_XATTR_TRANS_BLOCKS - 2 + \
					 WPFS_MAXQUOTAS_TRANS_BLOCKS(sb))

/*
 * Define the number of metadata blocks we need to account to modify data.
 *
 * This include super block, inode block, quota blocks and xattr blocks
 */
#define WPFS_META_TRANS_BLOCKS(sb)	(WPFS_XATTR_TRANS_BLOCKS + \
					WPFS_MAXQUOTAS_TRANS_BLOCKS(sb))

/* Delete operations potentially hit one directory's namespace plus an
 * entire inode, plus arbitrary amounts of bitmap/indirection data.  Be
 * generous.  We can grow the delete transaction later if necessary. */

#define WPFS_DELETE_TRANS_BLOCKS(sb)	(2 * WPFS_DATA_TRANS_BLOCKS(sb) + 64)

/* Define an arbitrary limit for the amount of data we will anticipate
 * writing to any given transaction.  For unbounded transactions such as
 * write(2) and truncate(2) we can write more than this, but we always
 * start off at the maximum transaction size and grow the transaction
 * optimistically as we go. */

#define WPFS_MAX_TRANS_DATA		64U

/* We break up a large truncate or write transaction once the handle's
 * buffer credits gets this low, we need either to extend the
 * transaction or to start a new one.  Reserve enough space here for
 * inode, bitmap, superblock, group and indirection updates for at least
 * one block, plus two quota updates.  Quota allocations are not
 * needed. */

#define WPFS_RESERVE_TRANS_BLOCKS	12U

#define WPFS_INDEX_EXTRA_TRANS_BLOCKS	8

#ifdef CONFIG_QUOTA
/* Amount of blocks needed for quota update - we know that the structure was
 * allocated so we need to update only inode+data */
#define WPFS_QUOTA_TRANS_BLOCKS(sb) (test_opt(sb, QUOTA) ? 2 : 0)
/* Amount of blocks needed for quota insert/delete - we do some block writes
 * but inode, sb and group updates are done only once */
#define WPFS_QUOTA_INIT_BLOCKS(sb) (test_opt(sb, QUOTA) ? (DQUOT_INIT_ALLOC*\
		(WPFS_SINGLEDATA_TRANS_BLOCKS(sb)-3)+3+DQUOT_INIT_REWRITE) : 0)

#define WPFS_QUOTA_DEL_BLOCKS(sb) (test_opt(sb, QUOTA) ? (DQUOT_DEL_ALLOC*\
		(WPFS_SINGLEDATA_TRANS_BLOCKS(sb)-3)+3+DQUOT_DEL_REWRITE) : 0)
#else
#define WPFS_QUOTA_TRANS_BLOCKS(sb) 0
#define WPFS_QUOTA_INIT_BLOCKS(sb) 0
#define WPFS_QUOTA_DEL_BLOCKS(sb) 0
#endif
#define WPFS_MAXQUOTAS_TRANS_BLOCKS(sb) (MAXQUOTAS*WPFS_QUOTA_TRANS_BLOCKS(sb))
#define WPFS_MAXQUOTAS_INIT_BLOCKS(sb) (MAXQUOTAS*WPFS_QUOTA_INIT_BLOCKS(sb))
#define WPFS_MAXQUOTAS_DEL_BLOCKS(sb) (MAXQUOTAS*WPFS_QUOTA_DEL_BLOCKS(sb))

int
wpfs_mark_iloc_dirty(handle_t *handle,
		     struct inode *inode,
		     struct wpfs_iloc *iloc);

/*
 * On success, We end up with an outstanding reference count against
 * iloc->bh.  This _must_ be cleaned up later.
 */

int wpfs_reserve_inode_write(handle_t *handle, struct inode *inode,
			struct wpfs_iloc *iloc);

int wpfs_mark_inode_dirty(handle_t *handle, struct inode *inode);

/*
 * Wrapper functions with which ext4 calls into JBD.  The intent here is
 * to allow these to be turned into appropriate stubs so ext4 can control
 * ext2 filesystems, so ext2+ext4 systems only nee one fs.  This work hasn't
 * been done yet.
 */

void wpfs_journal_abort_handle(const char *caller, const char *err_fn,
		struct buffer_head *bh, handle_t *handle, int err);

int __wpfs_journal_get_undo_access(const char *where, handle_t *handle,
				struct buffer_head *bh);

int __wpfs_journal_get_write_access(const char *where, handle_t *handle,
				struct buffer_head *bh);

/* When called with an invalid handle, this will still do a put on the BH */
int __wpfs_journal_forget(const char *where, handle_t *handle,
				struct buffer_head *bh);

/* When called with an invalid handle, this will still do a put on the BH */
int __wpfs_journal_revoke(const char *where, handle_t *handle,
				wpfs_fsblk_t blocknr, struct buffer_head *bh);

int __wpfs_journal_get_create_access(const char *where,
				handle_t *handle, struct buffer_head *bh);

int __wpfs_handle_dirty_metadata(const char *where, handle_t *handle,
				 struct inode *inode, struct buffer_head *bh);

#define wpfs_journal_get_undo_access(handle, bh) \
	__wpfs_journal_get_undo_access(__func__, (handle), (bh))
#define wpfs_journal_get_write_access(handle, bh) \
	__wpfs_journal_get_write_access(__func__, (handle), (bh))
#define wpfs_journal_revoke(handle, blocknr, bh) \
	__wpfs_journal_revoke(__func__, (handle), (blocknr), (bh))
#define wpfs_journal_get_create_access(handle, bh) \
	__wpfs_journal_get_create_access(__func__, (handle), (bh))
#define wpfs_journal_forget(handle, bh) \
	__wpfs_journal_forget(__func__, (handle), (bh))
#define wpfs_handle_dirty_metadata(handle, inode, bh) \
	__wpfs_handle_dirty_metadata(__func__, (handle), (inode), (bh))

handle_t *wpfs_journal_start_sb(struct super_block *sb, int nblocks);
int __wpfs_journal_stop(const char *where, handle_t *handle);

#define WPFS_NOJOURNAL_MAX_REF_COUNT ((unsigned long) 4096)

/* Note:  Do not use this for NULL handles.  This is only to determine if
 * a properly allocated handle is using a journal or not. */
static inline int wpfs_handle_valid(handle_t *handle)
{
	if ((unsigned long)handle < WPFS_NOJOURNAL_MAX_REF_COUNT)
		return 0;
	return 1;
}

static inline void wpfs_handle_sync(handle_t *handle)
{
	if (wpfs_handle_valid(handle))
		handle->h_sync = 1;
}

static inline void wpfs_handle_release_buffer(handle_t *handle,
						struct buffer_head *bh)
{
	if (wpfs_handle_valid(handle))
		jbd2_journal_release_buffer(handle, bh);
}

static inline int wpfs_handle_is_aborted(handle_t *handle)
{
	if (wpfs_handle_valid(handle))
		return is_handle_aborted(handle);
	return 0;
}

static inline int wpfs_handle_has_enough_credits(handle_t *handle, int needed)
{
	if (wpfs_handle_valid(handle) && handle->h_buffer_credits < needed)
		return 0;
	return 1;
}

static inline void wpfs_journal_release_buffer(handle_t *handle,
						struct buffer_head *bh)
{
	if (wpfs_handle_valid(handle))
		jbd2_journal_release_buffer(handle, bh);
}

static inline handle_t *wpfs_journal_start(struct inode *inode, int nblocks)
{
	return wpfs_journal_start_sb(inode->i_sb, nblocks);
}

#define wpfs_journal_stop(handle) \
	__wpfs_journal_stop(__func__, (handle))

static inline handle_t *wpfs_journal_current_handle(void)
{
	return journal_current_handle();
}

static inline int wpfs_journal_extend(handle_t *handle, int nblocks)
{
	if (wpfs_handle_valid(handle))
		return jbd2_journal_extend(handle, nblocks);
	return 0;
}

static inline int wpfs_journal_restart(handle_t *handle, int nblocks)
{
	if (wpfs_handle_valid(handle))
		return jbd2_journal_restart(handle, nblocks);
	return 0;
}

static inline int wpfs_journal_blocks_per_page(struct inode *inode)
{
	if (WPFS_JOURNAL(inode) != NULL)
		return jbd2_journal_blocks_per_page(inode);
	return 0;
}

static inline int wpfs_journal_force_commit(journal_t *journal)
{
	if (journal)
		return jbd2_journal_force_commit(journal);
	return 0;
}

static inline int wpfs_jbd2_file_inode(handle_t *handle, struct inode *inode)
{
	if (wpfs_handle_valid(handle))
		return jbd2_journal_file_inode(handle, &WPFS_I(inode)->jinode);
	return 0;
}

static inline void wpfs_update_inode_fsync_trans(handle_t *handle,
						 struct inode *inode,
						 int datasync)
{
	struct ext4_inode_info *ei = WPFS_I(inode);

	if (wpfs_handle_valid(handle)) {
		ei->i_sync_tid = handle->h_transaction->t_tid;
		if (datasync)
			ei->i_datasync_tid = handle->h_transaction->t_tid;
	}
}

/* super.c */
int wpfs_force_commit(struct super_block *sb);

static inline int wpfs_should_journal_data(struct inode *inode)
{
	if (WPFS_JOURNAL(inode) == NULL)
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 1;
	if (test_opt(inode->i_sb, DATA_FLAGS) == WPFS_MOUNT_JOURNAL_DATA)
		return 1;
	if (WPFS_I(inode)->i_flags & WPFS_JOURNAL_DATA_FL)
		return 1;
	return 0;
}

static inline int wpfs_should_order_data(struct inode *inode)
{
	if (WPFS_JOURNAL(inode) == NULL)
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;
	if (WPFS_I(inode)->i_flags & WPFS_JOURNAL_DATA_FL)
		return 0;
	if (test_opt(inode->i_sb, DATA_FLAGS) == WPFS_MOUNT_ORDERED_DATA)
		return 1;
	return 0;
}

static inline int wpfs_should_writeback_data(struct inode *inode)
{
	if (!S_ISREG(inode->i_mode))
		return 0;
	if (WPFS_JOURNAL(inode) == NULL)
		return 1;
	if (WPFS_I(inode)->i_flags & WPFS_JOURNAL_DATA_FL)
		return 0;
	if (test_opt(inode->i_sb, DATA_FLAGS) == WPFS_MOUNT_WRITEBACK_DATA)
		return 1;
	return 0;
}

#endif	/* _WPFS_JBD2_H */

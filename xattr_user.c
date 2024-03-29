/*
 * linux/fs/ext4/xattr_user.c
 * Handler for extended user attributes.
 *
 * Copyright (C) 2001 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include "wpfs_jbd2.h"
#include "wpfs.h"
#include "xattr.h"

static size_t
wpfs_xattr_user_list(struct inode *inode, char *list, size_t list_size,
		     const char *name, size_t name_len)
{
	const size_t prefix_len = XATTR_USER_PREFIX_LEN;
	const size_t total_len = prefix_len + name_len + 1;

	if (!test_opt(inode->i_sb, XATTR_USER))
		return 0;

	if (list && total_len <= list_size) {
		memcpy(list, XATTR_USER_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
wpfs_xattr_user_get(struct inode *inode, const char *name,
		    void *buffer, size_t size)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return wpfs_xattr_get(inode, WPFS_XATTR_INDEX_USER, name, buffer, size);
}

static int
wpfs_xattr_user_set(struct inode *inode, const char *name,
		    const void *value, size_t size, int flags)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	if (!test_opt(inode->i_sb, XATTR_USER))
		return -EOPNOTSUPP;
	return wpfs_xattr_set(inode, WPFS_XATTR_INDEX_USER, name,
			      value, size, flags);
}

struct xattr_handler wpfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= wpfs_xattr_user_list,
	.get	= wpfs_xattr_user_get,
	.set	= wpfs_xattr_user_set,
};

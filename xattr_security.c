/*
 * linux/fs/ext4/xattr_security.c
 * Handler for storing security labels as extended attributes.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/security.h>
#include "wpfs_jbd2.h"
#include "wpfs.h"
#include "xattr.h"

static size_t
wpfs_xattr_security_list(struct inode *inode, char *list, size_t list_size,
			 const char *name, size_t name_len)
{
	const size_t prefix_len = sizeof(XATTR_SECURITY_PREFIX)-1;
	const size_t total_len = prefix_len + name_len + 1;


	if (list && total_len <= list_size) {
		memcpy(list, XATTR_SECURITY_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
wpfs_xattr_security_get(struct inode *inode, const char *name,
		       void *buffer, size_t size)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return wpfs_xattr_get(inode, WPFS_XATTR_INDEX_SECURITY, name,
			      buffer, size);
}

static int
wpfs_xattr_security_set(struct inode *inode, const char *name,
		       const void *value, size_t size, int flags)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return wpfs_xattr_set(inode, WPFS_XATTR_INDEX_SECURITY, name,
			      value, size, flags);
}

int
wpfs_init_security(handle_t *handle, struct inode *inode, struct inode *dir)
{
	int err;
	size_t len;
	void *value;
	char *name;

	err = security_inode_init_security(inode, dir, &name, &value, &len);
	if (err) {
		if (err == -EOPNOTSUPP)
			return 0;
		return err;
	}
	err = wpfs_xattr_set_handle(handle, inode, WPFS_XATTR_INDEX_SECURITY,
				    name, value, len, 0);
	kfree(name);
	kfree(value);
	return err;
}

struct xattr_handler wpfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.list	= wpfs_xattr_security_list,
	.get	= wpfs_xattr_security_get,
	.set	= wpfs_xattr_security_set,
};

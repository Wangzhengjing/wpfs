/*
  File: fs/ext4/acl.h

  (C) 2001 Andreas Gruenbacher, <a.gruenbacher@computer.org>
*/

#include <linux/posix_acl_xattr.h>

#define EXT4_ACL_VERSION	0x0001

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} wpfs_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} wpfs_acl_entry_short;

typedef struct {
	__le32		a_version;
} wpfs_acl_header;

static inline size_t wpfs_acl_size(int count)
{
	if (count <= 4) {
		return sizeof(wpfs_acl_header) +
		       count * sizeof(wpfs_acl_entry_short);
	} else {
		return sizeof(wpfs_acl_header) +
		       4 * sizeof(wpfs_acl_entry_short) +
		       (count - 4) * sizeof(wpfs_acl_entry);
	}
}

static inline int wpfs_acl_count(size_t size)
{
	ssize_t s;
	size -= sizeof(wpfs_acl_header);
	s = size - 4 * sizeof(wpfs_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(wpfs_acl_entry_short))
			return -1;
		return size / sizeof(wpfs_acl_entry_short);
	} else {
		if (s % sizeof(wpfs_acl_entry))
			return -1;
		return s / sizeof(wpfs_acl_entry) + 4;
	}
}

#ifdef CONFIG_EXT4_FS_POSIX_ACL

/* acl.c */
extern int wpfs_check_acl(struct inode *, int);
extern int wpfs_acl_chmod(struct inode *);
extern int wpfs_init_acl(handle_t *, struct inode *, struct inode *);

#else  /* CONFIG_EXT4_FS_POSIX_ACL */
#include <linux/sched.h>
#define wpfs_check_acl NULL

static inline int
wpfs_acl_chmod(struct inode *inode)
{
	return 0;
}

static inline int
wpfs_init_acl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	return 0;
}
#endif  /* CONFIG_EXT4_FS_POSIX_ACL */


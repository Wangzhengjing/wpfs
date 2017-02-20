#obj-m := balloc.o bitmap.o dir.o file.o fsync.o ialloc.o inode.o \
#		ioctl.o namei.o super.o symlink.o hash.o resize.o extents.o \
#		wpfs_jbd2.o migrate.o mballoc.o block_validity.o move_extent.o
obj-m := wpfs.o
wpfs-objs := balloc.o bitmap.o dir.o file.o fsync.o ialloc.o inode.o \
               ioctl.o namei.o super.o symlink.o hash.o resize.o extents.o \
               wpfs_jbd2.o migrate.o mballoc.o block_validity.o move_extent.o\
		acl.o dir.o xattr.o xattr_security.o xattr_trusted.o xattr_user.o

KBUILD_EXPORT_SYMBOLS += /root/rpmbuild/SOURCES/linux-2.6.32-71.7.1.el6/Module.symvers
export KBUILD_EXPORT_SYMBOLS

KERN_PATH = /root/rpmbuild/SOURCES/linux-2.6.32-71.7.1.el6

all:
	make -C $(KERN_PATH) M=$(PWD) modules

clean:	
	make -C $(KERN_PATH) M=$(PWD) clean

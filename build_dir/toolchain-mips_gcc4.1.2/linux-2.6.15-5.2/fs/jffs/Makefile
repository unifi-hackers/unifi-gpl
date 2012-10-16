#
# Makefile for the linux Journalling Flash FileSystem (JFFS) routines.
#
# $Id: //depot/sw/releases/7.3_AP/linux/kernels/mips-linux-2.6.15/fs/jffs/Makefile#1 $
#

obj-$(CONFIG_JFFS_FS) += jffs.o

jffs-y 				:= jffs_fm.o intrep.o inode-v23.o
jffs-$(CONFIG_JFFS_PROC_FS)	+= jffs_proc.o
jffs-objs			:= $(jffs-y)

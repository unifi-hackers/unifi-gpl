#
# Makefile for nf-hipac on top of IPv4.
#

obj-$(CONFIG_IP_NF_HIPAC) += nf_hipac.o
nf_hipac-objs := ihash.o global.o rlp.o dimtree.o hipac.o nfhp_dev.o nfhp_proc.o nfhp_mod.o

ifdef CONFIG_IP_NF_HIPAC
ifeq ($(CONFIG_IP_NF_CONNTRACK),m)
obj-m += nf_hipac_cthelp.o
EXTRA_CFLAGS += -D CONNTRACK_MODULE
endif
endif

ifdef CONFIG_IP_NF_HIPAC_SINGLE_PATH
EXTRA_CFLAGS += -D SINGLE_PATH
endif

ifneq ($(ARCH), alpha)
ifneq ($(ARCH), ia64)
ifneq ($(ARCH), ppc64)
ifneq ($(ARCH), s390x)
ifneq ($(ARCH), sh64)
ifneq ($(ARCH), sparc64)
ifneq ($(ARCH), x86_64)
EXTRA_CFLAGS += -D BIT32_ARCH
endif
endif
endif
endif
endif
endif
endif

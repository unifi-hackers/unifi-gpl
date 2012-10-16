# vim:set sw=8 nosta:

BINS=hotplug2 hotplug2-dnode
SUBDIRS=linux24_compat docs examples
DESTDIR=


all: $(BINS)

install:
	$(INSTALL_BIN) $(BINS) $(DESTDIR)/sbin/


hotplug2: hotplug2.o hotplug2_utils.o childlist.o mem_utils.o rules.o filemap_utils.o
hotplug2-dnode: hotplug2-dnode.o hotplug2_utils.o mem_utils.o parser_utils.o


include common.mak

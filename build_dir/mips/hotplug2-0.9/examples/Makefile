# vim:set sw=8 nosta:

BINS=
SUBDIRS=
DESTDIR=
KERNELVER=`uname -r`


all:

install:
	if ! [ -e "/etc/hotplug2.rules" ]; then \
		case "$(KERNELVER)" in \
			2.6.*) \
			$(INSTALL) hotplug2.rules-2.6kernel $(DESTDIR)/etc/hotplug2.rules \
			;; \
			*) \
			$(INSTALL) hotplug2.rules-2.4kernel $(DESTDIR)/etc/hotplug2.rules \
			;; \
		esac; \
	fi;


include ../common.mak
MAKEDEP:=

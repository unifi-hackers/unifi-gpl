# Makefile for udev extra invoked from the udev main Makefile
#
# Copyright (C) 2004-2005 Kay Sievers <kay.sievers@vrfy.org>
#
# Released under the GNU General Public License, version 2.
#
PROG = udev_run_devd udev_run_hotplugd
OBJS = run_directory.o
HEADERS =
GEN_HEADERS =
MAN_PAGES =

prefix =
etcdir =	${prefix}/etc
sbindir =	${prefix}/sbin
usrbindir =	${prefix}/usr/bin
usrsbindir =	${prefix}/usr/sbin
libudevdir =	${prefix}/lib/udev
mandir =	${prefix}/usr/share/man
configdir =	${etcdir}/udev/

INSTALL = install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL}

all: $(PROG) $(MAN_PAGES)
.PHONY: all
.DEFAULT: all

%.o: %.c $(GEN_HEADERS)
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

$(PROG): %: $(HEADERS) %.o $(OBJS)
	$(E) "  LD      " $@
	$(Q) $(LD) $(LDFLAGS) $@.o $(OBJS) -o $@ $(LIBUDEV) $(LIB_OBJS)

# man pages
%.8: %.xml
	$(E) "  XMLTO   " $@
	$(Q) xmlto man $?
.PRECIOUS: %.8

clean:
	$(E) "  CLEAN   "
	$(Q) rm -f $(PROG) $(OBJS) $(GEN_HEADERS)
.PHONY: clean

install-bin: all
	$(INSTALL_PROGRAM) -D udev_run_devd $(DESTDIR)$(libudevdir)/udev_run_devd
	$(INSTALL_PROGRAM) -D udev_run_hotplugd $(DESTDIR)$(libudevdir)/udev_run_hotplugd
.PHONY: install-bin

uninstall-bin:
	- rm $(DESTDIR)$(libudevdir)/udev_run_devd
	- rm $(DESTDIR)$(libudevdir)/udev_run_hotplugd
.PHONY: uninstall-bin

install-man:
	@echo "Please create a man page for this tool."
.PHONY: install-man

uninstall-man:
	@echo "Please create a man page for this tool."
.PHONY: uninstall-man

install-config:
	@echo "no config file to install"
.PHONY: install-config

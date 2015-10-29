allgoals = all clean install check  clean-local

.PHONY: $(allgoals) $(allgoals:%=%-subdir)
export DESTDIR prefix bindir datarootdir datadir sysconfdir
export CC CFLAGS CXXFLAGS CPPFLAGS LDFLAGS

DESTDIR ?=
ifneq ($(DESTDIR),)
  override DESTDIR:=$(abspath $(DESTDIR))
endif
$(warning DESTDIR=$(DESTDIR))
export DESTDIR

sysconfdir = /etc
localstatedir = /var
prefix = /usr
bindir = $(prefix)/bin
sbindir = $(prefix)/sbin
datarootdir = ${prefix}/share
docrootdir = ${prefix}/share/doc
datadir = ${datarootdir}/kyoscand
docdir = ${docrootdir}/kyoscand
mandir = ${datarootdir}/man
spooldir = $(localstatedir)/spool
systemdsystemunitdir = /lib/systemd/system

SUBDIRS=src

all: all-subdir systemd/kyoscand.service

install: all install-subdir
	install -m 0755 -d $(DESTDIR)$(bindir)
	install -m 0755 -t $(DESTDIR)$(bindir) scripts/kyoscan
	install -m 0755 -d $(DESTDIR)$(sysconfdir)/init.d
	install -m 0755 -t $(DESTDIR)$(sysconfdir)/init.d etc/kyoscand.rc
	install -m 0755 -d $(DESTDIR)$(docdir)
	install -m 0644 -t $(DESTDIR)$(docdir) README COPYING
	install -m 0755 -d $(DESTDIR)$(mandir)/man1
	install -m 0644 -t $(DESTDIR)$(mandir)/man1 doc/kyoscand.1
	rm -f $(DESTDIR)$(mandir)/man1/kyoscand.1.gz
	gzip $(DESTDIR)$(mandir)/man1/kyoscand.1
	install -m 0755 -d $(DESTDIR)$(spooldir)/kyoscand
	install -m 0755 -d $(DESTDIR)$(systemdsystemunitdir)
	install -m 0644 -t $(DESTDIR)$(systemdsystemunitdir) systemd/kyoscand.service

clean: clean-subdir clean-local

clean-local:
	rm -f systemd/kyoscand.service

systemd/kyoscand.service: systemd/kyoscand.service.in
	mkdir -p systemd
	rm -f $@.tmp $@
	sed -e 's![@]bindir[@]!$(bindir)!g' \
	    -e 's![@]sbindir[@]!$(sbindir)!g' \
	    -e 's![@]sysconfdir[@]!$(sysconfdir)!g' \
	    $< > $@.tmp
	mv $@.tmp $@

check:

$(allgoals:%=%-subdir):
	@$(foreach subdir,$(SUBDIRS), \
	  $(MAKE) -C $(subdir) $(MAKEARGS) DESTDIR=$(DESTDIR) $(@:%-subdir=%) || exit 1 ; \
	)

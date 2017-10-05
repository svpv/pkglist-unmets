RPM_OPT_FLAGS ?= -O2 -g -Wall
all: pkglist-unmets
pkglist-unmets: unmets.c
	$(CC) $(RPM_OPT_FLAGS) -fwhole-program -o $@ $< -lrpm{,io}
ALT = /ALT
PKGLIST = $(ALT)/Sisyphus/x86_64/base/pkglist.classic.xz
apt.list: $(PKGLIST)
	echo 'rpm file:$(PKGLIST)' | \
	perl -pe 's#/([^/]+)/base/pkglist\.([^.]+).*# $$1 $$2#' >sources.list
	unmets -s sources.list |perl -pe 's/ .*//; s/#/ /' |sort -u >$@
	rm sources.list
my.list: $(PKGLIST) pkglist-unmets
	xz -d <$(PKGLIST) |./pkglist-unmets | \
	perl -pe 's/ /#/; s/ .*//; s/#/ /' |sort -u >$@
check: apt.list my.list
	[ -s $< ]
	diff -U1 $^

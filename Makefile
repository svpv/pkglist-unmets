RPM_OPT_FLAGS ?= -O2 -g -Wall
all: pkglist-unmets
pkglist-unmets: unmets.c
	$(CC) $(RPM_OPT_FLAGS) -fwhole-program -o $@ $< -lrpm{,io} -lzpkglist
ALT = /ALT
PKGLIST = $(ALT)/Sisyphus/x86_64/base/pkglist.classic.xz
req.list.1: $(PKGLIST)
	xzcat $(PKGLIST) | pkglist-query \
	'[%{Name} %{Version}-%{Release}\t%{RequireName} %{RequireFlags:depflags} %{RequireVersion}\n]' - | \
	sort -r |perl -lne 'print unless s/ +$$/ / && index($$lastline,$$_)==0; $$lastline=$$_' | \
	perl -pe 's/ *$$//' |sort -u >$@
req.list.2: $(PKGLIST) pkglist-unmets
	./pkglist-unmets --dump-requires $(PKGLIST) | \
	perl -pe 's/ /#/; s/#\d+:/ / || s/#/ /' |sort -u >$@
prov.list.1: $(PKGLIST)
	xzcat $(PKGLIST) | pkglist-query \
	'[%{ProvideName} %{ProvideFlags:depflags} %{ProvideVersion}\n][%{FILENAMES}\n]' - | \
	perl -pe 's/ *$$//' |sort -u >$@
prov.list.2: $(PKGLIST) pkglist-unmets
	./pkglist-unmets --dump-provides $(PKGLIST) | \
	perl -ne 'print unless /^rpmlib[(]/' |sort -u >$@
unmets.list.1: $(PKGLIST)
	echo 'rpm file:$(PKGLIST)' | \
	perl -pe 's#/([^/]+)/base/pkglist\.([^.]+).*# $$1 $$2#' >sources.list
	unmets -s sources.list |perl -pe 's/ .*//; s/#/ /' |sort -u >$@
	rm sources.list
unmets.list.2: $(PKGLIST) pkglist-unmets
	./pkglist-unmets $(PKGLIST) | \
	perl -pe 's/ /#/; s/ .*//; s/#/ /' |sort -u >$@
DIFF = diff -U1
check: req.list.1 req.list.2 prov.list.1 prov.list.2 unmets.list.1 unmets.list.2
	[ -s req.list.1 ] && $(DIFF) req.list.{1,2}
	[ -s prov.list.1 ] && $(DIFF) prov.list.{1,2}
	[ -s unmets.list.1 ] && $(DIFF) unmets.list.{1,2}

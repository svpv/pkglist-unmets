RPM_OPT_FLAGS ?= -O2 -g -Wall
all: pkglist-unmets
pkglist-unmets: unmets.c
	$(CC) $(RPM_OPT_FLAGS) -fwhole-program -o $@ $< -lrpm{,io}

if WITH_SERVER
xlator_LTLIBRARIES = haystack.la
endif
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/storage

haystack_la_LDFLAGS = -module $(GF_XLATOR_DEFAULT_LDFLAGS)

haystack_la_SOURCES = hs.c hs-ctx.c hs-inode-fd-ops.c hs-entry-ops.c hs-helpers.c
haystack_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la $(ZLIB_LIBS)

noinst_HEADERS = hs.h hs-ctx.h hs-messages.h hs-mem-types.h khash.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src -DHSDUMP $(LIBZ_CFLAGS) \
    -I$(top_srcdir)/rpc/xdr/src -I$(top_builddir)/rpc/xdr/src \
    -I$(top_srcdir)/rpc/rpc-lib/src

AM_CFLAGS = -fno-strict-aliasing -Wall $(GF_CFLAGS) -I$(top_srcdir)/glusterfsd/src

CLEANFILES =


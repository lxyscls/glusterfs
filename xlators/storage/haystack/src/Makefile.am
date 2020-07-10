if WITH_SERVER
xlator_LTLIBRARIES = haystack.la
endif
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/storage

haystack_la_LDFLAGS = -module $(GF_XLATOR_DEFAULT_LDFLAGS)

haystack_la_SOURCES = hs.c hs-ctx.c
haystack_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la

noinst_HEADERS = hs.h hs-messages.h hs-mem-types.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src -DHSDEBUG

AM_CFLAGS = -fno-strict-aliasing -Wall $(GF_CFLAGS) -I$(top_srcdir)/glusterfsd/src

CLEANFILES =


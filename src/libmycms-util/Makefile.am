include $(top_srcdir)/build/ltrc.inc

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)
DISTCLEANFILES = \
	libmycms-util.pc \
	$(NULL)
CLEANFILES = \
	mycms-util-all.exports \
	mycms-util-all.exports.tmp \
	$(NULL)

MYCMS_UTIL_COMMON_EXPORTS = \
	mycms-util-getpass.exports \
	$(NULL)
MYCMS_UTIL_SELECTIVE_EXPORTS = \
	$(NULL)

dist_noinst_DATA = \
	$(MYCMS_UTIL_COMMON_EXPORTS) \
	$(MYCMS_UTIL_SELECTIVE_EXPORTS) \
	$(NULL)

pkgconfig_DATA = libmycms-util.pc
noinst_LTLIBRARIES = libmycms-util-internal.la
lib_LTLIBRARIES = libmycms-util.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	$(NULL)

libmycms_util_internal_la_SOURCES = \
	mycms-util-getpass.c \
	$(NULL)
nodist_libmycms_util_internal_la_SOURCES = \
	$(NULL)
if ENABLE_PINENTRY
libmycms_util_internal_la_SOURCES += \
	mycms-util-pinentry.c \
	mycms-util-pinentry.h \
	$(NULL)
endif
libmycms_util_internal_la_LIBADD = \
	$(builddir)/../libmycms/libmycms.la \
	$(NULL)

libmycms_util_la_DEPENDENCIES = \
	libmycms-util-internal.la \
	mycms-util-all.exports \
	$(NULL)
if BUILD_WINDOWS
nodist_libmycms_util_la_SOURCES = \
	versioninfo.rc \
	$(NULL)
endif
libmycms_util_la_LIBADD = \
	libmycms-util-internal.la \
	$(NULL)
libmycms_util_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-version-info @LIBMYCMS_LT_CURRENT@:@LIBMYCMS_LT_REVISION@:@LIBMYCMS_LT_AGE@ \
	-export-symbols "mycms-util-all.exports" \
	-no-undefined \
	$(NULL)

mycms-util-all.exports: \
		$(MYCMS_UTIL_COMMON_EXPORTS) \
		$(MYCMS_UTIL_SELECTIVE_EXPORTS) \
		$(builddir)/Makefile \
		$(top_builddir)/config.h \
		$(NULL)
	rm -f mycms-util-all.exports.tmp
	for f in $(MYCMS_UTIL_COMMON_EXPORTS); do \
		cat "$(srcdir)/$$f" >> mycms-util-all.exports.tmp; \
	done
	mv mycms-util-all.exports.tmp mycms-util-all.exports

if BUILD_WINDOWS
mylibdir=$(libdir)
mylib_DATA=.libs/libmycms-util-@LIBMYCMS_LT_OLDEST@.dll.def
.libs/libmycms-util-@LIBMYCMS_LT_OLDEST@.dll.def:        libmycms-util.la
endif

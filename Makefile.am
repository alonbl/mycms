AUTOMAKE_OPTIONS = foreign dist-bzip2 1.10
ACLOCAL_AMFLAGS = -I m4 --install

#@AM_DISTCHECK_CONFIGURE_FLAGS-BEGIN
AM_DISTCHECK_CONFIGURE_FLAGS = \
	--enable-certificate-driver-file \
	--enable-certificate-driver-pkcs11 \
	--enable-cms-decrypt \
	--enable-cms-encrypt \
	--enable-cms-sign \
	--enable-cms-verify \
	--enable-io-driver-file \
	--enable-openssl-err-strings \
	--enable-pedantic \
	--enable-pinentry \
	--enable-strict \
	--enable-tests \
	--enable-tool \
	$(NULL)
#@AM_DISTCHECK_CONFIGURE_FLAGS-END

MAINTAINERCLEANFILES = \
	config.log config.status \
	$(srcdir)/Makefile.in \
	$(srcdir)/config.h.in $(srcdir)/config.h.in~ $(srcdir)/configure \
	$(srcdir)/install-sh $(srcdir)/ltmain.sh $(srcdir)/missing \
	$(srcdir)/depcomp $(srcdir)/compile $(srcdir)/aclocal.m4 \
	$(srcdir)/test-driver \
	$(srcdir)/config.guess $(srcdir)/config.sub \
	$(srcdir)/m4/ltsugar.m4 $(srcdir)/m4/libtool.m4 \
	$(srcdir)/m4/ltversion.m4 $(srcdir)/m4/lt~obsolete.m4 \
	$(srcdir)/m4/ltoptions.m4 $(srcdir)/m4/pkg.m4 \
	$(NULL)

EXTRA_DIST = \
	.gitignore \
	$(NULL)

SUBDIRS = \
	build \
	include \
	packaging \
	src \
	$(NULL)
if ENABLE_TESTS
SUBDIRS += \
	test \
	$(NULL)
endif

dist_doc_DATA = \
	$(NULL)

dist_noinst_DATA = \
	INSTALL.md \
	$(NULL)

dist_noinst_SCRIPTS = \
	conf-dev.sh \
	wsl-fixup-libtool-argv0.patch \
	wsl-fixup-wsl1-skip-env.patch \
	$(NULL)

if BUILD_WINDOWS
rootdir=$(prefix)
root_DATA = \
	package.info \
	$(NULL)
dist_doc_DATA += \
	COPYING \
	README.md \
	$(NULL)
else
dist_noinst_DATA += \
	COPYING \
	README.md \
	$(NULL)
endif

MAINTAINERCLEANFILES = \
	$(srcdir)/Makefile.in \
	$(NULL)

clean-local:
	rm -fr rootca.pki built.rootca
	rm -fr subca.pki built.subca

check-local: 	\
		built.rootca	\
		built.subca \
		$(NULL)

dist_noinst_SCRIPTS = \
	issue.sh \
	$(NULL)

dist_noinst_DATA = \
	oids.cnf \
	x509-types/COMMON \
	x509-types/ca \
	x509-types/encrypt \
	x509-types/sign \
	$(NULL)

built.rootca:	\
		oids.cnf \
		$(NULL)
	rm -rf built.rootca rootca.pki
	$(EASYRSA) --pki-dir=rootca.pki init-pki
	cp rootca.vars rootca.pki/vars
	touch rootca.pki/.rnd
	$(EASYRSA) --pki-dir=rootca.pki build-ca nopass
	touch built.rootca

built.subca:	\
		built.rootca \
		oids.cnf \
		$(NULL)
	rm -rf built.subca subca.pki
	$(EASYRSA) --pki-dir=subca.pki init-pki
	cp subca.vars subca.pki/vars
	touch subca.pki/.rnd

	cat "$(srcdir)/oids.cnf" >> subca.pki/openssl-easyrsa.cnf
	sed -i '1i oid_section = oids' subca.pki/openssl-easyrsa.cnf

	$(EASYRSA) --pki-dir=subca.pki build-ca nopass subca
	$(EASYRSA) --pki-dir=rootca.pki import-req ./subca.pki/reqs/ca.req subca
	$(EASYRSA) --pki-dir=rootca.pki sign-req ca subca
	cp ./rootca.pki/issued/subca.crt ./subca.pki/ca.crt
	touch built.subca

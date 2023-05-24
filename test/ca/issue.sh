#!/bin/sh

abs_builddir="${abs_builddir:-$(dirname "$0")}"
. "${abs_builddir}/ca-vars"

die() {
	local m="$1"
	echo "FATAL: ${m}" >&2
	exit 1
}

TEMPLATE="$1"; shift
NAME="$1"; shift
CERT="$1"; shift
KEY="$1"; shift

"${EASYRSA}" --pki-dir="${abs_builddir}/subca.pki" gen-req "${NAME}" nopass || die "req"
"${EASYRSA}" --pki-dir="${abs_builddir}/subca.pki" --subject-alt-name="URI:test:${NAME}" sign-req "${TEMPLATE}" "${NAME}" nopass || die "sign"

"${OPENSSL}" x509 -in "${abs_builddir}/subca.pki/issued/${NAME}.crt" -inform PEM -out "${CERT}" -outform DER || die "export.cert"
"${OPENSSL}" pkcs8 -in "${abs_builddir}/subca.pki/private/${NAME}.key" -inform PEM -out "${KEY}" -outform DER -nocrypt || die "export.key"

exit 0

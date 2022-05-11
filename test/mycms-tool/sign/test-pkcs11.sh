#!/bin/sh

srcdir="${srcdir:-.}"
builddir="${builddir:-${srcdir}}"
MYCMS_TOOL="${MYCMS_TOOL:-mycms-tool}"
SOFTHSM2_UTIL="${SOFTHSM2_UTIL:-softhsm2-util}"
PKCS11_TOOL="${PKCS11_TOOL:-pkcs11-tool}"
OPENSSL="${OPENSSL:-openssl}"
VALGRIND="${VALGRIND:-valgrind}"
LIBTOOL="${LIBTOOL:-libtool}"

VALGRIND_CMD="${VALGRIND_CMD:-"${LIBTOOL}" --mode=execute ${VALGRIND}}"

die() {
	local m="$1"
	echo "FATAL: ${m}" >&2
	exit 1
}

skip() {
	local m="$1"
	echo "SKIP: ${m}" >&2
	exit 77
}

MYTMP=
cleanup() {
	rm -fr "${MYTMP}"
}
trap cleanup 0

doval() {
	if [ "${MYCMS_DO_VALGRIND}" = 1 ]; then
		${VALGRIND_CMD} -q --leak-check=full --leak-resolution=high --show-leak-kinds=all --error-exitcode=99 --suppressions="${srcdir}/test-pkcs11.valgrind.supp" "$@"
	else
		"$@"
	fi
}

get_keyid() {
	local cert="$1"

	"${OPENSSL}" x509 -noout -in "$1" -inform DER -ext subjectKeyIdentifier |
		sed -e '1d' -e 's/ //g' -e 's/://g'
}

prepare_token() {
	"${SOFTHSM2_UTIL}" --init-token --free --label token1 --so-pin sosecret --pin secret || die "init-token"
	for o in 1 2 3; do
if [ -n "${__MYCMS_USE_CERTUTIL}" ]; then
		local k="${MYTMP}/k"
		local c="${MYTMP}/c"
		openssl pkcs8 -topk8 -inform DER -in "${builddir}/gen/test${o}.key" -out "${k}" -nocrypt || die "openssl.p8"
		openssl x509 -inform DER -in "${builddir}/gen/test${o}.crt" -out "${c}" || die "openssl.crt"
		"${SOFTHSM2_UTIL}" \
			--import "${MYTMP}/k" \
			--import-type=keypair \
			--token token1 \
			--id $(printf "%02x" ${o}) \
			--label test${o} \
			--pin secret \
			|| die "softhsm.import.key.${o}"
		"${SOFTHSM2_UTIL}" \
			--import "${MYTMP}/c" \
			--import-type=cert \
			--token token1 \
			--id $(printf "%02x" ${o}) \
			--label test${o} \
			--pin secret \
			|| die "softhsm.import.cert.${o}"
else
		"${PKCS11_TOOL}" \
			--module "${SOFTHSM2_MODULE}" \
			--token-label token1 \
			--login \
			--pin secret \
			--private \
			--id ${o} \
			--label test${o} \
			--type privkey \
			--usage-sign \
			--write-object "${builddir}/gen/test${o}.key" \
			|| die "pkcs11-tool.key.${o}"
		"${PKCS11_TOOL}" \
			--module "${SOFTHSM2_MODULE}" \
			--token-label token1 \
			--login \
			--pin secret \
			--id ${o} \
			--label test${o} \
			--type cert \
			--write-object "${builddir}/gen/test${o}.crt" \
			|| die "pkcs11-tool.crt.${o}"
fi
	done
}

test_sanity() {
	local PREFIX="${MYTMP}/sanity"
	local CMS="${PREFIX}-cms"
	local BADDATA="${PREFIX}-baddata"
	local out
	local test1_keyid
	local test2_keyid

	cp "${DATA}" "${BADDATA}"
	echo 1 >> "${BADDATA}"

	test1_keyid="$(get_keyid "${builddir}/gen/test1.crt")" || die "test1.keyid"

	echo "Signing by test1"
	doval "${MYCMS_TOOL}" sign \
		--cms-out="${CMS}" \
		--data-in="${DATA}" \
		--signer-cert="pkcs11:module=${SOFTHSM2_MODULE}:token-label=token1:cert-label=test1" \
		--signer-cert-pass="token=pass=secret" \
		|| die "sanity.sign.test1"

	echo "List signers test1"
	out="$(doval "${MYCMS_TOOL}" verify-list \
		--cms-in="${CMS}" \
		)" || die "sanity.verify-list '${out}'"

	keyid="$(get_keyid "${builddir}/gen/test1.crt")" || die "test1.keyid"

	[ "$(echo "${out}" | wc -l)" = 1 ] || die "Too many keys '${out}'"
	echo "${out}" | grep -iq "^${test1_keyid} SHA3-256$" || die "Keyid mismatch expected '${test1_keyid}' actual '${out}'"

	echo "Verify signature"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS}" \
		--data-in="${DATA}" \
		--cert="${builddir}/gen/test1.crt" \
		)" || die "sanity.verify.test1"

	[ "${out}" = "VERIFIED" ] || die "sanity.verify.result '${out}'"

	echo "Verify signature wrong signer"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS}" \
		--data-in="${DATA}" \
		--cert="${builddir}/gen/test2.crt" \
		)" || die "sanity.verify.wrong"

	[ "${out}" = "VERIFIED" ] && die "sanity.verify.wrong.result '${out}'"

	echo "Verify signature with bad data"
	out="$(doval "${MYCMS_TOOL}" verify \
		--cms-in="${CMS}" \
		--data-in="${BADDATA}" \
		--cert="${builddir}/gen/test1.crt" \
		)" || die "sanity.verify.bad"

	[ "${out}" = "VERIFIED" ] && die "sanity.verify.bad.result '${out}'"

	return 0
}

[ -x "${MYCMS_TOOL}" ] || skip "no tool"
features="$("${MYCMS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "sign" || skip "sign feature is not available"
echo "${features}" | grep -q "verify" || skip "verify feature is not available"
echo "${features}" | grep -q "certificate-driver-pkcs11" || skip "certificate-driver-pkcs11 feature is not available"

"${SOFTHSM2_UTIL}" --version > /dev/null || skip "softhsm2-util not found"
"${PKCS11_TOOL}" --version 2>&1 | grep -q "Usage:" || skip "pkcs11-tool not found"

[ -z "${SOFTHSM2_MODULE}" ] && die "Cannot find softhsm module"

MYTMP="$(mktemp -d)"
DATA="${MYTMP}/data"
dd if=/dev/urandom bs=512 count=20 of="${DATA}" status=none || die "dd plain"

tokendir="${MYTMP}/token"
mkdir -p "${tokendir}"
sed "s#@TOKENDIR@#${tokendir}#" "${srcdir}/softhsm2.conf.in" > "${MYTMP}/softhsm2.conf"
export SOFTHSM2_CONF="${MYTMP}/softhsm2.conf"

prepare_token

TESTS="${TESTS:-test_sanity}"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done

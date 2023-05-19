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

prepare_token() {
	"${SOFTHSM2_UTIL}" --init-token --free --label token1 --so-pin sosecret --pin secret || die "init-token"
	for o in 1 2 3 4 5; do
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
			--usage-decrypt \
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
	local CT="${PREFIX}-ct"
	local OUTPT="${PREFIX}-pt"

	echo "Encrypting to test1"
	doval "${MYCMS_TOOL}" encrypt \
		--cms-out="${CMS}" \
		--data-pt="${PT}" \
		--data-ct="${CT}" \
		--to="${builddir}/gen/test1.crt" \
		|| die "sanity.encrypt"
	echo "Decrypting by test1"
	doval "${MYCMS_TOOL}" decrypt \
		--cms-in="${CMS}" \
		--recip-cert="pkcs11:module=${SOFTHSM2_MODULE}:token-label=token1:cert-label=test1" \
		--recip-cert-pass="token=pass=secret" \
		--data-pt="${OUTPT}" \
		--data-ct="${CT}" \
		|| die "sanity.decrypt"

	cmp -s "${PT}" "${CT}" && die "sanity.cmp.ct"
	cmp -s "${PT}" "${OUTPT}" || die "sanity.cmp"

	return 0
}

test_add_recepients() {
	local PREFIX="${MYTMP}/addrecip"
	local CMS1="${PREFIX}-cms1"
	local CMS2="${PREFIX}-cms2"
	local CT="${PREFIX}-ct1"
	local OUTPT="${PREFIX}-pt"

	echo "Encrypting to test1 and test2"
	doval "${MYCMS_TOOL}" encrypt \
		--cms-out="${CMS1}" \
		--data-pt="${PT}" \
		--data-ct="${CT}" \
		--to="${builddir}/gen/test1.crt" \
		--to="${builddir}/gen/test2.crt" \
		|| die "add-recip.encrypt"

	echo "Adding to test3 and test4 using test1"
	doval "${MYCMS_TOOL}" encrypt-add \
		--cms-in="${CMS1}" \
		--cms-out="${CMS2}" \
		--recip-cert="pkcs11:module=${SOFTHSM2_MODULE}:token-label=token1:cert-label=test1" \
		--recip-cert-pass="token=pass=secret" \
		--to="${builddir}/gen/test3.crt" \
		--to="${builddir}/gen/test4.crt" \
		|| die "add-recip.encrypt"

	local x
	for x in test1 test2 test3 test4; do
		echo "Decrypting by '${x}'"
		doval "${MYCMS_TOOL}" decrypt \
			--cms-in="${CMS2}" \
			--recip-cert="pkcs11:module=${SOFTHSM2_MODULE}:token-label=token1:cert-label=${x}" \
			--recip-cert-pass="token=pass=secret" \
			--data-pt="${OUTPT}-${x}" \
			--data-ct="${CT}" \
			|| die "add-recip.decrypt.${x}"
		cmp -s "${PT}" "${OUTPT}-${x}" || die "sanity.cmp"
	done

	return 0
}

[ -x "${MYCMS_TOOL}" ] || skip "no tool"
features="$("${MYCMS_TOOL}" --version | grep "Features")" || die "Cannot execute tool"
echo "${features}" | grep -q "sane" || die "tool is insane"
echo "${features}" | grep -q "encrypt" || skip "encrypt feature is not available"
echo "${features}" | grep -q "decrypt" || skip "decrypt feature is not available"
echo "${features}" | grep -q "certificate-driver-pkcs11" || skip "certificate-driver-pkcs11 feature is not available"

"${SOFTHSM2_UTIL}" --version > /dev/null || skip "softhsm2-util not found"
"${PKCS11_TOOL}" --version 2>&1 | grep -q "Usage:" || skip "pkcs11-tool not found"

[ -z "${SOFTHSM2_MODULE}" ] && die "Cannot find softhsm module"

MYTMP="$(mktemp -d)"
PT="${MYTMP}/pt"
dd if=/dev/urandom bs=512 count=20 of="${PT}" status=none || die "dd plain"

tokendir="${MYTMP}/token"
mkdir -p "${tokendir}"
sed "s#@TOKENDIR@#${tokendir}#" "${srcdir}/softhsm2.conf.in" > "${MYTMP}/softhsm2.conf"
export SOFTHSM2_CONF="${MYTMP}/softhsm2.conf"

prepare_token

TESTS="${TESTS:-test_sanity test_add_recepients}"

for test in $TESTS; do
	echo "------------------------"
	echo "${test}"
	echo "------------------------"
	"${test}"
done

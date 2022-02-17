#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/cms.h>

#include <mycms/mycms-system-driver-core.h>
#include <mycms/mycms.h>

#include "mycms-certificate-private.h"
#include "mycms-error-internal.h"
#include "mycms-io-private.h"
#include "mycms-openssl.h"

bool
mycms_decrypt(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_io cms_in,
	const mycms_io data_pt,
	const mycms_io data_ct
) {
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED;
	bool ret = false;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (certificate == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.decrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate is mandatory"
		));
		goto cleanup;
	}

	if (cms_in == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.decrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS input is mandatory"
		));
		goto cleanup;
	}

	if (data_pt == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.decrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Plaintext data is mandatory"
		));
		goto cleanup;
	}

	if (data_ct == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.decrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Ciphertext data is mandatory"
		));
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.decrypt.bio",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to parse CMS"
		)));
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, _mycms_certificate_get_EVP_PKEY(certificate), _mycms_certificate_get_X509(certificate))) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.decrypt.key",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to set private key for CMS"
		)));
		goto cleanup;
	}

	if (!CMS_decrypt(cms, NULL, NULL, _mycms_io_get_BIO(data_ct), _mycms_io_get_BIO(data_pt), flags)) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.decrypt.decrypt",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to decrypt CMS"
		)));
		goto cleanup;
	}

	ret = true;

cleanup:

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

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
mycms_sign(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_list_str digests,
	const mycms_list_str keyopts,
	const mycms_io cms_in,
	const mycms_io cms_out,
	const mycms_io data_in
) {
	CMS_ContentInfo *cms = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	mycms_list_str digest;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_USE_KEYID | CMS_NOCERTS | CMS_NOSMIMECAP;
	bool ret = false;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (certificate == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.sign.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate is mandatory"
		));
		goto cleanup;
	}

	if (cms_in == NULL) {
		flags |= CMS_PARTIAL;
		if ((cms = CMS_sign(NULL, NULL, NULL, NULL, flags)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.sign.init",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to initiate CMS sign"
			)));
			goto cleanup;
		}
	} else {
		if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.sign.init",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to deserialize CMS"
			)));
			goto cleanup;
		}
	}

	if (data_in == NULL) {
		flags |= CMS_REUSE_DIGEST;
	}

	for (digest = digests;digest != NULL; digest = digest->next) {
		const EVP_MD *md = NULL;
		CMS_SignerInfo *signer = NULL;

		if ((md = EVP_get_digestbyname(digest->str)) == NULL) {
			_mycms_error_entry_dispatch(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.sign.algo",
				MYCMS_ERROR_CODE_ARGS,
				true,
				"Failed to resolve digest '%s'",
				digest->str
			));
			goto cleanup;
		}

		if ((signer = CMS_add1_signer(
			cms,
			_mycms_certificate_get_X509(certificate),
			_mycms_certificate_get_EVP_PKEY(certificate),
			md,
			flags | (keyopts == NULL ? 0 : CMS_KEY_PARAM) /* Does not work for 2nd sign, see https://github.com/openssl/openssl/issues/14257 */
		)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.sign.add",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to add signer"
			)));
			goto cleanup;
		}

		if (keyopts != NULL) { /* TODO: remove when openssl bug fixed */
			mycms_list_str keyopt;

			if ((ctx = CMS_SignerInfo_get0_pkey_ctx(signer)) == NULL) {
				_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
					"core.sign.add.prm",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Failed to resolve signer key"
				)));
				goto cleanup;
			}

			for (keyopt = keyopts;keyopt != NULL; keyopt = keyopt->next) {
				char opt[1024];
				char *p;
				strncpy(opt, keyopt->str, sizeof(opt));
				opt[sizeof(opt) - 1] = '\0';
				if ((p = strchr(opt, ':')) == NULL) {
					_mycms_error_entry_dispatch(_mycms_error_entry_base(
						_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
						"core.sign.keyopt",
						MYCMS_ERROR_CODE_ARGS,
						true,
						"Invalid keyopts '%s' no separator",
						opt
					));
					goto cleanup;
				}
				*p = '\0';
				p++;

				if (!EVP_PKEY_CTX_ctrl_str(ctx, opt, p)) {
					_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
						_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
						"core.sign.add.keyopt",
						MYCMS_ERROR_CODE_CRYPTO,
						true,
						"Failed to set signer key parameters"
					)));
					goto cleanup;
				}
			}
		}
	}

	if (cms_in != NULL) {
		if (!i2d_CMS_bio_stream(_mycms_io_get_BIO(cms_out), cms, _mycms_io_get_BIO(data_in), flags)) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.sign.out",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to serialize CMS (redo)"
			)));
			goto cleanup;
		}
	} else {
		if (!CMS_final(cms, _mycms_io_get_BIO(data_in), NULL, flags)) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.sign.out",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"CMS serialization final"
			)));
			goto cleanup;
		}
		if (i2d_CMS_bio(_mycms_io_get_BIO(cms_out), cms) <= 0) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.sign.out",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"CMS serialization write"
			)));
			goto cleanup;
		}
	}

	ret = true;

cleanup:

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

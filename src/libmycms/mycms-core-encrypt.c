#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/cms.h>
#include <openssl/x509.h>

#include <mycms/mycms-system-driver-core.h>
#include <mycms/mycms.h>

#include "mycms-certificate-private.h"
#include "mycms-error-internal.h"
#include "mycms-io-private.h"
#include "mycms-openssl.h"

static
STACK_OF(CMS_RecipientInfo) *
__add_recipients(
	const mycms mycms,
	CMS_ContentInfo *cms,
	const mycms_list_blob to,
	const mycms_list_str keyopts,
	int flags
) {
	STACK_OF(CMS_RecipientInfo) *ret = NULL;
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	X509 *x509 = NULL;
	mycms_list_blob t;

	if ((added = sk_CMS_RecipientInfo_new_null()) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.add.rcpt",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to create recipient info"
		)));
		goto cleanup;
	}

	for (t = to;t != NULL;t = t->next) {
		CMS_RecipientInfo *ri;
		EVP_PKEY_CTX *ctx;
		mycms_list_str keyopt;
		unsigned const char * p;

		p = t->blob.data;
		if ((x509 = d2i_X509(NULL, &p, t->blob.size)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.encrypt.add.cert",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to parse certificate"
			)));
			goto cleanup;
		}

		if ((ri = CMS_add1_recipient_cert(cms, x509, flags | CMS_KEY_PARAM)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.encrypt.add.cert",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to add certificate as recipient"
			)));
			goto cleanup;
		}

		X509_free(x509);
		x509 = NULL;

		if ((ctx = CMS_RecipientInfo_get0_pkey_ctx(ri)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.encrypt.add.prms",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to get key context"
			)));
			goto cleanup;
		}

		for (keyopt = keyopts; keyopt != NULL; keyopt = keyopt->next) {
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
					"core.encrypt.add.prms",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Failed to get key parameters"
				)));
				goto cleanup;
			}
		}

		sk_CMS_RecipientInfo_push(added, ri);
	}

	ret = added;
	added = NULL;

cleanup:
	X509_free(x509);
	x509 = NULL;

	sk_CMS_RecipientInfo_free(added);
	added = NULL;

	return ret;
}

bool
mycms_encrypt(
	const mycms mycms,
	const char * const cipher_name,
	const mycms_list_blob to,
	const mycms_list_str keyopts,
	const mycms_io cms_out,
	const mycms_io data_pt,
	const mycms_io data_ct
) {
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	const EVP_CIPHER *c = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;
	bool ret = false;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (cipher_name == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Cipher name is mandatory"
		));
		goto cleanup;
	}

	if (to == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Recipient name is mandatory"
		));
		goto cleanup;
	}

	if (cms_out == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS out is mandatory"
		));
		goto cleanup;
	}

	if (data_pt == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Plaintext data is mandatory"
		));
		goto cleanup;
	}

	if (data_ct == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Ciphertext data is mandatory"
		));
		goto cleanup;
	}

	if ((c = EVP_get_cipherbyname(cipher_name)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Cannot resolve cipher '%s'",
			cipher_name
		));
		goto cleanup;
	}

	if ((cms = CMS_encrypt(NULL, NULL, c, flags)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.encrypt",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"CMS encrypt failed"
		)));
		goto cleanup;
	}

	if ((added = __add_recipients(mycms, cms, to, keyopts, flags)) == NULL) {
		goto cleanup;
	}

	if (!CMS_final(cms, _mycms_io_get_BIO(data_pt), _mycms_io_get_BIO(data_ct), flags)) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.encrypt",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"CMS final failed"
		)));
		goto cleanup;
	}

	if (i2d_CMS_bio(_mycms_io_get_BIO(cms_out), cms)  <= 0) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt.encrypt",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"CMS serialization failed"
		)));
		goto cleanup;
	}

	ret = true;

cleanup:

	sk_CMS_RecipientInfo_free(added);
	added = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

bool
mycms_encrypt_add(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_list_blob to,
	const mycms_list_str keyopts,
	const mycms_io cms_in,
	const mycms_io cms_out
) {
	STACK_OF(CMS_RecipientInfo) *added = NULL;
	CMS_ContentInfo *cms = NULL;
	int flags = CMS_BINARY | CMS_DETACHED | CMS_PARTIAL | CMS_USE_KEYID;
	bool ret = false;
	int i;

	if (mycms == NULL) {
		goto cleanup;
	}

	if (certificate == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-add.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate is mandatory"
		));
		goto cleanup;
	}

	if (to == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-add.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Recipient is mandatory"
		));
		goto cleanup;
	}

	if (cms_in == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-add.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS input is mandatory"
		));
		goto cleanup;
	}

	if (cms_out == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-add.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS output is mandatory"
		));
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-add.bio",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"CMS deserialization failed"
		)));
		goto cleanup;
	}

	if (!CMS_decrypt_set1_pkey(cms, _mycms_certificate_get_EVP_PKEY(certificate), _mycms_certificate_get_X509(certificate))) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-add.bio",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"CMS set key failed"
		)));
		goto cleanup;
	}

	if ((added = __add_recipients(mycms, cms, to, keyopts, flags)) == NULL) {
		goto cleanup;
	}

	for (i = 0; i < sk_CMS_RecipientInfo_num(added); i++) {
		CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(added, i);

		if (!CMS_RecipientInfo_encrypt(cms, ri)) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.encrypt-add.encrypt",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"CMS recipient encryption failed"
			)));
			goto cleanup;
		}
	}

	if (i2d_CMS_bio(_mycms_io_get_BIO(cms_out), cms)  <= 0) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-add.out",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"CMS serialization failed"
		)));
		goto cleanup;
	}

	ret = true;

cleanup:

/* https://github.com/openssl/openssl/issues/21026 */
#if (0x030000000l <= OPENSSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER <= 0x030000090l) || (0x030100000l <= OPENSSL_VERSION_NUMBER && OPENSSL_VERSION_NUMBER <= 0x030100010l)
	BIO_free_all(CMS_dataInit(cms, NULL));
#endif
	sk_CMS_RecipientInfo_free(added);
	added = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

bool
mycms_encrypt_reset(
	const mycms mycms,
	const mycms_list_blob to,
	const mycms_io cms_in,
	const mycms_io cms_out
) {
	mycms_list_blob t;
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_RecipientInfo) *recps = NULL;
	STACK_OF(CMS_RecipientInfo) *stash = NULL;
	STACK_OF(X509) *certs = NULL;
	bool ret = false;
	int i;


	if (mycms == NULL) {
		goto cleanup;
	}

	if (to == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Recipient is mandatory"
		));
		goto cleanup;
	}

	if (cms_in == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS input is mandatory"
		));
		goto cleanup;
	}

	if (cms_out == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS output is mandatory"
		));
		goto cleanup;
	}

	if ((stash = sk_CMS_RecipientInfo_new_null()) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.init",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to allocate recipient info stack"
		)));
		goto cleanup;
	}

	if ((certs = sk_X509_new_null()) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.init",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to allocate certificate stack"
		)));
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.in",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to deserialize CMS"
		)));
		goto cleanup;
	}

	if ((recps = CMS_get0_RecipientInfos(cms)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.rcpt",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to get recipients out of CMS"
		)));
		goto cleanup;
	}

	for (t = to;t != NULL;t = t->next) {
		X509 *x509;
		unsigned const char * p;

		p = t->blob.data;
		if ((x509 = d2i_X509(NULL, &p, t->blob.size)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.encrypt-reset.cert",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to parse recipient certificate"
			)));
			goto cleanup;
		}

		sk_X509_push(certs, x509);
	}

	for (i = 0; i < sk_CMS_RecipientInfo_num(recps); ) {
		CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(recps, i);
		bool found = false;
		int j;

		for (j = 0;  j < sk_X509_num(certs); j++) {
			X509 *x509 = sk_X509_value(certs, j);

			if (CMS_RecipientInfo_ktri_cert_cmp(ri, x509) == 0) {
				found = true;
				break;
			}
		}

		if (found) {
			i++;
		} else {
			sk_CMS_RecipientInfo_push(stash, sk_CMS_RecipientInfo_delete(recps, i));
		}
	}

	if (i2d_CMS_bio(_mycms_io_get_BIO(cms_out), cms)  <= 0) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.encrypt-reset.out",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to serialize CMS"
		)));
		goto cleanup;
	}

	ret = true;

cleanup:

	/*
	 * HACK-BEGIN:
	 * There is no way to directly free CMS_RecipientInfo so reapply these to CMS_ContentInfo.
	 */
	for (i = 0; i < sk_CMS_RecipientInfo_num(stash); i++) {
		CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(stash, i);
		sk_CMS_RecipientInfo_push(recps, ri);
	}
	/* HACK-END */

	sk_CMS_RecipientInfo_free(stash);

	sk_X509_pop_free(certs, X509_free);

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

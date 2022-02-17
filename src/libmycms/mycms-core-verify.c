#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/cms.h>

#include <mycms/mycms-system-driver-core.h>
#include <mycms/mycms.h>

#include "mycms-error-internal.h"
#include "mycms-io-private.h"
#include "mycms-openssl.h"

struct internal_signer_s {
	X509 *x509;
	ASN1_OBJECT *digest;
	bool found;
};
MYCMS_LIST_DECLARE(internal_signer, struct internal_signer_s, signer)

static
void
__internal_signer_free(
	mycms_system system,
	const mycms_list_internal_signer l
) {
	mycms_list_internal_signer _l = l;
	while (_l != NULL) {
		mycms_list_internal_signer t = _l;
		_l = _l->next;

		X509_free(t->signer.x509);
		t->signer.x509 = NULL;
		ASN1_OBJECT_free(t->signer.digest);
		t->signer.digest = NULL;
		mycms_system_free(system, "signer", t);
	}
}

static
mycms_list_internal_signer
__mycms_list_signer_to_internal(
	mycms_system system,
	const mycms_list_signer l
) {
	mycms_list_signer e;
	mycms_list_internal_signer ret = NULL;
	mycms_list_internal_signer signers = NULL;

	for (e = l;e != NULL;e = e->next) {
		mycms_list_internal_signer t;
		unsigned const char * p;

		if ((t = mycms_system_zalloc(system, "signer", sizeof(*t))) == NULL) {
			goto cleanup;
		}
		t->next = signers;
		signers = t;

		p = e->signer.cert.data;
		if ((t->signer.x509 = d2i_X509(NULL, &p, e->signer.cert.size)) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"core.verify.list",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot parse signer certificate"
			)));
			goto cleanup;
		}

		if (e->signer.digest != NULL) {
			if ((t->signer.digest = OBJ_txt2obj(e->signer.digest, 0)) == NULL) {
				_mycms_error_entry_dispatch(_mycms_error_entry_base(
					_mycms_error_capture(mycms_system_get_error(system)),
					"core.verify.list",
					MYCMS_ERROR_CODE_ARGS,
					true,
					"Cannot resolve signer digest"
				));
				goto cleanup;
			}
		}
	}

	ret = signers;
	signers = NULL;

cleanup:

	__internal_signer_free(system, signers);
	signers = NULL;

	return ret;
}

bool
mycms_verify_list_free(
	const mycms mycms,
	const mycms_list_signer l
) {
	mycms_system system = NULL;
	mycms_list_signer t;
	bool ret = false;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		goto cleanup;
	}

	t = l;
	while(t != NULL) {
		mycms_list_signer x = t;
		t = x->next;
		mycms_system_free(system, "signer.keyid", x->signer.keyid.data);
		mycms_system_free(system, "signer.digest", x->signer.digest);
		mycms_system_free(system, "signer", x);
	}

	ret = true;

cleanup:

	return ret;
}

bool
mycms_verify_list(
	const mycms mycms,
	const mycms_io cms_in,
	mycms_list_signer * const signers
) {
	mycms_system system = NULL;
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_SignerInfo) *signerids = NULL;
	mycms_list_signer _signers = NULL;
	int i;
	bool ret = false;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify-list.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Cannot get system context"
		));
		goto cleanup;
	}

	if (cms_in == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify-list.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS input is mandatory"
		));
		goto cleanup;
	}

	if (signers == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify-list.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Signers are mandatory"
		));
		goto cleanup;
	}

	*signers = NULL;

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify-list.list",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"CMS deserialization failed"
		)));
		goto cleanup;
	}

	if ((signerids = CMS_get0_SignerInfos(cms)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify-list.list",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot get signers out of CMS"
		)));
		goto cleanup;
	}

	for (i = 0; i < sk_CMS_SignerInfo_num(signerids); i++) {
		CMS_SignerInfo *signer = sk_CMS_SignerInfo_value(signerids, i);
		ASN1_OCTET_STRING *keyid = NULL;

		if (CMS_SignerInfo_get0_signer_id(signer, &keyid, NULL, NULL)) {
			mycms_list_signer t = NULL;
			X509_ALGOR *dig = NULL;
			char digest[256];

			if ((t = mycms_system_zalloc(system, "signer", sizeof(*t))) == NULL) {
				goto cleanup;
			}

			t->next = _signers;
			_signers = t;

			t->signer.keyid.size = keyid->length;
			if ((t->signer.keyid.data = mycms_system_zalloc(system, "signer.keyid", t->signer.keyid.size)) == NULL) {
				goto cleanup;
			}
			memcpy(t->signer.keyid.data, keyid->data, t->signer.keyid.size);

			CMS_SignerInfo_get0_algs(signer, NULL, NULL, &dig, NULL);
			if (!OBJ_obj2txt(digest, sizeof(digest), dig->algorithm, 0)) {
				_mycms_error_entry_dispatch(_mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
					"core.verify-list.do",
					MYCMS_ERROR_CODE_ARGS,
					true,
					"Cannot resolve signer algorithm"
				));
				goto cleanup;
			}
			t->signer.digest = mycms_system_strdup(system, "signer.digest", digest);
		}
	}

	*signers = _signers;
	_signers = NULL;

	ret = true;

cleanup:

	mycms_verify_list_free(mycms, _signers);
	_signers = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

bool
mycms_verify(
	const mycms mycms,
	mycms_io cms_in,
	mycms_io data_in,
	const mycms_list_signer signers,
	bool * const verified
) {
#if 0
	const int flags = CMS_DETACHED | CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_CONTENT_VERIFY;
	CMS_verify(cms, _certs, NULL, _mycms_io_get_BIO(data_in), NULL, flags);
#endif
	mycms_system system = NULL;
	mycms_list_internal_signer isigners = NULL;
	mycms_list_internal_signer isigners_i = NULL;
	CMS_ContentInfo *cms = NULL;
	STACK_OF(CMS_SignerInfo) *signerids = NULL;
	BIO *cmsbio = NULL;
	unsigned char buf[4096];
	bool ret = false;

	if (mycms == NULL) {
		goto cleanup;
	}

	if ((system = mycms_get_system(mycms)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Cannot get system context"
		));
		goto cleanup;
	}

	if (cms_in == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"CMS input is mandatory"
		));
		goto cleanup;
	}

	if (data_in == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Data input is mandatory"
		));
		goto cleanup;
	}

	if (verified == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.args",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Verified flag is mandatory"
		));
		goto cleanup;
	}

	*verified = false;

	if ((isigners = __mycms_list_signer_to_internal(system, signers)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.list",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot get signers out of CMS"
		)));
		goto cleanup;
	}

	if ((cms = d2i_CMS_bio(_mycms_io_get_BIO(cms_in), NULL)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.in",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot deserialize CMS"
		)));
		goto cleanup;
	}

	if ((signerids = CMS_get0_SignerInfos(cms)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.in",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot get signers out of the CMS"
		)));
		goto cleanup;
	}

	if (sk_CMS_SignerInfo_num(signerids) <= 0) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.in",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"No signers"
		)));
		goto cleanup;
	}

	/*
	 * Do not use CMS_verify:
	 * 1. It iterates all certificates and verify signature (resources)
	 * 2. It must have access to all signer certificates
         */
	if ((cmsbio = CMS_dataInit(cms, _mycms_io_get_BIO(data_in))) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
			"core.verify.do",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot initialize CMS data input"
		)));
		goto cleanup;
	}

	{
		/*
		 * Run through input and update digest
		 */
		int x;
		while ((x = BIO_read(cmsbio, buf, sizeof(buf))) > 0);
		if (x < 0) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
				"core.verify.do",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot read CMS data"
			)));
			goto cleanup;
		}
	}

	ret = true;

	for (isigners_i = isigners; isigners_i != NULL; isigners_i = isigners_i->next) {
		int i;
		for (i = 0; i < sk_CMS_SignerInfo_num(signerids); i++) {
			CMS_SignerInfo *signer = sk_CMS_SignerInfo_value(signerids, i);

			if (!CMS_SignerInfo_cert_cmp(signer, isigners_i->signer.x509)) {
				X509_ALGOR *dig = NULL;

				CMS_SignerInfo_get0_algs(signer, NULL, NULL, &dig, NULL);

				if (isigners_i->signer.digest == NULL || OBJ_cmp(dig->algorithm, isigners_i->signer.digest) == 0) {
					if (CMS_SignerInfo_verify_content(signer, cmsbio) <= 0) {
						_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
							_mycms_error_capture(mycms_context_get_error(mycms_get_context(mycms))),
							"core.verify.do",
							MYCMS_ERROR_CODE_CRYPTO,
							true,
							"Verify failed"
						)));
						goto cleanup;
					}
					isigners_i->signer.found = true;
				}
			}
		}
	}

	*verified = true;
	for (isigners_i = isigners; isigners_i != NULL; isigners_i = isigners_i->next) {
		*verified = *verified && isigners_i->signer.found;
	}

cleanup:

	__internal_signer_free(system, isigners);
	isigners = NULL;

	{
		BIO *tbio;
		do {
			tbio = BIO_pop(cmsbio);
			BIO_free(cmsbio);
			cmsbio = tbio;
		} while (cmsbio != NULL && cmsbio != _mycms_io_get_BIO(data_in));
	}
	cmsbio = NULL;

	CMS_ContentInfo_free(cms);
	cms = NULL;

	return ret;
}

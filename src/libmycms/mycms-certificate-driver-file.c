#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms/mycms-certificate-driver-file.h>

#include "mycms-error-internal.h"
#include "mycms-openssl.h"

struct __mycms_certificate_driver_file_s {
#ifndef OPENSSL_NO_RSA
	RSA *rsa;
#endif
};
typedef struct __mycms_certificate_driver_file_s *__mycms_certificate_driver_file;

static int __convert_padding(const int padding) {
	int ret;
	switch (padding) {
#ifndef OPENSSL_NO_RSA
		case MYCMS_PADDING_PKCS1:
			ret = RSA_PKCS1_PADDING;
		break;
		case MYCMS_PADDING_OEAP:
			ret = RSA_PKCS1_OAEP_PADDING;
		break;
		case MYCMS_PADDING_NONE:
			ret = RSA_NO_PADDING;
		break;
#endif
		default:
			ret = -1;
		break;
	}
	return ret;
}

static
mycms_system
__get_system(
	const mycms_certificate certificate
) {
	mycms_context context = NULL;

	if ((context = mycms_certificate_get_context(certificate)) == NULL) {
		return NULL;
	}

	return mycms_context_get_system(context);
}

static
EVP_PKEY *
__driver_load_pkey(
	const mycms_certificate certificate,
	const char *file
) {
	EVP_PKEY *k = NULL;
	BIO *bio = NULL;

	if (file == NULL) {
		goto cleanup;
	}

	if ((bio = BIO_new_file(file, "rb")) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load.pkey",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot open private key file '%s'",
			file
		)));
		goto cleanup;
	}

	if ((k = d2i_PrivateKey_bio(bio, NULL)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load.pkey",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot parse private key from file '%s'",
			file
		)));
		goto cleanup;
	}

cleanup:

	BIO_free(bio);
	bio = NULL;

	return k;
}

#ifndef OPENSSL_NO_RSA
static
int
__driver_rsa_private_op(
	const mycms_certificate certificate,
	const int op,
	const unsigned char * const from,
	const size_t from_size,
	unsigned char * const to,
	const size_t to_size,
	const int padding
) {
	__mycms_certificate_driver_file certificate_file = NULL;
	const RSA_METHOD *rsa_method = NULL;
	int cpadding;
	int ret = -1;

	if ((certificate_file = (__mycms_certificate_driver_file)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	if (from == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.op.from",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"From buffer must not be null"
		));
		goto cleanup;
	}

	if (to == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.op.to",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"To buffer must not be null"
		));
		goto cleanup;
	}

	if (from_size == 0) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.op.from_size",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"From size must be greater than zero"
		));
		goto cleanup;
	}

	if (to_size < from_size) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.op.from_size",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"To size must be greater than from (%ld>=%ld)",
			to_size,
			from_size
		));
		goto cleanup;
	}

	if ((cpadding = __convert_padding(padding)) == -1) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.op.padding",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Invalid padding %d",
			padding
		));
		goto cleanup;
	}

	if ((rsa_method = RSA_get_method(certificate_file->rsa)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.op",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot get RSA method"
		)));
		goto cleanup;
	}

	switch (op) {
		default:
			_mycms_error_entry_dispatch(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
				"certificate.driver.file.op.type",
				MYCMS_ERROR_CODE_ARGS,
				true,
				"Invalid op type %d",
				op
			));
			goto cleanup;
		case MYCMS_PRIVATE_OP_ENCRYPT:
			ret = RSA_meth_get_priv_enc(rsa_method)(from_size, from, to, certificate_file->rsa, cpadding);
		break;
		case MYCMS_PRIVATE_OP_DECRYPT:
			ret = RSA_meth_get_priv_dec(rsa_method)(from_size, from, to, certificate_file->rsa, cpadding);
		break;
	}

cleanup:

	return ret;
}
#endif

static
bool
__driver_free(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_file certificate_file;
	bool ret = false;

	if ((system = __get_system(certificate)) == NULL) {
		return false;
	}

	if ((certificate_file = (__mycms_certificate_driver_file)mycms_certificate_get_driverdata(certificate)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.free",
			MYCMS_ERROR_CODE_ARGS,
			false,
			"No context"
		));
		goto cleanup;
	}

#ifndef OPENSSL_NO_RSA
	RSA_free(certificate_file->rsa);
	certificate_file->rsa = NULL;
#endif

	if (!mycms_system_free(system, "ccertificate_file", certificate_file)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

static
bool
__driver_load(
	const mycms_certificate certificate,
	const mycms_dict parameters
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_file certificate_file = NULL;

	EVP_PKEY *evp = NULL;
	BIO *bio_in = NULL;
	BIO *bio_out = NULL;

	const char *cert_file;
	const char *key_file;
	mycms_blob blob;
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (parameters == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Parameters must be provided"
		));
		goto cleanup;
	}

	if ((system = __get_system(certificate)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Cannot get system context"
		));
		goto cleanup;
	}

	if ((cert_file = mycms_dict_entry_get(parameters, "cert", NULL)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"No cert attribute in parameters"
		));
		goto cleanup;
	}

	if ((key_file = mycms_dict_entry_get(parameters, "key", NULL)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"No key attribute in parameters"
		));
		goto cleanup;
	}

	if ((bio_in = BIO_new_file(cert_file, "rb")) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot open certificate file '%s'",
			cert_file
		)));
		goto cleanup;
	}

	if ((bio_out = BIO_new(BIO_s_mem())) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.file.load.cert",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot allocate cache BIO"
		)));
		goto cleanup;
	}

	{
		unsigned char buffer[1024];
		int n;

		while ((n = BIO_read(bio_in, buffer, sizeof(buffer))) > 0) {
			if (BIO_write(bio_out, buffer, n) != n) {
				_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
					"certificate.driver.file.load.cert",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Cannot write to cache BIO"
				)));
				goto cleanup;
			}
		}
		if (n != 0) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
				"certificate.driver.file.load.cert",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot read certificate file '%s'",
				cert_file
			)));
			goto cleanup;
		}
	}

	blob.size = BIO_get_mem_data(bio_out, &blob.data);

	if ((evp = __driver_load_pkey(certificate, key_file)) == NULL) {
		goto cleanup;
	}

	if ((certificate_file = mycms_system_zalloc(system, "certificate_file", sizeof(*certificate_file))) == NULL) {
		goto cleanup;
	}

	switch (EVP_PKEY_id(evp)) {
		default:
			_mycms_error_entry_dispatch(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
				"certificate.driver.file.load.type",
				MYCMS_ERROR_CODE_ARGS,
				true,
				"Unsupported key type %d",
				EVP_PKEY_id(evp)
			));
			goto cleanup;
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			if ((certificate_file->rsa = EVP_PKEY_get1_RSA(evp)) == NULL) {
				_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
					"certificate.driver.file.load.rsa",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Cannot get RSA out of certificate"
				)));
				goto cleanup;
			}
		break;
#endif
	}

	if (!mycms_certificate_set_driverdata(certificate, certificate_file)) {
		goto cleanup;
	}
	certificate_file = NULL;

	if (!mycms_certificate_apply_certificate(certificate, &blob)) {
		goto cleanup;
	}

	ret = true;

cleanup:
	BIO_free(bio_in);
	bio_in = NULL;

	BIO_free(bio_out);
	bio_out = NULL;

	EVP_PKEY_free(evp);
	evp = NULL;

	if (certificate_file != NULL) {
#ifndef OPENSSL_NO_RSA
		RSA_free(certificate_file->rsa);
		certificate_file->rsa = NULL;
#endif
		mycms_system_free(system, "certificate_file", certificate_file);
		certificate_file = NULL;
	}

	return ret;
}

const char *
mycms_certificate_driver_file_usage(void) {
	return (
		"CERTIFICATE EXPRESSION ATTRIBUTES\n"
		"cert: DER encoded certificate file\n"
		"key: DER encoded PKCS#8 file\n"
	);
}

bool
mycms_certificate_driver_file_apply(
	const mycms_certificate certificate
) {
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (!mycms_certificate_set_driver_free(certificate, __driver_free)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_driver_load(certificate, __driver_load)) {
		goto cleanup;
	}

#ifndef OPENSSL_NO_RSA
	if (!mycms_certificate_set_driver_rsa_private_op(certificate, __driver_rsa_private_op)) {
		goto cleanup;
	}
#endif
	ret = true;

cleanup:

	return ret;
}

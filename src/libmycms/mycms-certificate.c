#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms/mycms-certificate.h>

#include "mycms-error-internal.h"
#include "mycms-openssl.h"

struct mycms_certificate_s {
	mycms_context context;
	const void *userdata;
	const void *driverdata;
	mycms_certificate_driver_free driver_free;
	mycms_certificate_driver_load driver_load;
	mycms_certificate_driver_rsa_private_op driver_rsa_private_op;
	mycms_certificate_passphrase_callback passphrase_callback;
	X509 *x509;
	EVP_PKEY *evp;
};

static struct {
#ifndef OPENSSL_NO_RSA
	RSA_METHOD *rsa_method;
	int rsa_index;
#endif
} __openssl_methods;

static int __convert_padding(const int padding) {
	int ret;
	switch (padding) {
#ifndef OPENSSL_NO_RSA
		case RSA_PKCS1_PADDING:
			ret = MYCMS_PADDING_PKCS1;
		break;
		case RSA_PKCS1_OAEP_PADDING:
			ret = MYCMS_PADDING_OEAP;
		break;
		case RSA_NO_PADDING:
			ret = MYCMS_PADDING_NONE;
		break;
#endif
		default:
			ret = MYCMS_PADDING_INVALID;
		break;
	}
	return ret;
}

static
bool
__driver_free_default(
	const mycms_certificate certificate __attribute__((unused))
) {
	return true;
}

static
bool
__driver_load_default(
	const mycms_certificate certificate,
	const mycms_dict dict __attribute__((unused))
) {
        _mycms_error_entry_dispatch(_mycms_error_entry_base(
		_mycms_error_capture(mycms_context_get_error(certificate->context)),
		"certificate.load",
		MYCMS_ERROR_CODE_NOT_IMPLEMENTED,
		true,
		"Certificate load is not implemented"
	));

	return false;
}

static
int
driver_rsa_private_op_default(
	const mycms_certificate certificate __attribute__((unused)),
	const int op __attribute__((unused)),
	const unsigned char * const from __attribute__((unused)),
	const size_t from_size __attribute__((unused)),
	unsigned char * const to __attribute__((unused)),
	const size_t to_size __attribute__((unused)),
	const int padding __attribute__((unused))
) {
        _mycms_error_entry_dispatch(_mycms_error_entry_base(
		_mycms_error_capture(mycms_context_get_error(certificate->context)),
		"certificate.op",
		MYCMS_ERROR_CODE_NOT_IMPLEMENTED,
		true,
		"Private key is not available"
	));

	return -1;
}

static
bool
passphrase_callback_default(
	const mycms_certificate certificate __attribute__((unused)),
	const char * const what __attribute__((unused)),
	char **p,
	const size_t size __attribute__((unused))
) {
	*p = NULL;
	return true;
}

static const struct mycms_certificate_s __MYCMS_CERTIFICATE_INIT[1] = {{
	NULL,
	NULL,
	NULL,
	__driver_free_default,
	__driver_load_default,
	driver_rsa_private_op_default,
	passphrase_callback_default,
	NULL,
	NULL
}};

#ifndef OPENSSL_NO_RSA

static
bool
__setup_rsa_evp(
	mycms_certificate certificate,
	EVP_PKEY *evp
) {
	RSA *rsa = NULL;
	bool ret = false;

	if ((rsa = EVP_PKEY_get1_RSA(evp)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.setup.rsa",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot get RSA out of EVP"
		)));
		goto cleanup;
	}

	if (!RSA_set_method(rsa, __openssl_methods.rsa_method)) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.setup.method",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot set RSA method"
		)));
		goto cleanup;
	}

	if (!RSA_set_ex_data(rsa, __openssl_methods.rsa_index, certificate)) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.setup.exdata",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot set RSA exdata"
		)));
		goto cleanup;
	}

	if (EVP_PKEY_set1_RSA(evp, rsa) != 1) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.setup.rsa",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot set RSA of EVP"
		)));
		goto cleanup;
	}

	ret = true;

cleanup:

	RSA_free(rsa);
	rsa = NULL;

	return ret;
}

static
mycms_certificate
__get_rsa_certificate(
	RSA *rsa
) {
	mycms_certificate certificate = NULL;

	if (rsa == NULL) {
		goto cleanup;
	}

	certificate = (mycms_certificate)RSA_get_ex_data(rsa, __openssl_methods.rsa_index);

cleanup:

	return certificate;
}

static
inline
int
__rsa_op(
	int private_op,
	int flen,
	const unsigned char *from,
	int tlen,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	mycms_certificate certificate;
	int cpadding;
	int ret = -1;

 	if ((certificate = __get_rsa_certificate(rsa)) == NULL) {
		goto cleanup;
	}

	if (certificate->driver_rsa_private_op == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.op",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"No registered RSA private key operation"
		));
		goto cleanup;
	}

	if ((cpadding = __convert_padding(padding)) == MYCMS_PADDING_INVALID) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.op",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Padding %d is not supported",
			padding
		));
		goto cleanup;
	}

	ret = certificate->driver_rsa_private_op(
		certificate,
		private_op,
		from,
		flen,
		to,
		tlen,
		cpadding
	);

cleanup:

	return ret;
}

static
int
__openssl_rsa_enc(
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	return __rsa_op(
		MYCMS_PRIVATE_OP_ENCRYPT,
		flen,
		from,
		RSA_size(rsa),
		to,
		rsa,
		padding
	);
}

static
int
__openssl_rsa_dec(
	int flen,
	const unsigned char *from,
	unsigned char *to,
	RSA *rsa,
	int padding
) {
	return __rsa_op(
		MYCMS_PRIVATE_OP_DECRYPT,
		flen,
		from,
		flen,
		to,
		rsa,
		padding
	);
}
#endif

bool
_mycms_certificate_static_init(
	const mycms_system system
) {
#ifndef OPENSSL_NO_RSA
	RSA_METHOD *rsa_method = NULL;
	int rsa_index = -1;
#endif
	bool ret = false;

#ifndef OPENSSL_NO_RSA
	if (__openssl_methods.rsa_method == NULL) {

		if ((rsa_method = RSA_meth_dup(RSA_get_default_method())) == NULL) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.init.method",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot get RSA default method"
			)));
			goto cleanup;
		}
		if (!RSA_meth_set1_name(rsa_method, "mycms")) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.init.method.name",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot set method name"
			)));
			goto cleanup;
		}
		if (!RSA_meth_set_priv_dec(rsa_method, __openssl_rsa_dec)) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.init.method.op",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot set method priv dec"
			)));
			goto cleanup;
		}
		if (!RSA_meth_set_priv_enc(rsa_method, __openssl_rsa_enc)) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.init.method.op",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot set method priv enc"
			)));
			goto cleanup;
		}

		if ((rsa_index = RSA_get_ex_new_index(
			0,
			"mycms",
			NULL,
			NULL,
			NULL
		)) == -1) {
			_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.init.method.exdata.index",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot get exdata index" 
			)));
			goto cleanup;
		}
	}
#endif

#ifndef OPENSSL_NO_RSA
	__openssl_methods.rsa_method = rsa_method;
	rsa_method = NULL;
	__openssl_methods.rsa_index = rsa_index;
#endif

	ret = true;

cleanup:
	RSA_meth_free (rsa_method);
	rsa_method = NULL;

	return ret;
}

bool
_mycms_certificate_static_clean(void) {
#ifndef OPENSSL_NO_RSA
	if (__openssl_methods.rsa_method != NULL) {
		RSA_meth_free (__openssl_methods.rsa_method);
		__openssl_methods.rsa_method = NULL;
	}
#endif
	return 1;
}

mycms_certificate
mycms_certificate_new(
	const mycms_context context
) {
	mycms_system system = NULL;
	mycms_certificate certificate = NULL;

	if (context == NULL) {
		goto cleanup;
	}

	if ((system = mycms_context_get_system(context)) == NULL) {
		goto cleanup;
	}

	if ((certificate = mycms_system_zalloc(system, "certificate", sizeof(*certificate))) == NULL) {
		goto cleanup;
	}

	memcpy(certificate, __MYCMS_CERTIFICATE_INIT, sizeof(__MYCMS_CERTIFICATE_INIT));
	certificate->context = context;

cleanup:

	return certificate;
}

bool
mycms_certificate_construct(
	const mycms_certificate certificate __attribute__((unused))
) {
	if (certificate == NULL) {
		return false;
	}

	return true;
}

bool
mycms_certificate_destruct(
	const mycms_certificate certificate
) {
	bool ret = true;

	if (certificate != NULL) {
		mycms_system system = mycms_context_get_system(certificate->context);

		EVP_PKEY_free(certificate->evp);
		certificate->evp = NULL;

		X509_free(certificate->x509);
		certificate->x509 = NULL;

		ret = certificate->driver_free(certificate) && ret;

		ret = mycms_system_free(system, "certificate", certificate) && ret;
	}

	return ret;
}

mycms_context
mycms_certificate_get_context(
	const mycms_certificate certificate
) {
	if (certificate == NULL) {
		return NULL;
	}

	return certificate->context;
}

const void *
mycms_certificate_get_userdata(
	const mycms_certificate certificate
) {
	if (certificate == NULL) {
		return NULL;
	}

	return certificate->userdata;
}

bool
mycms_certificate_set_userdata(
	const mycms_certificate certificate,
	const void *userdata
) {
	if (certificate == NULL) {
		return NULL;
	}

	certificate->userdata = userdata;

	return true;
}

const void *
mycms_certificate_get_driverdata(
	const mycms_certificate certificate
) {
	if (certificate == NULL) {
		return NULL;
	}

	return certificate->driverdata;
}

bool
mycms_certificate_set_driverdata(
	const mycms_certificate certificate,
	const void *driverdata
) {
	certificate->driverdata = driverdata;
	return true;
}

bool
mycms_certificate_set_driver_load(
	const mycms_certificate certificate,
	const mycms_certificate_driver_load driver_load
) {
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (driver_load == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.driver.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate driver load callback must be provided"
		));
		goto cleanup;
	}

	certificate->driver_load = driver_load;

	ret = true;

cleanup:

	return ret;
}

bool
mycms_certificate_set_driver_free(
	const mycms_certificate certificate,
	const mycms_certificate_driver_free driver_free
) {
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (driver_free == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.driver.free",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate driver free callback must be provided"
		));
		goto cleanup;
	}

	certificate->driver_free = driver_free;

	ret = true;

cleanup:

	return ret;
}

bool
mycms_certificate_set_driver_rsa_private_op(
	const mycms_certificate certificate,
	const mycms_certificate_driver_rsa_private_op driver_rsa_private_op
) {
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (driver_rsa_private_op == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.driver.op",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate driver private op callback must be provided"
		));
		goto cleanup;
	}

	certificate->driver_rsa_private_op = driver_rsa_private_op;

	ret = true;

cleanup:

	return ret;
}

bool
mycms_certificate_set_passphrase_callback(
	const mycms_certificate certificate,
	const mycms_certificate_passphrase_callback passphrase_callback
) {
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (passphrase_callback == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.driver.passphrase",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate driver passphrase callback must be provided"
		));
		goto cleanup;
	}

	certificate->passphrase_callback = passphrase_callback;

	ret = true;

cleanup:

	return ret;
}

bool
mycms_certificate_load(
	const mycms_certificate certificate,
	const mycms_dict parameters
) {
	if (certificate == NULL) {
		return false;
	}

	return certificate->driver_load(certificate, parameters);
}

bool
mycms_certificate_apply_certificate(
	const mycms_certificate certificate,
	const mycms_blob *blob
) {
	unsigned const char * p;
	X509 *x509 = NULL;
	EVP_PKEY *evp = NULL;
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (blob == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.apply",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Certificate must be provided"
		));
		goto cleanup;
	}

	p = blob->data;
	if ((x509 = d2i_X509(NULL, &p, blob->size)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.apply.x509",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot parse certificate"
		)));
		goto cleanup;
	}

	if ((evp = X509_get_pubkey(x509)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.apply.pubkey",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot get public key out of certificate"
		)));
		goto cleanup;
	}

	switch (EVP_PKEY_id(evp)) {
#ifndef OPENSSL_NO_RSA
		case EVP_PKEY_RSA:
			if (!__setup_rsa_evp(certificate, evp)) {
				goto cleanup;
			}
		break;
#endif
		default:
			goto cleanup;
	}

	certificate->x509 = x509;
	x509 = NULL;
	certificate->evp = evp;
	evp = NULL;

	ret = true;

cleanup:
	X509_free(x509);
	x509 = NULL;

	EVP_PKEY_free(evp);
	evp = NULL;

	return ret;
}

bool
mycms_certificate_acquire_passphrase(
	const mycms_certificate certificate,
	const char * const what,
	char **p,
	const size_t size
) {
	bool ret = false;

	if (certificate == NULL) {
		return false;
	}

	if (p == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(certificate->context)),
			"certificate.passphrase",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Passphrase buffer must be provided"
		));
		goto cleanup;
	}

	ret = certificate->passphrase_callback(certificate, what, p, size);

cleanup:

	return ret;
}

X509 *
_mycms_certificate_get_X509(
	const mycms_certificate certificate
) {
	if (certificate == NULL) {
		return NULL;
	}

	return certificate->x509;
}

EVP_PKEY *
_mycms_certificate_get_EVP_PKEY(
	const mycms_certificate certificate
) {
	if (certificate == NULL) {
		return NULL;
	}

	return certificate->evp;
}

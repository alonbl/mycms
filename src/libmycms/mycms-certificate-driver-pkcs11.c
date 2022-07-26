#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <mycms/mycms-certificate-driver-pkcs11.h>
#include <mycms/mycms-list.h>
#include <mycms/mycms-system-driver-core.h>

#include "mycms-context-internal.h"
#include "mycms-error-internal.h"
#include "pkcs11.h"

#define __INVALID_SESSION_HANDLE	((CK_SESSION_HANDLE)-1)
#define __INVALID_OBJECT_HANDLE		((CK_OBJECT_HANDLE)-1)

struct __pkcs11_provider_s {
	char *name;
	int reference_count;
	void *module_handle;
	bool should_finalize;
	CK_FUNCTION_LIST_PTR f;
};

MYCMS_LIST_DECLARE(pkcs11_provider, struct __pkcs11_provider_s, entry)

struct __mycms_certificate_driver_pkcs11_s {
	char display[1024];
	mycms_certificate certificate;
	struct __pkcs11_provider_s *p;
	char *token_label;
	CK_SESSION_HANDLE session_handle;
	CK_OBJECT_HANDLE key_handle;
	bool protected_auth;
	bool login_required;
	bool always_authenticate;
	mycms_blob id;

	bool assume_loggedin;
	bool key_attributes_valid;
};
typedef struct __mycms_certificate_driver_pkcs11_s *__mycms_certificate_driver_pkcs11;

const char *
__rv2str(
	const CK_RV rv
) {
	switch (rv) {
		case CKR_OK: return "CKR_OK";
		case CKR_CANCEL: return "CKR_CANCEL";
		case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
		case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
		case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
		case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
		case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
		case CKR_NO_EVENT: return "CKR_NO_EVENT";
		case CKR_NEED_TO_CREATE_THREADS: return "CKR_NEED_TO_CREATE_THREADS";
		case CKR_CANT_LOCK: return "CKR_CANT_LOCK";
		case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
		case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
		case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
		case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
		case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
		case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
		case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
		case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
		case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
		case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
		case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
		case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
		case CKR_FUNCTION_NOT_PARALLEL: return "CKR_FUNCTION_NOT_PARALLEL";
		case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
		case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
		case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
		case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
		case CKR_KEY_NOT_NEEDED: return "CKR_KEY_NOT_NEEDED";
		case CKR_KEY_CHANGED: return "CKR_KEY_CHANGED";
		case CKR_KEY_NEEDED: return "CKR_KEY_NEEDED";
		case CKR_KEY_INDIGESTIBLE: return "CKR_KEY_INDIGESTIBLE";
		case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
		case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
		case CKR_KEY_UNEXTRACTABLE: return "CKR_KEY_UNEXTRACTABLE";
		case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
		case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
		case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
		case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
		case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
		case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
		case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
		case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
		case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
		case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
		case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
		case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
		case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
		case CKR_SESSION_PARALLEL_NOT_SUPPORTED: return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
		case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
		case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
		case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
		case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
		case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
		case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
		case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
		case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
		case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
		case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
		case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
		case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
		case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
		case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
		case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
		case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
		case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
		case CKR_SAVED_STATE_INVALID: return "CKR_SAVED_STATE_INVALID";
		case CKR_INFORMATION_SENSITIVE: return "CKR_INFORMATION_SENSITIVE";
		case CKR_STATE_UNSAVEABLE: return "CKR_STATE_UNSAVEABLE";
		case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
		case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
		case CKR_MUTEX_BAD: return "CKR_MUTEX_BAD";
		case CKR_MUTEX_NOT_LOCKED: return "CKR_MUTEX_NOT_LOCKED";
		case CKR_FUNCTION_REJECTED: return "CKR_FUNCTION_REJECTED";
		case CKR_VENDOR_DEFINED: return "CKR_VENDOR_DEFINED";
		default: return "Unmapped PKCS#11 error";
	}
}

static
mycms_error_entry
__error_entry_pkcs11_rv(
	const CK_RV rv,
	const mycms_error_entry entry
) {
	_mycms_error_entry_prm_add_u32(entry, MYCMS_ERROR_KEY_PKCS11_RV, rv);
	_mycms_error_entry_prm_add_str(entry, MYCMS_ERROR_KEY_OPENSSL_STATUS_STR, __rv2str(rv));
	return entry;
}

static
void
__fixup_fixed_string(
	char * const target,			/* MUST BE >= length+1 */
	const char * const source,
	const size_t length			/* FIXED STRING LENGTH */
) {
	char *p;

	memmove (target, source, length);
	p = target+length;
	*p = '\0';
	p--;
	while (p >= target && *p == ' ') {
		*p = '\0';
		p--;
	}
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
CK_MECHANISM_TYPE
__convert_padding(const int padding) {
	int ret;
	switch (padding) {
		case MYCMS_PADDING_PKCS1:
			ret = CKM_RSA_PKCS;
		break;
		case MYCMS_PADDING_OEAP:
			ret = CKM_RSA_PKCS_OAEP;
		break;
		case MYCMS_PADDING_NONE:
			ret = CKM_RSA_X_509;
		break;
		default:
			ret = CKR_MECHANISM_INVALID;
		break;
	}
	return ret;
}

static
CK_RV
__get_object_attributes(
	const mycms_system system,
	const __mycms_certificate_driver_pkcs11 certificate_pkcs11,
	const CK_OBJECT_HANDLE object,
	const CK_ATTRIBUTE_PTR attrs,
	const unsigned count
) {
	CK_RV rv = CKR_FUNCTION_FAILED;
	unsigned i;

	if (certificate_pkcs11->session_handle == __INVALID_SESSION_HANDLE) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetAttributeValue(
			certificate_pkcs11->session_handle,
			object,
			attrs,
			count
		)) != CKR_OK
	) {
		if (rv != CKR_ATTRIBUTE_SENSITIVE && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
			_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.driver.pkcs11.attrs.pre",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot get object attributes"
			)));
			goto cleanup;
		}
	}

	for (i=0;i<count;i++) {
		if (attrs[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
		}
		else if (attrs[i].ulValueLen == 0) {
			attrs[i].pValue = NULL;
		}
		else {
			if (
				(attrs[i].pValue = mycms_system_zalloc(
					system,
					"pkcs11.attrs[i].pValue",
					attrs[i].ulValueLen
				)) == NULL
			) {
				rv = CKR_HOST_MEMORY;
				goto cleanup;
			}
		}
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetAttributeValue(
			certificate_pkcs11->session_handle,
			object,
			attrs,
			count
		)) != CKR_OK
	) {
		if (rv != CKR_ATTRIBUTE_SENSITIVE && rv != CKR_ATTRIBUTE_TYPE_INVALID) {
			_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.driver.pkcs11.attrs.post",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Cannot get object attributes"
			)));
			goto cleanup;
		}
	}

cleanup:

	return rv;
}

static
CK_RV
__free_attributes (
	const mycms_system system,
	const CK_ATTRIBUTE_PTR attrs,
	const unsigned count
) {
	unsigned i;

	for (i=0;i<count;i++) {
		mycms_system_free(system, "pkcs11.attrs[i].pValue", attrs[i].pValue);
		attrs[i].pValue = NULL;
	}

	return CKR_OK;
}

static
CK_RV
__find_object(
	__mycms_certificate_driver_pkcs11 certificate_pkcs11,
	const CK_ATTRIBUTE * const filter,
	const CK_ULONG filter_attrs,
	CK_OBJECT_HANDLE_PTR object_handle
) {
	bool should_FindObjectsFinal = false;
	CK_ULONG objects_size;
	CK_RV rv = CKR_FUNCTION_FAILED;

	*object_handle = __INVALID_OBJECT_HANDLE;

	if (certificate_pkcs11->session_handle == __INVALID_SESSION_HANDLE) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_FindObjectsInit(
			certificate_pkcs11->session_handle,
			(CK_ATTRIBUTE_PTR)filter,
			filter_attrs
		)) != CKR_OK
	) {
		_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate_pkcs11->certificate))),
			"certificate.driver.pkcs11.find.init",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot initiate object find"
		)));
		goto cleanup;
	}
	should_FindObjectsFinal = true;

	if ((rv = certificate_pkcs11->p->f->C_FindObjects(
		certificate_pkcs11->session_handle,
		object_handle,
		1,
		&objects_size
	)) != CKR_OK) {
		_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate_pkcs11->certificate))),
			"certificate.driver.pkcs11.find",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to search objects"
		)));
		goto cleanup;
	}

	if (objects_size == 0) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate_pkcs11->certificate))),
			"certificate.driver.pkcs11.find",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"No object found"
		));
		*object_handle = __INVALID_OBJECT_HANDLE;
	}

	rv = CKR_OK;

cleanup:

	if (should_FindObjectsFinal) {
		certificate_pkcs11->p->f->C_FindObjectsFinal(
			certificate_pkcs11->session_handle
		);
	}

	return rv;
}

static
void
__unload_provider(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;

	mycms_list_pkcs11_provider head;
	bool found;

	if ((system = __get_system(certificate)) == NULL) {
		goto cleanup;
	}

	head = (mycms_list_pkcs11_provider)_mycms_context_get_pkcs11_state(mycms_certificate_get_context(certificate));
	found = true;
	while (found) {
		mycms_list_pkcs11_provider p;
		mycms_list_pkcs11_provider t;
		found = false;

		for (
			p = NULL, t = head;
			t != NULL;
			p = t, t = t->next
		) {
			if (t->entry.reference_count == 0) {
				break;
			}
		}

		if (t != NULL) {
			if (p == NULL) {
				head = t->next;
			} else {
				p->next = t->next;
			}


			if (t->entry.should_finalize) {
				t->entry.f->C_Finalize(NULL);
				t->entry.should_finalize = false;
			}
			t->entry.f = NULL;
			if (t->entry.module_handle != NULL) {
				mycms_system_driver_core_dlclose(system)(
					system,
					t->entry.module_handle
				);
				t->entry.module_handle = NULL;
			}
			mycms_system_free(system, "pkcs11_provider.name", t->entry.name);
			mycms_system_free(system, "pkcs11_provider.entry", t);
			t = NULL;
		}
	}

	_mycms_context_set_pkcs11_state(mycms_certificate_get_context(certificate), head);

cleanup:
	;
}

static
struct __pkcs11_provider_s *
__load_provider(
	const mycms_certificate certificate,
	const char * const module,
	const char * const reserved
) {
	mycms_system system = NULL;
	mycms_list_pkcs11_provider t = NULL;
	mycms_list_pkcs11_provider pkcs11_provider = NULL;
	CK_C_GetFunctionList gfl = NULL;
	CK_C_INITIALIZE_ARGS initargs;
	CK_C_INITIALIZE_ARGS_PTR pinitargs = NULL;
	CK_RV rv;
	struct __pkcs11_provider_s *ret = NULL;

	if ((system = __get_system(certificate)) == NULL) {
		return NULL;
	}

	for (
		t = (mycms_list_pkcs11_provider)_mycms_context_get_pkcs11_state(mycms_certificate_get_context(certificate));
		t != NULL;
		t = t->next
	) {
		if (!strcmp(t->entry.name, module)) {
			break;
		}
	}

	if (t != NULL) {
		pkcs11_provider = t;
	} else {
		if ((pkcs11_provider = mycms_system_zalloc(system, "pkcs11_provider", sizeof(*pkcs11_provider))) == NULL) {
			goto cleanup;
		}

		if ((pkcs11_provider->entry.name = mycms_system_strdup(system, "pkcs11_provider.name", module)) == NULL) {
			goto cleanup;
		}

		pkcs11_provider->next = (mycms_list_pkcs11_provider)_mycms_context_get_pkcs11_state(mycms_certificate_get_context(certificate));
		_mycms_context_set_pkcs11_state(mycms_certificate_get_context(certificate), pkcs11_provider);

		if ((pkcs11_provider->entry.module_handle = mycms_system_driver_core_dlopen(system)(
			system,
			pkcs11_provider->entry.name,
			RTLD_NOW | RTLD_LOCAL
		)) == NULL) {
			_mycms_error_entry_dispatch(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.driver.pkcs11.load",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to load PKCS#11 provider `%s`",
				module
			));
			goto cleanup;
		}

		{
			void *p;

			/*
			 * Make compiler happy!
			 */
			p = mycms_system_driver_core_dlsym(system)(
				system,
				pkcs11_provider->entry.module_handle,
				"C_GetFunctionList"
			);
			memmove(&gfl, &p, sizeof(gfl));
		}

		if (gfl == NULL) {
			_mycms_error_entry_dispatch(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.driver.pkcs11.gfl.entry",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to resolve PKCS#11 provider `%s` function list entry",
				pkcs11_provider->entry.name
			));
			goto cleanup;
		}

		if ((rv = gfl(&pkcs11_provider->entry.f)) != CKR_OK) {
			_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.driver.pkcs11.gfl",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to acquire PKCS#11 provider `%s` function list",
				pkcs11_provider->entry.name
			)));
			goto cleanup;
		}

		memset(&initargs, 0, sizeof(initargs));
		if (reserved != NULL) {
			initargs.pReserved = (char *)reserved;
			pinitargs = &initargs;
		}

		if ((rv = pkcs11_provider->entry.f->C_Initialize(pinitargs)) != CKR_OK) {
			if (rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
				_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
					_mycms_error_capture(mycms_system_get_error(system)),
					"certificate.driver.pkcs11.init",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Failed to initialize PKCS#11 provider `%s`",
					pkcs11_provider->entry.name
				)));
				goto cleanup;
			}
		}
		else {
			pkcs11_provider->entry.should_finalize = true;
		}
	}

	pkcs11_provider->entry.reference_count++;
	ret = &pkcs11_provider->entry;
	pkcs11_provider = NULL;

cleanup:
	__unload_provider(certificate);

	return ret;
}

static
CK_RV
__common_login(
	const mycms_certificate certificate,
	const CK_USER_TYPE user,
	const char * const what
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	char pin[512];
	char *p;
	bool loggedin = false;
	CK_RV rv = CKR_FUNCTION_FAILED;

	if ((system = __get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.login",
			MYCMS_ERROR_CODE_CRYPTO,
			false,
			"Failed to acquire PKCS#11 context"
		));
		goto cleanup;
	}

	if (certificate_pkcs11->session_handle == __INVALID_SESSION_HANDLE) {
		rv = CKR_SESSION_HANDLE_INVALID;
		goto cleanup;
	}

	if (!loggedin && certificate_pkcs11->protected_auth) {
		if ((rv = certificate_pkcs11->p->f->C_Login (
			certificate_pkcs11->session_handle,
			user,
			NULL_PTR,
			0
		)) == CKR_OK || rv != CKR_USER_ALREADY_LOGGED_IN) {
			loggedin = true;
		}
	}

	if (!loggedin) {
		p = pin;
		if (!mycms_certificate_acquire_passphrase(certificate, what, &p, sizeof(pin))) {
			_mycms_error_entry_dispatch(_mycms_error_entry_base(
				_mycms_error_capture(mycms_system_get_error(system)),
				"certificate.driver.pkcs11.login.pass",
				MYCMS_ERROR_CODE_CRYPTO,
				false,
				"Failed to acquire passphrase for '%s' for '%s'",
				certificate_pkcs11->display,
				what
			));
			goto cleanup;
		}

		if ((rv = certificate_pkcs11->p->f->C_Login (
			certificate_pkcs11->session_handle,
			user,
			(CK_UTF8CHAR_PTR)p,
			p == NULL ? 0 : strlen(p)
		)) == CKR_OK || rv != CKR_USER_ALREADY_LOGGED_IN) {
			loggedin = true;
		}
	}

	if (!loggedin) {
		_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
			_mycms_error_capture(mycms_system_get_error(system)),
			"certificate.driver.pkcs11.login",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Login to '%s' failed for '%s'",
			certificate_pkcs11->display,
			what
		)));
		goto cleanup;
	}

	rv = CKR_OK;

cleanup:
	mycms_system_explicit_bzero(system, pin, sizeof(pin));

	return rv;
}

static
CK_RV
__context_login(
	const mycms_certificate certificate
) {
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_RV rv = CKR_FUNCTION_FAILED;

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.login.context",
			MYCMS_ERROR_CODE_CRYPTO,
			false,
			"Failed to get PKCS#11 context"
		));
		goto cleanup;
	}

	if (certificate_pkcs11->always_authenticate) {
		if ((rv = __common_login(certificate, CKU_CONTEXT_SPECIFIC, "key")) != CKR_OK) {
			_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
				"certificate.driver.pkcs11.login",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Context specific login failed for '%s'",
				certificate_pkcs11->display
			)));
			goto cleanup;
		}
	}

	rv = CKR_OK;

cleanup:

	return rv;
}

static
bool
__open_slot(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_SLOT_ID_PTR slots = NULL;
	CK_ULONG slotnum = 0;
	CK_ULONG slot_index;
	CK_RV rv = CKR_FUNCTION_FAILED;

	bool found;
	bool ret = false;

	if ((system = __get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.login",
			MYCMS_ERROR_CODE_CRYPTO,
			false,
			"Failed to acquire PKCS#11 context"
		));
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetSlotList (
			CK_TRUE,
			NULL_PTR,
			&slotnum
		)) != CKR_OK
	) {
		_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.login.slots.pre",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to list slots for '%s'",
			certificate_pkcs11->display
		)));
		goto cleanup;
	}

	if ((slots = mycms_system_zalloc(system, "pkcs11.slots", sizeof(*slots) * slotnum)) == NULL) {
		goto cleanup;
	}

	if (
		(rv = certificate_pkcs11->p->f->C_GetSlotList (
			CK_TRUE,
			slots,
			&slotnum
		)) != CKR_OK
	) {
		_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.login.slots.post",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to list slots for '%s'",
			certificate_pkcs11->display
		)));
		goto cleanup;
	}

	for (
		found = false, slot_index = 0;
		(
			slot_index < slotnum &&
			!found
		);
		slot_index++
	) {
		CK_TOKEN_INFO info;

		if (certificate_pkcs11->p->f->C_GetTokenInfo (
			slots[slot_index],
			&info
		) != CKR_OK) {
		} else {
			char label[sizeof(info.label)+1];
			__fixup_fixed_string(label, (char *)info.label, sizeof(info.label));
			if (!strcmp(label, certificate_pkcs11->token_label)) {
				found = true;
				certificate_pkcs11->protected_auth = (info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) != 0;
				certificate_pkcs11->login_required = (info.flags & CKF_LOGIN_REQUIRED) != 0;
				break;
			}
		}
	}

	if (!found) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.login.token",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Cannot find certificate '%s'",
			certificate_pkcs11->display
		));
		goto cleanup;
	}

	if ((rv = certificate_pkcs11->p->f->C_OpenSession (
		slots[slot_index],
		CKF_SERIAL_SESSION,
		NULL_PTR,
		NULL_PTR,
		&certificate_pkcs11->session_handle
	)) != CKR_OK) {
		_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.login.session",
			MYCMS_ERROR_CODE_CRYPTO,
			true,
			"Failed to open session to '%s' slot %ld",
			certificate_pkcs11->display,
			slots[slot_index]
		)));
		certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
		goto cleanup;
	}

	ret = true;

cleanup:

	mycms_system_free(system, "pkcs11.slots", slots);
	slots = NULL;

	return ret;
}

static
bool
__open_private_key(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_ATTRIBUTE key_attrs[] = {
		{CKA_ALWAYS_AUTHENTICATE, NULL, 0}
	};
	CK_RV rv = CKR_FUNCTION_FAILED;

	int retry;
	bool ret = false;

	if ((system = __get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	retry = 3;
	while(retry--) {
		if (!certificate_pkcs11->assume_loggedin && certificate_pkcs11->login_required) {
			if ((rv = __common_login(certificate, CKU_USER, "token")) != CKR_OK) {
				switch (rv) {
					default:
						_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
							_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
							"certificate.driver.pkcs11.private",
							MYCMS_ERROR_CODE_CRYPTO,
							false,
							"Failed to login into '%s'",
							certificate_pkcs11->display
						)));
						goto cleanup;
					case CKR_SESSION_CLOSED:
					case CKR_SESSION_HANDLE_INVALID:
					case CKR_USER_NOT_LOGGED_IN:
						goto retry;
				}
			}
			certificate_pkcs11->assume_loggedin = true;
		}

		if (!certificate_pkcs11->key_attributes_valid) {
			CK_OBJECT_CLASS c = CKO_PRIVATE_KEY;
			const CK_ATTRIBUTE filter[] = {
				{CKA_CLASS, &c, sizeof(c)},
				{CKA_ID, certificate_pkcs11->id.data, certificate_pkcs11->id.size}
			};

			if ((rv = __find_object(
				certificate_pkcs11,
				filter,
				sizeof(filter) / sizeof(*filter),
				&certificate_pkcs11->key_handle
			)) != CKR_OK) {
				switch (rv) {
					default:
						_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
							_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
							"certificate.driver.pkcs11.private",
							MYCMS_ERROR_CODE_CRYPTO,
							false,
							"Failed to find private key '%s'",
							certificate_pkcs11->display
						)));
						goto cleanup;
					case CKR_SESSION_CLOSED:
					case CKR_SESSION_HANDLE_INVALID:
					case CKR_USER_NOT_LOGGED_IN:
						goto retry;
				}
				goto cleanup;
			}

			if (certificate_pkcs11->key_handle == __INVALID_OBJECT_HANDLE) {
				goto cleanup;
			}

			if (__get_object_attributes(
				system,
				certificate_pkcs11,
				certificate_pkcs11->key_handle,
				key_attrs,
				sizeof(key_attrs) / sizeof(*key_attrs)
			) == CKR_OK) {
				if (key_attrs[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
					certificate_pkcs11->always_authenticate = *(CK_BBOOL *)key_attrs[0].pValue != CK_FALSE;
				}
			}

			certificate_pkcs11->key_attributes_valid = true;
		}

		break;

	retry:

		certificate_pkcs11->assume_loggedin = false;
		if (!__open_slot(certificate)) {
			goto cleanup;
		}
	}

	ret = true;

cleanup:

	__free_attributes(
		system,
		key_attrs,
		sizeof(key_attrs) / sizeof(*key_attrs)
	);

	return ret;
}

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
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_MECHANISM mech = {0, NULL, 0};
	CK_ULONG size;
	CK_RV rv = CKR_FUNCTION_FAILED;
	int ret = -1;

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		goto cleanup;
	}

	if (from == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.op.from",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"From buffer must not be null"
		));
		goto cleanup;
	}

	if (to == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.op.to",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"To buffer must not be null"
		));
		goto cleanup;
	}

	if (from_size == 0) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.op.from_size",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"From size must be greater than zero"
		));
		goto cleanup;
	}

	if (to_size < from_size) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.op.from_size",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"To size must be greater than from (%ld>=%ld)",
			to_size,
			from_size
		));
		goto cleanup;
	}

	if ((mech.mechanism = __convert_padding(padding)) == CKR_MECHANISM_INVALID) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.op.padding",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Invalid padding %d",
			padding
		));
		goto cleanup;
	}

	if (!__open_private_key(certificate)) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.open.privatekey",
			MYCMS_ERROR_CODE_RESOURCE_ACCESS,
			true,
			"Failed to load private key"
		));
		goto cleanup;
	}

	switch (op) {
		default:
			_mycms_error_entry_dispatch(_mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
				"certificate.driver.pkcs11.op.type",
				MYCMS_ERROR_CODE_ARGS,
				true,
				"Invalid op type %d",
				op
			));
			goto cleanup;
		case MYCMS_PRIVATE_OP_ENCRYPT:
			if ((rv = certificate_pkcs11->p->f->C_SignInit (
				certificate_pkcs11->session_handle,
				&mech,
				certificate_pkcs11->key_handle
			)) != CKR_OK) {
				_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
					"certificate.driver.pkcs11.op.sign.pre",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Sign failed for '%s'",
					certificate_pkcs11->display
				)));
				goto cleanup;
			}
			if (__context_login(certificate) != CKR_OK) {
				goto cleanup;
			}
			size = to_size;
			if ((rv = certificate_pkcs11->p->f->C_Sign (
				certificate_pkcs11->session_handle,
				(CK_BYTE_PTR)from,
				from_size,
				(CK_BYTE_PTR)to,
				&size
			)) != CKR_OK) {
				_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
					"certificate.driver.pkcs11.op.sign.post",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Sign failed for '%s'",
					certificate_pkcs11->display
				)));
				goto cleanup;
			}
		break;
		case MYCMS_PRIVATE_OP_DECRYPT:
			if ((rv = certificate_pkcs11->p->f->C_DecryptInit (
				certificate_pkcs11->session_handle,
				&mech,
				certificate_pkcs11->key_handle
			)) != CKR_OK) {
				_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
					"certificate.driver.pkcs11.op.decrypt.pre",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Decrypt failed for '%s'",
					certificate_pkcs11->display
				)));
				goto cleanup;
			}
			if (__context_login(certificate) != CKR_OK) {
				goto cleanup;
			}
			size = to_size;
			if ((rv = certificate_pkcs11->p->f->C_Decrypt (
				certificate_pkcs11->session_handle,
				(CK_BYTE_PTR)from,
				from_size,
				(CK_BYTE_PTR)to,
				&size
			)) != CKR_OK) {
				_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
					_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
					"certificate.driver.pkcs11.op.decrypt.post",
					MYCMS_ERROR_CODE_CRYPTO,
					true,
					"Decrypt failed for '%s'",
					certificate_pkcs11->display
				)));
				goto cleanup;
			}
		break;
	}

	ret = size;

cleanup:

	return ret;
}

static
bool
__driver_free(
	const mycms_certificate certificate
) {
	mycms_system system = NULL;
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;
	bool ret = false;

	if ((system = __get_system(certificate)) == NULL) {
		goto cleanup;
	}

	if ((certificate_pkcs11 = (__mycms_certificate_driver_pkcs11)mycms_certificate_get_driverdata(certificate)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.free",
			MYCMS_ERROR_CODE_CRYPTO,
			false,
			"Failed to acquire PKCS#11 context"
		));
		goto cleanup;
	}

	certificate_pkcs11->key_handle = __INVALID_OBJECT_HANDLE;
	if (certificate_pkcs11->session_handle != __INVALID_SESSION_HANDLE) {
		certificate_pkcs11->p->f->C_Logout(certificate_pkcs11->session_handle);
		certificate_pkcs11->p->f->C_CloseSession(certificate_pkcs11->session_handle);
		certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
	}

	mycms_system_free(system, "certificate_pkcs11.id.data", certificate_pkcs11->id.data);
	certificate_pkcs11->id.data = NULL;

	mycms_system_free(system, "certificate_pkcs11.token_label", certificate_pkcs11->token_label);
	certificate_pkcs11->token_label = NULL;

	if (certificate_pkcs11->p != NULL) {
		certificate_pkcs11->p->reference_count--;
		certificate_pkcs11->p = NULL;
	}
	mycms_system_free(system, "certificate_pkcs11", certificate_pkcs11);

	__unload_provider(certificate);

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
	__mycms_certificate_driver_pkcs11 certificate_pkcs11 = NULL;

	CK_RV rv = CKR_FUNCTION_FAILED;

	const char *module = NULL;
	const char *token_label = NULL;
	const char *cert_label = NULL;

	bool ret = false;

	const int CERT_ATTRS_ID = 0;
	const int CERT_ATTRS_VALUE = 1;
	CK_ATTRIBUTE cert_attrs[] = {
		{CKA_ID, NULL, 0},
		{CKA_VALUE, NULL, 0}
	};

	if (certificate == NULL) {
		return false;
	}

	if (parameters == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Parameters must be provided"
		));
		goto cleanup;
	}

	if ((system = __get_system(certificate)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"Cannot get system context"
		));
		goto cleanup;
	}

	if ((module = mycms_dict_entry_get(parameters, "module", NULL)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"No module attribute in parameters"
		));
		goto cleanup;
	}

	if ((token_label = mycms_dict_entry_get(parameters, "token-label", NULL)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"No token-label attribute in parameters"
		));
		goto cleanup;
	}

	if ((cert_label = mycms_dict_entry_get(parameters, "cert-label", NULL)) == NULL) {
		_mycms_error_entry_dispatch(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
			"certificate.driver.pkcs11.load",
			MYCMS_ERROR_CODE_ARGS,
			true,
			"No cert-label attribute in parameters"
		));
		goto cleanup;
	}

	if ((certificate_pkcs11 = mycms_system_zalloc(system, "certificate_pkcs11", sizeof(*certificate_pkcs11))) == NULL) {
		goto cleanup;
	}
	snprintf(
		certificate_pkcs11->display,
		sizeof(certificate_pkcs11->display),
		"PKCS#11: module='%s', token='%s', cert='%s'",
		module,
		token_label,
		cert_label
	);
	certificate_pkcs11->certificate = certificate;
	certificate_pkcs11->token_label = mycms_system_strdup(system, "certificate_pkcs11.token_label", token_label);
	certificate_pkcs11->session_handle = __INVALID_SESSION_HANDLE;
	certificate_pkcs11->key_handle = __INVALID_OBJECT_HANDLE;

	if (!mycms_certificate_set_driverdata(certificate, certificate_pkcs11)) {
		goto cleanup;
	}

	if ((certificate_pkcs11->p = __load_provider(certificate, module, mycms_dict_entry_get(parameters, "init-reserved", NULL))) == NULL) {
		goto cleanup;
	}

	if (!__open_slot(certificate)) {
		goto cleanup;
	}

	{
		CK_OBJECT_CLASS c = CKO_CERTIFICATE;
		const CK_ATTRIBUTE filter[] = {
			{CKA_CLASS, &c, sizeof(c)},
			{CKA_LABEL, (char *)cert_label, strlen(cert_label)}
		};
		mycms_blob blob;
		CK_OBJECT_HANDLE o;

		if ((rv = __find_object(
			certificate_pkcs11,
			filter,
			sizeof(filter) / sizeof(*filter),
			&o
		)) != CKR_OK) {
			_mycms_error_entry_dispatch(__error_entry_pkcs11_rv(rv, _mycms_error_entry_base(
				_mycms_error_capture(mycms_context_get_error(mycms_certificate_get_context(certificate))),
				"certificate.driver.pkcs11.load.objects",
				MYCMS_ERROR_CODE_CRYPTO,
				true,
				"Failed to find '%s'",
				certificate_pkcs11->display
			)));
			goto cleanup;
		}

		if (o == __INVALID_OBJECT_HANDLE) {
			goto cleanup;
		}

		if (__get_object_attributes(
			system,
			certificate_pkcs11,
			o,
			cert_attrs,
			sizeof(cert_attrs) / sizeof(*cert_attrs)
		) != CKR_OK) {
			goto cleanup;
		}

		if (cert_attrs[CERT_ATTRS_ID].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
			goto cleanup;
		}

		if (cert_attrs[CERT_ATTRS_VALUE].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
			goto cleanup;
		}

		if (cert_attrs[CERT_ATTRS_ID].ulValueLen < 1) {
			goto cleanup;
		}

		certificate_pkcs11->id.size = cert_attrs[CERT_ATTRS_ID].ulValueLen;
		if ((certificate_pkcs11->id.data = mycms_system_zalloc(system, "certificate_pkcs11.id", certificate_pkcs11->id.size)) == NULL) {
			goto cleanup;
		}
		memcpy(certificate_pkcs11->id.data, cert_attrs[CERT_ATTRS_ID].pValue, certificate_pkcs11->id.size);
		blob.data = cert_attrs[CERT_ATTRS_VALUE].pValue;
		blob.size = cert_attrs[CERT_ATTRS_VALUE].ulValueLen;
		if (!mycms_certificate_apply_certificate(certificate, &blob)) {
			goto cleanup;
		}
	}

	ret = true;

cleanup:

	__free_attributes(
		system,
		cert_attrs,
		sizeof(cert_attrs) / sizeof(*cert_attrs)
	);

	return ret;
}

const char *
mycms_certificate_driver_pkcs11_usage(void) {
	return (
		"CERTIFICATE EXPRESSION ATTRIBUTES\n"
		"module: PKCS#11 module to load\n"
		"token-label: token label\n"
		"cert-label: certificate label\n"
		"init-reserved: reserved C_Initialize argument\n"
		"\n"
		"PASSPHRASE EXPRESSION WHAT\n"
		"token: token passphrase\n"
		"key: key passphrase\n"
	);
}

bool
mycms_certificate_driver_pkcs11_apply(
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

	if (!mycms_certificate_set_driver_rsa_private_op(certificate, __driver_rsa_private_op)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

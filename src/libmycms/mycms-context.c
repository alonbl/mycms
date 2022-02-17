#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <mycms/mycms-static.h>

#include "mycms-context-internal.h"
#include "mycms-error-internal.h"

struct __mycms_context_s {
	mycms_system system;
	void *pkcs11_state;
	void *user_context;
};

mycms_context
mycms_context_new(
	const mycms_system system
) {
	mycms_context context = NULL;
	mycms_context ret = NULL;

	mycms_static_init(system);

	if ((context = mycms_system_zalloc(system, "mycms_context", sizeof(*context))) == NULL) {
		goto cleanup;
	}

	context->system = system;

	ret = context;
	context = NULL;

cleanup:

	mycms_context_destruct(context);

	return ret;
}

bool
mycms_context_construct(
	const mycms_context context __attribute__((unused))
) {
	return true;
}

bool
mycms_context_destruct(
	const mycms_context context
) {
	bool ret = true;

	if (context != NULL) {
		ret = mycms_system_free(context->system, "mycms_context", context) && ret;
	}

	return ret;
}

mycms_system
mycms_context_get_system(
	const mycms_context context
) {
	if (context == NULL) {
		return NULL;
	}
	return context->system;
}

const void *
mycms_context_get_user_context(
	const mycms_context context
) {
	if (context == NULL) {
		return NULL;
	}
	return context->user_context;
}

bool
mycms_context_set_user_context(
	const mycms_context context,
	void *user_context
) {
	if (context == NULL) {
		return false;
	}
	context->user_context = user_context;
	return true;
}

mycms_error
mycms_context_get_error(
	const mycms_context context
) {
	if (context == NULL) {
		return NULL;
	}
	return mycms_system_get_error(context->system);
}

void
mycms_context_error_reset(
	const mycms_context context
) {
	mycms_error_reset(mycms_context_get_error(context));
}

void *
_mycms_context_get_pkcs11_state(
	const mycms_context context
) {
	if (context == NULL) {
		return NULL;
	}

	return context->pkcs11_state;
}

bool
_mycms_context_set_pkcs11_state(
	const mycms_context context,
	void *pkcs11_state
) {
	if (context == NULL) {
		return false;
	}

	context->pkcs11_state = pkcs11_state;

	return true;
}

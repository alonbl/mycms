#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>

#include <mycms/mycms.h>

struct __mycms_s {
	mycms_context context;
};

mycms
mycms_new(
	const mycms_context context
) {
	mycms_system system = mycms_context_get_system(context);
	mycms ret = NULL;
	mycms mycms = NULL;

	if (context == NULL) {
		return NULL;
	}

	if ((mycms = mycms_system_zalloc(system, "mycms", sizeof(*mycms))) == NULL) {
		goto cleanup;
	}

	mycms->context = context;

	ret = mycms;
	mycms = NULL;

cleanup:

	mycms_destruct(mycms);

	return ret;
}

bool
mycms_construct(
	const mycms mycms
) {
	if (mycms == NULL) {
		return false;
	}

	return true;
}

bool
mycms_destruct(
	const mycms mycms
) {
	int ret = true;

	if (mycms != NULL) {
		mycms_system system = mycms_get_system(mycms);

		ret = mycms_system_free(system, "mycms", mycms) && ret;
	}

	return ret;
}

mycms_context
mycms_get_context(
	const mycms mycms
) {
	if (mycms == NULL) {
		return NULL;
	}

	return mycms->context;
}

mycms_system
mycms_get_system(
	const mycms mycms
) {
	if (mycms == NULL) {
		return NULL;
	}
	return mycms_context_get_system(mycms->context);
}

mycms_error
mycms_get_error(
	const mycms mycms
) {
	return mycms_context_get_error(mycms_get_context(mycms));
}

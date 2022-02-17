#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>

#include <mycms/mycms-system.h>

#include "mycms-error-internal.h"

static struct {
        bool init;
        mycms_system system;
        void *(*orig_m)(size_t, const char *, int);
        void *(*orig_r)(void *, size_t, const char *, int);
        void (*orig_f)(void *, const char *, int);
} __static_context[1];

static
void *
__openssl_malloc(
	size_t num,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	return mycms_system_realloc(__static_context->system, "openssl", NULL, num);
}

static
void *
__openssl_realloc(
	void *p,
	size_t num,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	return mycms_system_realloc(__static_context->system, "openssl", p, num);
}

static
void
__openssl_free(
	void *p,
	const char *file __attribute__((unused)),
	int line __attribute__((unused))
) {
	mycms_system_free(__static_context->system, "openssl", p);
}

void
_mycms_openssl_static_init(
	const mycms_system system
) {
	/*
	 * PKCS#11 provider with openssl 3 sets hooks at atexit causing system
	 * to be triggered after system is freed.
	 * need much more complex solutions to hook memory management without
	 * openssl support polls.
	 */
	(void)system;
#if 0
	if (!__static_context->init) {
		__static_context->init = true;
		__static_context->system = system;
		CRYPTO_get_mem_functions(
			&__static_context->orig_m,
			&__static_context->orig_r,
			&__static_context->orig_f
		);
		if (!CRYPTO_set_mem_functions(
			__openssl_malloc,
			__openssl_realloc,
			__openssl_free
		)) {
			/* can we do anything? */
		}

#if 0
		OPENSSL_init_crypto(
#ifdef ENABLE_OPENSSL_ERR_STRINGS
			OPENSSL_INIT_LOAD_CRYPTO_STRINGS
#endif
			| OPENSSL_INIT_NO_ATEXIT,
			NULL
		);
#endif
	}
#endif
}

void
_mycms_openssl_static_clean(
	const mycms_system system __attribute__((unused))
) {
	/*
	 * PKCS#11 provider with openssl usage such as softhsm
	 * has library conflict with parent initialization
	 * and leaks memory.
	 * openssl atexit or other hook is taking care of releasing
	 * resources.
	 */
#if 0
	if (__static_context->init) {
		CRYPTO_set_mem_functions(
			__static_context->orig_m,
			__static_context->orig_r,
			__static_context->orig_f
		);
		memset(__static_context, 0, sizeof(*__static_context));

		OPENSSL_cleanup();
	}
#endif
}

#define __OPENSSL_MSG_SIZE 1024

static
int
__error_entry_openssl_status_cb(
	const char *str,
	size_t len __attribute__((unused)),
	void *u
) {
	char *buf = (char *)u;
	size_t s = strlen(buf);

	buf += s;
	s = __OPENSSL_MSG_SIZE - s;

	strncpy(buf, str, s-1);
	buf[s-1] = '\x0';

	return 1;
}

mycms_error_entry
_error_entry_openssl_status(
	const mycms_error_entry entry
) {
	char buf[__OPENSSL_MSG_SIZE];

	memset(buf, 0, sizeof(buf));
	_mycms_error_entry_prm_add_u32(entry, MYCMS_ERROR_KEY_OPENSSL_STATUS, ERR_peek_last_error());
	ERR_print_errors_cb(__error_entry_openssl_status_cb, buf);
	_mycms_error_entry_prm_add_str(entry, MYCMS_ERROR_KEY_OPENSSL_STATUS_STR, buf);
	return entry;
}

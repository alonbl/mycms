#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <string.h>

#include <mycms/mycms-static.h>

static struct {
	bool init;
} __static_context[1];

void
_mycms_error_static_init(void);

void
_mycms_openssl_static_init(
	const mycms_system system
);

void
_mycms_openssl_static_clean(
	const mycms_system system
);

bool
_mycms_certificate_static_init(
	const mycms_system system
);

bool
_mycms_certificate_static_clean(void);

bool
mycms_static_init(
	const mycms_system system __attribute__((unused))
) {
	if (!__static_context->init) {
		_mycms_error_static_init();
		_mycms_openssl_static_init(system);
		_mycms_certificate_static_init(system);
		__static_context->init = true;
	}

	return true;
}

bool
mycms_static_clean(
	const mycms_system system __attribute__((unused))
) {
	if (__static_context->init) {
		_mycms_openssl_static_clean(system);
		_mycms_certificate_static_clean();
		memset(__static_context, 0, sizeof(__static_context));
	}

	return true;
}

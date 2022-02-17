#ifndef __MYCMS_CONTEXT_INTERNAL_H
#define __MYCMS_CONTEXT_INTERNAL_H

#include <mycms/mycms-context.h>

void *
_mycms_context_get_pkcs11_state(
	const mycms_context context
);

bool
_mycms_context_set_pkcs11_state(
	const mycms_context context,
	void *pkcs11_state
);

#endif

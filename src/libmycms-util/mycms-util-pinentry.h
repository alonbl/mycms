#ifndef __MYCMS_PINENTRY_H
#define __MYCMS_PINENTRY_H

#include <mycms/mycms-context.h>

struct _mycms_util_pinentry_s;
typedef struct _mycms_util_pinentry_s *_mycms_pinentry;


_mycms_pinentry
_mycms_util_pinentry_new(
	const mycms_context context
);

bool
_mycms_util_pinentry_construct(
	const _mycms_pinentry pinentry,
	const char * const prog
);

bool
_mycms_util_pinentry_destruct(
	const _mycms_pinentry pinentry
);

mycms_context
_mycms_util_pinentry_get_context(
	const _mycms_pinentry pinentry
);

bool
_mycms_util_pinentry_exec(
	const _mycms_pinentry pinentry,
	const char * const title,
	const char * const prompt,
	char * const pin,
	const size_t pin_size
);

#endif

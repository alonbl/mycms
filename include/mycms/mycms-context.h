#ifndef __MYCMS_CONTEXT_H
#define __MYCMS_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "mycms-error.h"
#include "mycms-system.h"


#ifdef __cplusplus
extern "C" {
#endif

struct __mycms_context_s;
typedef struct __mycms_context_s *mycms_context;

mycms_context
mycms_context_new(
	const mycms_system system
);

bool
mycms_context_construct(
	const mycms_context context
);

bool
mycms_context_destruct(
	const mycms_context context
);

mycms_system
mycms_context_get_system(
	const mycms_context context
);

const void *
mycms_context_get_user_context(
	const mycms_context context
);

bool
mycms_context_set_user_context(
	const mycms_context context,
	void *user_context
);

mycms_error
mycms_context_get_error(
	const mycms_context context
);

void
mycms_context_error_reset(
	const mycms_context context
);

#ifdef __cplusplus
}
#endif

#endif

#ifndef __MYCMS_STATIC_H
#define __MYCMS_STATIC_H

#include "mycms-system.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
mycms_static_init(
	const mycms_system system
);

bool
mycms_static_clean(
	const mycms_system system
);

#ifdef __cplusplus
}
#endif

#endif

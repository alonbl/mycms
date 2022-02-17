#ifndef __MYCMS_UTIL_H
#define __MYCMS_UTIL_H

#include <stdlib.h>

#define _MYCMS_UTIL_MIN(x, y) ((x) < (y) ? (x) : (y))
#define _MYCMS_UTIL_MAX(x, y) ((x) > (y) ? (x) : (y))

const char *
_mycms_util_snprintf(
	char * const buf,
	size_t size,
	const char * const format,
	...
) __attribute__((format(printf, 3, 4)));

#endif

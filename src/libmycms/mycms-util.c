#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include <mycms/mycms-system.h>

#include "mycms-error-internal.h"
#include "mycms-util.h"

const char *
_mycms_util_snprintf(
	char * const buf,
	size_t size,
	const char * const format,
	...
) {
	va_list ap;

	va_start(ap, format);
	vsnprintf(buf, size, format, ap);
	va_end(ap);

	return buf;
}

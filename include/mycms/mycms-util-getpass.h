#ifndef __MYCMS_GETPASS_H
#define __MYCMS_GETPASS_H

#include "mycms-context.h"

const char *
mycms_util_getpass_usage(void);

bool
mycms_util_getpass(
	const mycms_context context,
	const char * const title,
	const char * const prompt,
	const char * const exp,
	char * const pass,
	const size_t size
);

#endif

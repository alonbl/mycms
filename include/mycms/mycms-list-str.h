#ifndef __MYCMS_LIST_STR_H
#define __MYCMS_LIST_STR_H

#include "mycms-system.h"
#include "mycms-list.h"

MYCMS_LIST_DECLARE(str, char *, str)

bool
mycms_list_str_add(
	const mycms_system system,
	mycms_list_str * const head,
	const char * const str
);

bool
mycms_list_str_free(
	const mycms_system system,
	const mycms_list_str head
);

#endif

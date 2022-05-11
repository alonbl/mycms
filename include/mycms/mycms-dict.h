#ifndef __MYCMS_DICT_H
#define __MYCMS_DICT_H

#include "mycms-context.h"
#include "mycms-list.h"

typedef struct {
	const char *k;
	const char *v;
} mycms_dict_entry;

MYCMS_LIST_DECLARE(dict_entry, mycms_dict_entry, entry)

struct mycms_dict_s;
typedef struct mycms_dict_s *mycms_dict;
typedef void (*mycms_dict_free_callback)(
	const mycms_dict dict,
	const void *p
);

mycms_dict
mycms_dict_new(
	const mycms_context context
);

bool
mycms_dict_construct(
	const mycms_dict dict
);

bool
mycms_dict_destruct(
	const mycms_dict dict
);

mycms_context
mycms_dict_get_context(
	const mycms_dict dict
);

bool
mycms_dict_entry_clear(
	const mycms_dict dict
);

bool
mycms_dict_entry_put(
	const mycms_dict dict,
	const char * const k,
	const char * const v
);

const char *
mycms_dict_entry_get(
	const mycms_dict dict,
	const char * const k,
	bool * const found
);

bool
mycms_dict_entry_del(
	const mycms_dict dict,
	const char * const k
);

mycms_list_dict_entry
mycms_dict_entries(
	const mycms_dict dict
);

#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <openssl/crypto.h>

#include <mycms/mycms-dict.h>

struct mycms_dict_s {
	mycms_context context;
	mycms_list_dict_entry head;
};

static
void
__free_entry(
	const mycms_system system,
	const mycms_list_dict_entry entry
) {
	if (entry != NULL) {
		mycms_system_free(system, "dict.entry.k", (void *)entry->entry.k);
		entry->entry.k = NULL;

		mycms_system_free(system, "dict.entry.v", (void *)entry->entry.v);
		entry->entry.v = NULL;

		mycms_system_free(system, "dict.entry", entry);
	}
}

mycms_dict
mycms_dict_new(
	const mycms_context context
) {
	mycms_system system = NULL;
	mycms_dict dict = NULL;

	if (context == NULL) {
		return NULL;
	}

	if ((system = mycms_context_get_system(context)) == NULL) {
		goto cleanup;
	}

	if ((dict = mycms_system_zalloc(system, "dict", sizeof(*dict))) == NULL) {
		goto cleanup;
	}

	dict->context = context;

cleanup:

	return dict;
}

bool
mycms_dict_construct(
	const mycms_dict dict
) {
	if (dict == NULL) {
		return false;
	}

	return true;
}

bool
mycms_dict_destruct(
	const mycms_dict dict
) {
	bool ret = true;

	if (dict != NULL) {
		mycms_system system = mycms_context_get_system(dict->context);

		ret = mycms_dict_entry_clear(dict) && ret;
		ret = mycms_system_free(system, "dict", dict) && ret;
	}

	return ret;
}

mycms_context
mycms_dict_get_context(
	const mycms_dict dict
) {
	mycms_context ret = NULL;

	if (dict == NULL) {
		goto cleanup;
	}

	ret = dict->context;

cleanup:

	return ret;
}

bool
mycms_dict_entry_clear(
	const mycms_dict dict
) {
	mycms_system system = NULL;
	bool ret = false;

	if (dict == NULL) {
		goto cleanup;
	}

	if ((system = mycms_context_get_system(dict->context)) == NULL) {
		goto cleanup;
	}

	while(dict->head != NULL) {
		mycms_list_dict_entry t = dict->head;
		dict->head = dict->head->next;
		__free_entry(system, t);
	}

	ret = true;

cleanup:

	return ret;
}

bool
mycms_dict_entry_put(
	const mycms_dict dict,
	const char * const k,
	const char * const v
) {
	mycms_system system = NULL;
	mycms_list_dict_entry t = NULL;
	const char *vdup = NULL;
	bool ret = false;

	if (dict == NULL) {
		return false;
	}

	if (k == NULL) {
		goto cleanup;
	}

	if ((system = mycms_context_get_system(dict->context)) == NULL) {
		goto cleanup;
	}

	if (v != NULL) {
		if ((vdup = mycms_system_strdup(system, "dict.entry.v", v)) == NULL) {
			goto cleanup;
		}
	}

	for (t = dict->head; t != NULL; t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}
	if (t != NULL) {
		mycms_system_free(system, "dict.entry.v", (void *)t->entry.v);
		t->entry.v = vdup;
		vdup = NULL;
		t = NULL;
	} else {
		if ((t = mycms_system_zalloc(system, "dict.entry", sizeof(*t))) == NULL) {
			goto cleanup;
		}
		if ((t->entry.k = mycms_system_strdup(system, "dict.entry.k", k)) == NULL) {
			goto cleanup;
		}
		t->entry.v = vdup;
		vdup = NULL;
		t->next = dict->head;
		dict->head = t;
		t = NULL;
	}

	ret = true;

cleanup:
	__free_entry(system, t);

	return ret;
}

const char *
mycms_dict_entry_get(
	const mycms_dict dict,
	const char * const k,
	bool * const found
) {
	mycms_list_dict_entry t;
	const char *ret = NULL;

	if (found != NULL) {
		*found = false;
	}

	if (dict == NULL) {
		return NULL;
	}

	if (k == NULL) {
		goto cleanup;
	}

	for (t = dict->head; t != NULL; t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}

	if (t != NULL) {
		if (found != NULL) {
			*found = true;
		}
		ret = t->entry.v;
	}

cleanup:

	return ret;
}

bool
mycms_dict_entry_del(
	const mycms_dict dict,
	const char * const k
) {
	mycms_system system = NULL;
	mycms_list_dict_entry p;
	mycms_list_dict_entry t;
	bool ret = false;

	if (dict == NULL) {
		goto cleanup;
	}

	if (k == NULL) {
		goto cleanup;
	}

	if ((system = mycms_context_get_system(dict->context)) == NULL) {
		goto cleanup;
	}

	for (p = NULL, t = dict->head; t != NULL; p = t, t = t->next) {
		if (!strcmp(k, t->entry.k)) {
			break;
		}
	}

	if (t != NULL) {
		if (p == NULL) {
			dict->head = t->next;
		} else {
			p->next = t->next;
		}
		__free_entry(system, t);
		t = NULL;
	}

	ret = true;

cleanup:

	return ret;
}

mycms_list_dict_entry
mycms_dict_entries(
	const mycms_dict dict
) {
	if (dict == NULL) {
		return NULL;
	}

	return dict->head;
}

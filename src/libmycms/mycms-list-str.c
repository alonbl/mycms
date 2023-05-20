#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <mycms/mycms-list-str.h>

bool
mycms_list_str_add(
	const mycms_system system,
	mycms_list_str * const head,
	const char * const str
) {
	bool ret = false;

	mycms_list_str t;
	if ((t = mycms_system_zalloc(system, "mycms_list_str_add.new", sizeof(*t))) == NULL) {
	       goto cleanup;
	}
	if ((t->str = mycms_system_strdup(system, "mycms_list_str_add.dup", str)) == NULL) {
	       goto cleanup;
	}

	if (*head == NULL) {
		*head = t;
	} else {
		mycms_list_str i;
		for (i = *head;i->next != NULL; i = i->next);
		i->next = t;
	}

	ret = true;

cleanup:

	return ret;
}

bool
mycms_list_str_free(
	const mycms_system system,
	const mycms_list_str head
) {
	mycms_list_str h = head;
	while (h != NULL) {
		mycms_list_str t = h;
		h = h->next;
		mycms_system_free(system, "mycms_list_str_free.str", t->str);
		mycms_system_free(system, "mycms_list_str_free", t);
	}

	return true;
}

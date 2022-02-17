#ifndef __MYCMS_CMD_ENCRYPT_H
#define __MYCMS_CMD_ENCRYPT_H

int
_cmd_encrypt(
	const mycms_context context,
	int argc,
	char *argv[]
);

int
_cmd_encrypt_add(
	const mycms_context context,
	int argc,
	char *argv[]
);

int
_cmd_encrypt_reset(
	const mycms_context context,
	int argc,
	char *argv[]
);

#endif

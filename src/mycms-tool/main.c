#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include <mycms/mycms-static.h>

#include "cmd-common.h"
#include "cmd-decrypt.h"
#include "cmd-encrypt.h"
#include "cmd-sign.h"
#include "cmd-verify.h"
#include "getoptutil.h"

static const char *__FEATURES[] = {
	"sane",
#if defined(ENABLE_PINENTRY)
	"pinentry",
#endif
#if defined(ENABLE_IO_DRIVER_FILE)
	"io-driver-file",
#endif
#if defined(ENABLE_CERTIFICATE_DRIVER_FILE)
	"certificate-driver-file",
#endif
#if defined(ENABLE_CERTIFICATE_DRIVER_PKCS11)
	"certificate-driver-pkcs11",
#endif
#if defined(ENABLE_CMS_SIGN)
	"sign",
#endif
#if defined(ENABLE_CMS_VERIFY)
	"verify",
#endif
#if defined(ENABLE_CMS_ENCRYPT)
	"encrypt",
#endif
#if defined(ENABLE_CMS_DECRYPT)
	"decrypt",
#endif
	NULL
};

int main(int argc, char *argv[]) {
	enum {
		OPT_HELP = 0x1000,
		OPT_VERSION,
		OPT_VERBOSE,
		OPT_STDIO_EOL,
		OPT_MAX
	};

	static struct commands_s {
		const char *c;
		const char *m;
		int (*f)(const mycms_context context, int argc, char *argv[]);
	} commands[] = {
#if defined(ENABLE_CMS_SIGN)
		{"sign", "sign data", _cmd_sign},
#endif
#if defined(ENABLE_CMS_VERIFY)
		{"verify-list", "list signers", _cmd_verify_list},
		{"verify", "verift signature", _cmd_verify},
#endif
#if defined(ENABLE_CMS_ENCRYPT)
		{"encrypt", "encrypt data to recipients", _cmd_encrypt},
		{"encrypt-add", "add recipients in existing cms", _cmd_encrypt_add},
		{"encrypt-reset", "reset recipients in existing cms", _cmd_encrypt_reset},
#endif
#if defined(ENABLE_CMS_DECRYPT)
		{"decrypt", "decrypt cms", _cmd_decrypt},
#endif
		{NULL, NULL, NULL}
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"version\0print version", no_argument, NULL, OPT_VERSION},
		{"verbose\0verbose diagnostics", no_argument, NULL, OPT_VERBOSE},
		{"stdio-eol\0stdio eol, either crlf or lf", required_argument, NULL, OPT_STDIO_EOL},
		{NULL, 0, NULL, 0}
	};

	mycms_system system = NULL;
	mycms_context context = NULL;
	struct commands_s *cmd;
	const char *command;
	bool verbose = false;
	char optstring[1024];
	int option;
	int ret = 1;

	if ((system = mycms_system_new()) == NULL) {
		goto cleanup;
	}

	if (!mycms_system_construct(system)) {
		goto cleanup;
	}

	if (!mycms_static_init(system)) {
		fprintf(stderr, "Failed to initialize certificate interface\n");
		goto cleanup;
	}

	if ((context = mycms_context_new(system)) == NULL) {
		goto cleanup;
	}

	if (!mycms_context_construct(context)) {
		goto cleanup;
	}

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		fprintf(stderr, "Failed to construct options");
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "command [options]", long_options);
				printf("\nAvailable commands:\n");
				for (cmd = commands; cmd->c != NULL; cmd++) {
					printf("%8s%-16s - %s\n", "", cmd->c, cmd->m);
				}
				ret = 0;
				goto cleanup;
			case OPT_VERSION:
				printf("%s-%s\n", PACKAGE_NAME, PACKAGE_VERSION);
				printf("Features:");
				{
					const char **p;
					for (p = __FEATURES; *p != NULL; p++) {
						printf(" %s", *p);
					}
				}
				printf("\n");
				ret = 0;
				goto cleanup;
			case OPT_VERBOSE:
				verbose = true;
			break;
			case OPT_STDIO_EOL:
#ifdef _WIN32
				if (!strcmp(optarg, "crlf")) {
				} else if (!strcmp(optarg, "lf")) {
					_setmode(0, _O_BINARY);
					_setmode(1, _O_BINARY);
					_setmode(2, _O_BINARY);
#else
				if (!strcmp(optarg, "lf")) {
#endif
				} else {
					fprintf(stderr, "Invalid stdio eol '%s'\n", optarg);
				}
			break;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "Command is missing\n");
		goto cleanup;
	}

	command = argv[optind++];

	for (cmd = commands; cmd->c != NULL; cmd++) {
		if (!strcmp(command, cmd->c)) {
			ret = cmd->f(context, argc, argv);
			goto cleanup;
		}
	}

	fprintf(stderr, "Unknown command '%s'\n", command);

cleanup:

	if (system != NULL) {
		mycms_error error = mycms_system_get_error(system);

		if (mycms_error_has_error(error)) {
			char buf[10 * 1024];
			uint32_t code;

			mycms_error_format_simple(error, &code, buf, sizeof(buf));
			fprintf(stderr, "ERROR: %08x: %s\n", code, buf);

			if (verbose) {
				mycms_error_format(error, buf, sizeof(buf));
				fputs(buf, stderr);
			}
		}
	}

	mycms_context_destruct(context);
	mycms_static_clean(system);
	mycms_system_destruct(system);

	return ret;
}

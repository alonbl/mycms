#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <mycms/mycms.h>

#include "getoptutil.h"
#include "util.h"

#include "cmd-common.h"
#include "cmd-sign.h"

int
_cmd_sign(
	const mycms_context context,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_DIGEST,
		OPT_SIGNER_CERT,
		OPT_SIGNER_CERT_PASS,
		OPT_KEYOPT,
		OPT_CMS_IN,
		OPT_CMS_OUT,
		OPT_DATA_IN,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"digest\0DIGEST|digest to use, default is SHA3-256", required_argument, NULL, OPT_DIGEST},
		{"signer-cert\0CERTIFICATE_EXPRESSION|signer certificate to use", required_argument, NULL, OPT_SIGNER_CERT},
		{"signer-cert-pass\0PASSPHRASE_EXPRESSION|signer certificate passphrase to use", required_argument, NULL, OPT_SIGNER_CERT_PASS},
		{"keyopt\0KEYOPT|key options opt:value, may be specified multiple times", required_argument, NULL, OPT_KEYOPT},
		{"cms-in\0FILE|input cms for resign", required_argument, NULL, OPT_CMS_IN},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"data-in\0FILE|input text data", required_argument, NULL, OPT_DATA_IN},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char * certificate_exp = NULL;
	const char * pass_exp = NULL;

	mycms_system system = mycms_context_get_system(context);
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io cms_out = NULL;
	mycms_io data_in = NULL;
	mycms_dict certificate_dict = NULL;
	mycms_dict pass_dict = NULL;
	mycms_list_str keyopts = NULL;
	mycms_certificate certificate = NULL;
	mycms_list_str digests = NULL;

	if ((mycms = mycms_new(context)) == NULL) {
		goto cleanup;
	}

	if (!mycms_construct(mycms)) {
		goto cleanup;
	}

	if (!getoptutil_short_from_long(long_options, "+", optstring, sizeof(optstring))) {
		fprintf(stderr, "Failed to construct options");
		goto cleanup;
	}

	while ((option = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (option) {
			case OPT_HELP:
				getoptutil_usage(stdout, argv[0], "sign [options]", long_options);
				_cmd_common_extra_usage();
				ret = 0;
				goto cleanup;
			case OPT_DIGEST:
				if (!mycms_list_str_add(system, &digests, optarg)) {
					goto cleanup;
				}
			break;
			case OPT_CMS_IN:
				if ((cms_in = mycms_io_new(context)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(cms_in)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(cms_in, optarg, "rb")) {
					goto cleanup;
				}
			break;
			case OPT_CMS_OUT:
				if ((cms_out = mycms_io_new(context)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(cms_out)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(cms_out, optarg, "wb")) {
					goto cleanup;
				}
			break;
			case OPT_DATA_IN:
				if ((data_in = mycms_io_new(context)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(data_in)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(data_in, optarg, "rb")) {
					goto cleanup;
				}
			break;
			case OPT_SIGNER_CERT:
				certificate_exp = optarg;
			break;
			case OPT_SIGNER_CERT_PASS:
				pass_exp = optarg;
			break;
			case OPT_KEYOPT:
				if (!mycms_list_str_add(system, &keyopts, optarg)) {
					goto cleanup;
				}
			break;
			default:
				fprintf(stderr, "Invalid option\n");
				goto cleanup;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unexpected positional options\n");
		goto cleanup;
	}

	if (certificate_exp == NULL) {
		fprintf(stderr, "Certificate is mandatory\n");
		goto cleanup;
	}
	if (cms_out == NULL) {
		fprintf(stderr, "CMS out is mandatory\n");
		goto cleanup;
	}

	if (digests == NULL) {
		mycms_list_str_add(system, &digests, "SHA3-256");
	}

	if ((certificate_dict = mycms_dict_new(context)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(certificate_dict)) {
		goto cleanup;
	}

	if (!util_split_string(certificate_dict, certificate_exp)) {
		goto cleanup;
	}

	if ((pass_dict = mycms_dict_new(context)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(pass_dict)) {
		goto cleanup;
	}

	if (!util_split_string(pass_dict, pass_exp)) {
		goto cleanup;
	}

	if ((certificate = mycms_certificate_new(context)) == NULL) {
		goto cleanup;
	}

	if (!mycms_certificate_construct(certificate)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_userdata(certificate, pass_dict)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_passphrase_callback(certificate, _cmd_common_passphrase_callback)) {
		goto cleanup;
	}

	{
		_cmd_common_certificate_driver_apply x;
		if ((x = _cmd_common_get_certificate_driver(&certificate_exp)) == NULL) {
			fprintf(stderr, "Cannot resolve certificate expression");
			goto cleanup;
		}
		if (!x(certificate)) {
			fprintf(stderr, "Cannot apply certificate expression");
			goto cleanup;
		}
	}

	if (!mycms_certificate_load(certificate, certificate_dict)) {
		goto cleanup;
	}

	if (!mycms_sign(mycms, certificate, digests, keyopts, cms_in, cms_out, data_in)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_list_str_free(system, digests);
	digests = NULL;

	mycms_list_str_free(system, keyopts);
	keyopts = NULL;

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_io_destruct(cms_out);
	cms_out = NULL;

	mycms_io_destruct(data_in);
	data_in = NULL;

	mycms_certificate_destruct(certificate);
	certificate = NULL;

	mycms_dict_destruct(certificate_dict);
	certificate_dict = NULL;

	mycms_dict_destruct(pass_dict);
	pass_dict = NULL;

	mycms_destruct(mycms);
	mycms = NULL;

	return ret;
}

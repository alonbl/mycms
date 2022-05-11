#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include <mycms/mycms.h>

#include "getoptutil.h"
#include "util.h"

#include "cmd-common.h"
#include "cmd-encrypt.h"

int
_cmd_encrypt(
	const mycms_context context,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CIPHER,
		OPT_CMS_OUT,
		OPT_DATA_PT,
		OPT_DATA_CT,
		OPT_TO,
		OPT_KEYOPT,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cipher\0CIPHER|cipher to use, default is AES-256-CBC", required_argument, NULL, OPT_CIPHER},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"data-pt\0FILE|input plain text data", required_argument, NULL, OPT_DATA_PT},
		{"data-ct\0FILE|output plain text data", required_argument, NULL, OPT_DATA_CT},
		{"to\0FILE|target DER encoded certificate, may be specified several times", required_argument, NULL, OPT_TO},
		{"keyopt\0KEYOPT_EXPRESSION|key options expression", required_argument, NULL, OPT_KEYOPT},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char *cipher = "AES-256-CBC";

	const char * keyopt_exp = NULL;

	mycms_system system = mycms_context_get_system(context);
	mycms mycms = NULL;
	mycms_io cms_out = NULL;
	mycms_io data_pt = NULL;
	mycms_io data_ct = NULL;
	mycms_list_blob to = NULL;
	mycms_dict keyopt_dict = NULL;

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
				getoptutil_usage(stdout, argv[0], "encrypt [options]", long_options);
				_cmd_common_extra_usage();
				ret = 0;
				goto cleanup;
			case OPT_CIPHER:
				cipher = optarg;
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
			case OPT_DATA_PT:
				if ((data_pt = mycms_io_new(context)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(data_pt)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(data_pt, optarg, "rb")) {
					goto cleanup;
				}
			break;
			case OPT_DATA_CT:
				if ((data_ct = mycms_io_new(context)) == NULL) {
					goto cleanup;
				}
				if (!mycms_io_construct(data_ct)) {
					goto cleanup;
				}
				if (!mycms_io_open_file(data_ct, optarg, "wb")) {
					goto cleanup;
				}
			break;
			case OPT_TO:
				{
					mycms_list_blob t;

					if ((t = mycms_system_zalloc(system, "to", sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!_cmd_common_load_cert(system, optarg, &t->blob)) {
						fprintf(stderr, "Cannot load certificate");
						mycms_system_free(system, "to", t);
						goto cleanup;
					}

					t->next = to;
					to = t;
				}
			break;
			case OPT_KEYOPT:
				keyopt_exp = optarg;
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

	if (cms_out == NULL) {
		fprintf(stderr, "CMS out is mandatory\n");
		goto cleanup;
	}
	if (data_pt == NULL) {
		fprintf(stderr, "Data PT is mandatory\n");
		goto cleanup;
	}
	if (data_ct == NULL) {
		fprintf(stderr, "Data CT is mandatory\n");
		goto cleanup;
	}

	if ((keyopt_dict = mycms_dict_new(context)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(keyopt_dict)) {
		goto cleanup;
	}

	if (!util_split_string(keyopt_dict, keyopt_exp)) {
		goto cleanup;
	}

	if (!mycms_encrypt(mycms, cipher, to, keyopt_dict, cms_out, data_pt, data_ct)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_out);
	cms_out = NULL;

	mycms_io_destruct(data_pt);
	data_pt = NULL;

	mycms_io_destruct(data_ct);
	data_ct = NULL;

	mycms_dict_destruct(keyopt_dict);
	keyopt_dict = NULL;

	while(to != NULL) {
		mycms_list_blob t = to;
		to = to->next;
		t->next = NULL;
		mycms_system_free(system, "to.data", t->blob.data);
		t->blob.data = NULL;
		mycms_system_free(system, "to", t);
	}

	mycms_destruct(mycms);
	mycms = NULL;

	return ret;
}

int
_cmd_encrypt_add(
	const mycms_context context,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_CMS_OUT,
		OPT_RECIP_CERT,
		OPT_RECIP_CERT_PASS,
		OPT_TO,
		OPT_KEYOPT,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-in\0FILE|input cms", required_argument, NULL, OPT_CMS_IN},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"recip-cert\0CERTIFICATE_EXPRESSION|recipient certificate to use", required_argument, NULL, OPT_RECIP_CERT},
		{"recip-cert-pass\0PASSPHRASE_EXPRESSION|recipient certificate passphrase to use", required_argument, NULL, OPT_RECIP_CERT_PASS},
		{"to\0FILE|target DER encoded certificate, may be specified several times", required_argument, NULL, OPT_TO},
		{"keyopt\0KEYOPT_EXPRESSION|key options expression", required_argument, NULL, OPT_KEYOPT},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	const char * certificate_exp = NULL;
	const char * pass_exp = NULL;
	const char * keyopt_exp = NULL;

	mycms_system system = mycms_context_get_system(context);
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io cms_out = NULL;
	mycms_list_blob to = NULL;
	mycms_dict keyopt_dict = NULL;
	mycms_dict certificate_dict = NULL;
	mycms_dict pass_dict = NULL;
	mycms_certificate certificate = NULL;

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
				getoptutil_usage(stdout, argv[0], "encrypt-add [options]", long_options);
				_cmd_common_extra_usage();
				ret = 0;
				goto cleanup;
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
			case OPT_RECIP_CERT:
				certificate_exp = optarg;
			break;
			case OPT_RECIP_CERT_PASS:
				pass_exp = optarg;
			break;
			case OPT_TO:
				{
					mycms_list_blob t;

					if ((t = mycms_system_zalloc(system, "to", sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!_cmd_common_load_cert(system, optarg, &t->blob)) {
						fprintf(stderr, "Cannot load certificate");
						mycms_system_free(system, "to", t);
						goto cleanup;
					}

					t->next = to;
					to = t;
				}
			break;
			case OPT_KEYOPT:
				keyopt_exp = optarg;
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
	if (cms_in == NULL) {
		fprintf(stderr, "CMS in is mandatory\n");
		goto cleanup;
	}
	if (cms_out == NULL) {
		fprintf(stderr, "CMS out is mandatory\n");
		goto cleanup;
	}
	if (to == NULL) {
		fprintf(stderr, "To is mandatory\n");
		goto cleanup;
	}

	if ((certificate = mycms_certificate_new(context)) == NULL) {
		goto cleanup;
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

	if (!mycms_certificate_construct(certificate)) {
		goto cleanup;
	}

	if (!mycms_certificate_set_userdata(certificate, pass_dict)) {
		goto cleanup;
	}

	if ((keyopt_dict = mycms_dict_new(context)) == NULL) {
		goto cleanup;
	}

	if (!mycms_dict_construct(keyopt_dict)) {
		goto cleanup;
	}

	if (!util_split_string(keyopt_dict, keyopt_exp)) {
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

	if (!mycms_encrypt_add(mycms, certificate, to, keyopt_dict, cms_in, cms_out)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_io_destruct(cms_out);
	cms_out = NULL;

	mycms_certificate_destruct(certificate);
	certificate = NULL;

	mycms_dict_destruct(certificate_dict);
	certificate_dict = NULL;

	mycms_dict_destruct(pass_dict);
	pass_dict = NULL;

	mycms_dict_destruct(keyopt_dict);
	keyopt_dict = NULL;

	while(to != NULL) {
		mycms_list_blob t = to;
		to = to->next;
		t->next = NULL;
		mycms_system_free(system, "to.data", t->blob.data);
		t->blob.data = NULL;
		mycms_system_free(system, "to", t);
	}

	mycms_destruct(mycms);
	mycms = NULL;

	return ret;
}

int
_cmd_encrypt_reset(
	const mycms_context context,
	int argc,
	char *argv[]
) {
	enum {
		OPT_HELP = 0x1000,
		OPT_CMS_IN,
		OPT_CMS_OUT,
		OPT_TO,
		OPT_MAX
	};

	static struct option long_options[] = {
		{"help\0this usage", no_argument, NULL, OPT_HELP},
		{"cms-in\0FILE|input cms", required_argument, NULL, OPT_CMS_IN},
		{"cms-out\0FILE|output cms", required_argument, NULL, OPT_CMS_OUT},
		{"to\0FILE|target DER encoded certificate, may be specified several times", required_argument, NULL, OPT_TO},
		{NULL, 0, NULL, 0}
	};

	char optstring[1024];
	int option;
	int ret = 1;

	mycms_system system = mycms_context_get_system(context);
	mycms mycms = NULL;
	mycms_io cms_in = NULL;
	mycms_io cms_out = NULL;
	mycms_list_blob to = NULL;

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
				getoptutil_usage(stdout, argv[0], "encrypt-add [options]", long_options);
				_cmd_common_extra_usage();
				ret = 0;
				goto cleanup;
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
			case OPT_TO:
				{
					mycms_list_blob t;

					if ((t = mycms_system_zalloc(system, "to", sizeof(*t))) == NULL) {
						goto cleanup;
					}

					if (!_cmd_common_load_cert(system, optarg, &t->blob)) {
						fprintf(stderr, "Cannot load certificate");
						mycms_system_free(system, "to", t);
						goto cleanup;
					}

					t->next = to;
					to = t;
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
	if (cms_in == NULL) {
		fprintf(stderr, "CMS in is mandatory\n");
		goto cleanup;
	}
	if (cms_out == NULL) {
		fprintf(stderr, "CMS out is mandatory\n");
		goto cleanup;
	}
	if (to == NULL) {
		fprintf(stderr, "To is mandatory\n");
		goto cleanup;
	}

	if (!mycms_encrypt_reset(mycms, to, cms_in, cms_out)) {
		goto cleanup;
	}

	ret = 0;

cleanup:

	mycms_io_destruct(cms_in);
	cms_in = NULL;

	mycms_io_destruct(cms_out);
	cms_out = NULL;

	while(to != NULL) {
		mycms_list_blob t = to;
		to = to->next;
		t->next = NULL;
		mycms_system_free(system, "to.data", t->blob.data);
		t->blob.data = NULL;
		mycms_system_free(system, "to", t);
	}

	mycms_destruct(mycms);
	mycms = NULL;

	return ret;
}

/*
 * Differential test of the exported C API: load one res_digium_phone.so
 * (the original or ours) outside Asterisk, with stub Asterisk symbols,
 * run the same calls, and print the results.  Diff the output of both.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ---- Asterisk data symbols ---- */
const char *ast_config_AST_CONFIG_DIR = "/etc/asterisk";
const char *ast_config_AST_VAR_DIR = "/var/lib/asterisk";
unsigned int ast_options[4];
int option_debug, option_verbose, ast_verb_sys_level;
const char __ast_string_field_empty[] = "";

/* ---- Asterisk functions with behavior ---- */
void *__ast_calloc(size_t n, size_t s, const char *f, int l, const char *fn) { return calloc(n, s); }
void *__ast_malloc(size_t s, const char *f, int l, const char *fn) { return malloc(s); }
void *__ast_realloc(void *p, size_t s, const char *f, int l, const char *fn) { return realloc(p, s); }
void __ast_free(void *p, const char *f, int l, const char *fn) { free(p); }
void ast_free_ptr(void *p) { free(p); }
void ast_std_free(void *p) { free(p); }
char *__ast_strdup(const char *s, const char *f, int l, const char *fn) { return s ? strdup(s) : NULL; }
char *__ast_strndup(const char *s, size_t n, const char *f, int l, const char *fn) { return s ? strndup(s, n) : NULL; }
int __ast_vasprintf(char **ret, const char *fmt, va_list ap, const char *f, int l, const char *fn) { return vasprintf(ret, fmt, ap); }

struct ast_str { size_t len; size_t used; void *ts; char str[]; };
int __ast_str_helper(struct ast_str **buf, ssize_t max_len, int append, const char *fmt, va_list ap,
	const char *file, int lineno, const char *function)
{
	va_list aq;
	size_t off = append ? (*buf)->used : 0;
	int need;

	va_copy(aq, ap);
	need = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);
	if (need < 0) {
		return -1;
	}
	if (off + need + 1 > (*buf)->len) {
		struct ast_str *n = realloc(*buf, sizeof(**buf) + off + need + 1);
		if (!n) {
			return -1;
		}
		n->len = off + need + 1;
		*buf = n;
	}
	vsnprintf((*buf)->str + off, (*buf)->len - off, fmt, ap);
	(*buf)->used = off + need;
	return need;
}

void ast_log(int level, const char *file, int line, const char *func, const char *fmt, ...)
{
	va_list ap;
	printf("    LOG: ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

/* A "channel" here is a pointer to its technology: { const char *type; }. */
void *ast_channel_tech(void *chan) { return chan; }

static int module_refs;
void __ast_module_ref(void *m, const char *f, int l, const char *fn) { module_refs++; }
void __ast_module_unref(void *m, const char *f, int l, const char *fn) { module_refs--; }

/* ---- helpers ---- */
static void *lib;
#define F(name) ((__typeof__(&name##_t)) sym(#name))
static void *sym(const char *n)
{
	void *p = dlsym(lib, n);
	if (!p) {
		printf("MISSING %s\n", n);
		exit(1);
	}
	return p;
}

static void dump(const char *what, const char *buf, size_t n)
{
	size_t i;
	printf("  %s [", what);
	for (i = 0; i < n; i++) {
		unsigned char c = buf[i];
		if (c >= 32 && c < 127) putchar(c); else printf("\\x%02x", c);
	}
	printf("]\n");
}

static void ptr_in(const char *what, const char *p, const char *base, size_t n)
{
	if (!p) printf("  %s NULL\n", what);
	else if (p >= base && p < base + n) printf("  %s +%ld '%s'\n", what, (long)(p - base), p);
	else printf("  %s outside '%s'\n", what, p);
}

/* prototypes (for F()) */
char *phone_utils_xml_escape_t(const char *, char *, int);
void phone_utils_parse_uri_t(char *, char **, char **);
int phone_utils_str_to_uint_t(const char *, unsigned int *);
int phone_utils_verify_user_agent_t(const char *);
int phone_utils_get_model_t(const char *, char *);
struct ast_str *phone_utils_shell_quoted_t(const char *);
struct ast_str *phone_utils_filename_to_fullpath_t(const char *, const char *);
int dpma_asprintf_t(char **, const char *, ...);
int dpma_config_auth_flags_t(void *);
const char *dpma_config_password_t(void *);
void dpma_append_config_file_dir_t(char *, unsigned int, const char *, void *);
void *dpma_config_get_t(void);
void dpma_config_unref_t(void *);
const char *phone_users_line_get_name_t(void *);

struct cfgh { int (*handler)(void *); struct cfgh *next; };
struct infoh { const char *tech; int (*send)(void *, void *, const char *, const char *, const char *); struct infoh *next; };
int dpma_register_config_handler_t(struct cfgh *);
void dpma_unregister_config_handler_t(struct cfgh *);
void dpma_process_config_handlers_t(void *);
int dpma_register_info_handler_t(struct infoh *);
void dpma_unregister_info_handler_t(struct infoh *);
int dpma_info_send_t(void *, void *, const char *, const char *, const char *);
int dpma_register_pjsip_endpoint_is_dphone_t(int (*)(const char *));
void dpma_unregister_pjsip_endpoint_is_dphone_t(void);
int dpma_pjsip_endpoint_is_dphone_t(const char *);

static int hA(void *l) { printf("    handler A(%p)\n", l); return 0; }
static int hB(void *l) { printf("    handler B(%p)\n", l); return 0; }
static int hC(void *l) { printf("    handler C(%p)\n", l); return 0; }
static int sendX(void *c, void *h, const char *ct, const char *b, const char *ua)
{
	printf("    sendX(%s, %p, %s, %s, %p)\n", *(const char **) c, h, ct ? ct : "NULL", b ? b : "NULL", (void *) ua);
	return 7;
}
static int sendY(void *c, void *h, const char *ct, const char *b, const char *ua) { printf("    sendY\n"); return 9; }
static int isd(const char *e) { printf("    isd(%s)\n", e); return 42; }

int main(int argc, char **argv)
{
	static const char *strs[] = { "", "abc", "a&b", "<tag attr=\"v\">'x'</tag>", "&&&&", "\"\"\"", "\xc3\xa9<>", "x<y", "&", NULL };
	static const char *uris[] = { "sip:1001@127.0.0.1:5060;transport=udp", "sip:host", "nocolon", "",
		"pjsip:a@b;x=1;transport=tcp;y=2", "sip:a@b@c;transport=", "sip:a;transporT=tls",
		"sip:a;transport=tls;transport=udp", "sip:a;transpor", ":", "sip:@;", NULL };
	static const char *nums[] = { "0", "42", "-1", " 5", "0x1f", "010", "4294967296", "12abc", "", "+7", " -3", "99999999999999999999", NULL };
	static const char *uas[] = { "", "Digium D65", "SANGOMA P330", "sangoma", "xdigiumx", "Polycom", "Sangoma P", NULL };
	static const char *models[] = { "", "Digium D65 2_9_17", "digium D65", "D x", "Sangoma P330 1.0", "Sangoma_P330 x",
		"Polycom VVX", "digium  double", "Digium", "di D70 y", "sangoma p x", "SANGOMA P315 3", NULL };
	static const char *quotes[] = { "", "abc", "it's", "''", "a b", "x'y'z'", NULL };
	int i, n;
	char buf[128];

	lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!lib) {
		printf("dlopen: %s\n", dlerror());
		return 1;
	}

	printf("== xml_escape\n");
	for (i = 0; strs[i]; i++) {
		for (n = 0; n <= 14; n++) {
			char *r;
			memset(buf, 'Z', sizeof(buf));
			r = F(phone_utils_xml_escape)(strs[i], buf + 1, n);
			printf(" '%s' %d ret %+ld\n", strs[i], n, (long)(r - (buf + 1)));
			dump("out", buf, n + 3);
		}
		memset(buf, 'Z', sizeof(buf));
		F(phone_utils_xml_escape)(strs[i], buf + 1, 64);
		dump("out64", buf, 64);
	}

	printf("== parse_uri\n");
	for (i = 0; uris[i]; i++) {
		int t;
		for (t = 0; t < 2; t++) {
			char u[128], *addr = (char *) 1, *tr = (char *) 1;
			size_t len = strlen(uris[i]) + 1;
			memcpy(u, uris[i], len);
			F(phone_utils_parse_uri)(u, &addr, t ? &tr : NULL);
			printf(" '%s' transport=%d\n", uris[i], t);
			dump("buf", u, len);
			ptr_in("addr", addr, u, len);
			if (t) ptr_in("transport", tr, u, len);
		}
	}
	{
		char *addr = (char *) 1, *tr = (char *) 1;
		F(phone_utils_parse_uri)(NULL, &addr, &tr);
		printf(" NULL: addr '%s' transport '%s'\n", addr, tr);
	}

	printf("== str_to_uint\n");
	for (i = 0; nums[i]; i++) {
		unsigned int out = 0xdeadbeef;
		int r = F(phone_utils_str_to_uint)(nums[i], &out);
		printf(" '%s' -> %d %u\n", nums[i], r, out);
	}

	printf("== verify_user_agent\n");
	printf(" NULL -> %d\n", F(phone_utils_verify_user_agent)(NULL));
	for (i = 0; uas[i]; i++) printf(" '%s' -> %d\n", uas[i], F(phone_utils_verify_user_agent)(uas[i]));

	printf("== get_model\n");
	memset(buf, 'Z', sizeof(buf));
	printf(" NULL -> %d\n", F(phone_utils_get_model)(NULL, buf));
	for (i = 0; models[i]; i++) {
		memset(buf, 'Z', sizeof(buf));
		n = F(phone_utils_get_model)(models[i], buf);
		printf(" '%s' -> %d\n", models[i], n);
		dump("model", buf, 12);
	}

	printf("== shell_quoted\n");
	for (i = 0; quotes[i]; i++) {
		struct ast_str *s = F(phone_utils_shell_quoted)(quotes[i]);
		printf(" '%s' -> len %zu used %zu '%s'\n", quotes[i], s->len, s->used, s->str);
		free(s);
	}

	printf("== filename_to_fullpath\n");
	{
		const char *names[] = { NULL, "", "/abs/f", "rel", "rel" };
		const char *dirs[] = { "/d", "/d", "/d", "/d", NULL };
		for (i = 0; i < 5; i++) {
			struct ast_str *s = F(phone_utils_filename_to_fullpath)(names[i], dirs[i]);
			printf(" %s,%s -> len %zu used %zu '%s'\n", names[i] ? names[i] : "NULL", dirs[i] ? dirs[i] : "NULL", s->len, s->used, s->str);
			free(s);
		}
		{
			char longname[200];
			struct ast_str *s;
			memset(longname, 'n', 199);
			longname[199] = 0;
			s = F(phone_utils_filename_to_fullpath)(longname, "/d");
			printf(" long -> len %zu used %zu\n", s->len, s->used);
			free(s);
		}
	}

	printf("== dpma_asprintf\n");
	{
		char *r = NULL;
		n = F(dpma_asprintf)(&r, "%s-%d-%.2f", "x", 5, 1.5);
		printf(" %d '%s'\n", n, r);
		free(r);
	}

	printf("== config (no current config)\n");
	{
		int (*ig[5])(void *) = {
			(void *) sym("dpma_config_auth_flags"), (void *) sym("dpma_config_enable_discovery"),
			(void *) sym("dpma_config_initial_threads"), (void *) sym("dpma_config_max_threads"),
			(void *) sym("dpma_config_delay") };
		const char *(*sg[13])(void *) = {
			(void *) sym("dpma_config_password"), (void *) sym("dpma_config_mdns_addr"),
			(void *) sym("dpma_config_mdns_port"), (void *) sym("dpma_config_mdns_transport"),
			(void *) sym("dpma_config_service_name"), (void *) sym("dpma_config_pjsip_message_context"),
			(void *) sym("dpma_config_file_dir"), (void *) sym("dpma_config_firmware_package_file"),
			(void *) sym("dpma_config_firmware_package_dir"), (void *) sym("dpma_config_server_uuid"),
			(void *) sym("dpma_config_reg_addr"), (void *) sym("dpma_config_reg_port"),
			(void *) sym("dpma_config_file_url_prefix") };
		static const size_t offs[13] = { 0x14, 0x114, 0x314, 0x31e, 0x328, 0x3a8, 0x3f8, 0x13f8, 0x23f8, 0x33f8, 0x35f8, 0x37f8, 0x3802 };
		static const size_t lens[13] = { 0x100, 0x200, 10, 10, 0x80, 0x50, 0x1000, 0x1000, 0x1000, 0x200, 0x200, 10, 0x1000 };
		char *cfg = calloc(1, 0x4804);
		int round;

		printf(" get -> %p\n", F(dpma_config_get)());
		F(dpma_config_unref)(NULL);
		for (i = 0; i < 5; i++) printf(" int[%d](NULL) = %d\n", i, ig[i](NULL));
		for (i = 0; i < 13; i++) {
			const char *r;
			if (i >= 2 && i <= 5 && i != 3) {
				continue; /* both dereference (offset) */
			}
			r = sg[i](NULL);
			if ((uintptr_t) r < 0x10000) printf(" str[%d](NULL) = %#lx\n", i, (unsigned long)(uintptr_t) r);
			else printf(" str[%d](NULL) = '%s'\n", i, r);
		}
		memset(buf, 'Z', sizeof(buf));
		F(dpma_append_config_file_dir)(buf, 64, "f", NULL);
		dump("append(NULL cfg)", buf, 8);

		for (round = 0; round < 2; round++) {
			printf(" -- fake config round %d\n", round);
			for (i = 0; i < 5; i++) ((int *) cfg)[i] = 7 + i + round * 100;
			for (i = 0; i < 13; i++) {
				memset(cfg + offs[i], 0, lens[i]);
				if (round == 0) snprintf(cfg + offs[i], lens[i], "v%d", i);
			}
			for (i = 0; i < 5; i++) printf(" int[%d] = %d\n", i, ig[i](cfg));
			for (i = 0; i < 13; i++) {
				const char *r = sg[i](cfg);
				if (r >= cfg && r < cfg + 0x4804) printf(" str[%d] = +%#lx '%s'\n", i, (long)(r - cfg), r);
				else printf(" str[%d] = const '%s'\n", i, r);
			}
			{
				struct { unsigned int len; const char *file; } cases[] = {
					{ 64, "f.xml" }, { 64, NULL }, { 64, "" }, { 3, NULL }, { 4, "f" }, { 1, NULL }, { 0, NULL } };
				size_t k;
				if (round == 0) {
					strcpy(cfg + 0x3f8, "/var/files");
				}
				for (k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
					memset(buf, 'Z', sizeof(buf));
					F(dpma_append_config_file_dir)(buf + 1, cases[k].len, cases[k].file, cfg);
					printf(" append(%u, %s)", cases[k].len, cases[k].file ? cases[k].file : "NULL");
					dump("", buf, 20);
				}
			}
		}
		free(cfg);
	}

	printf("== transport tables\n");
	{
		const char *names[] = { "phone_line_transport_option", "phone_line_transport_string", "phone_line_transport_type" };
		for (i = 0; i < 3; i++) {
			const char **t = sym(names[i]);
			printf(" %s: '%s' '%s' '%s' '%s'\n", names[i], t[0], t[1], t[2], t[3]);
		}
	}

	printf("== line_get_name\n");
	printf(" %d\n", F(phone_users_line_get_name)(buf) == buf);

	printf("== config handlers\n");
	{
		struct cfgh A = { hA, NULL }, B = { hB, NULL }, C = { hC, NULL }, D = { NULL, NULL }, X = { hA, NULL };
		printf(" reg A %d\n", F(dpma_register_config_handler)(&A));
		printf(" reg D %d\n", F(dpma_register_config_handler)(&D));
		printf(" reg B %d\n", F(dpma_register_config_handler)(&B));
		printf(" reg C %d refs %d\n", F(dpma_register_config_handler)(&C), module_refs);
		printf(" next A=%s D=%s B=%s C=%s\n", A.next == &D ? "D" : "?", D.next == &B ? "B" : "?", B.next == &C ? "C" : "?", C.next ? "?" : "0");
		F(dpma_process_config_handlers)((void *) 0x1234);
		F(dpma_unregister_config_handler)(&B);
		printf(" unreg B: refs %d B.next %p D.next==C %d\n", module_refs, (void *) B.next, D.next == &C);
		F(dpma_unregister_config_handler)(&X);
		printf(" unreg X: refs %d\n", module_refs);
		F(dpma_unregister_config_handler)(&A);
		printf(" unreg A: refs %d A.next %p\n", module_refs, (void *) A.next);
		F(dpma_process_config_handlers)((void *) 0x5678);
		F(dpma_unregister_config_handler)(&C);
		printf(" unreg C: refs %d\n", module_refs);
		F(dpma_register_config_handler)(&B);
		printf(" reg B after: D.next==B %d\n", D.next == &B);
		F(dpma_process_config_handlers)(NULL);
		F(dpma_unregister_config_handler)(&D);
		F(dpma_unregister_config_handler)(&B);
		printf(" all gone: refs %d\n", module_refs);
		F(dpma_process_config_handlers)((void *) 1);
		F(dpma_register_config_handler)(&A);
		F(dpma_process_config_handlers)((void *) 2);
		F(dpma_unregister_config_handler)(&A);
	}

	printf("== info handlers\n");
	{
		struct infoh X = { "PJSIP", sendX, NULL }, Y = { "local", sendY, NULL };
		const char *pjsip = "pjsip", *local = "Local", *iax = "IAX2";
		printf(" send none %d\n", F(dpma_info_send)(&pjsip, (void *) 0x10, "a/b", "body", NULL));
		printf(" reg X %d reg Y %d refs %d\n", F(dpma_register_info_handler)(&X), F(dpma_register_info_handler)(&Y), module_refs);
		printf(" send pjsip %d\n", F(dpma_info_send)(&pjsip, (void *) 0x10, "a/b", "body", NULL));
		printf(" send pjsip nulls %d\n", F(dpma_info_send)(&pjsip, NULL, NULL, NULL, NULL));
		printf(" send local %d\n", F(dpma_info_send)(&local, NULL, NULL, NULL, NULL));
		printf(" send iax %d\n", F(dpma_info_send)(&iax, NULL, NULL, NULL, NULL));
		F(dpma_unregister_info_handler)(&X);
		printf(" unreg X refs %d X.next %p\n", module_refs, (void *) X.next);
		printf(" send pjsip %d\n", F(dpma_info_send)(&pjsip, NULL, NULL, NULL, NULL));
		F(dpma_unregister_info_handler)(&Y);
		F(dpma_unregister_info_handler)(&Y);
		printf(" refs %d\n", module_refs);
	}

	printf("== is_dphone\n");
	printf(" call %d\n", F(dpma_pjsip_endpoint_is_dphone)("e1"));
	printf(" reg %d\n", F(dpma_register_pjsip_endpoint_is_dphone)(isd));
	printf(" reg again %d\n", F(dpma_register_pjsip_endpoint_is_dphone)(isd));
	printf(" call %d\n", F(dpma_pjsip_endpoint_is_dphone)("e2"));
	F(dpma_unregister_pjsip_endpoint_is_dphone)();
	printf(" call %d\n", F(dpma_pjsip_endpoint_is_dphone)("e3"));
	printf(" reg NULL %d\n", F(dpma_register_pjsip_endpoint_is_dphone)(NULL));
	printf(" reg %d\n", F(dpma_register_pjsip_endpoint_is_dphone)(isd));
	F(dpma_unregister_pjsip_endpoint_is_dphone)();

	fflush(stdout);
	_exit(0);
}

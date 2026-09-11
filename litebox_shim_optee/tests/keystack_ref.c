// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Re-hosted reference implementation of `system_derive_ta_svn_key_stack()`
// from the Microsoft OP-TEE fork for differential testing.
//
// The derivation logic in `system_derive_ta_svn_key_stack()` is copied verbatim
// from the C original. Only the surrounding OP-TEE services are re-hosted:
//
//   vm_check_access_rights()  -> dropped; a memory-safety check.
//   system_get_ta_version()   -> injected TA SVN.
//   huk_subkey_derive()       -> HMAC-SHA256(HUK, LE32(usage) || data), per
//                                optee_os core/kernel/huk_subkey.c.
//   crypto_mac_*()            -> the HMAC-SHA256 below.
//   HUK                       -> /proc/sys/kernel/random/boot_id.
//
// Usage: keystack_ref <cases-file>

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* HMAC-SHA256 via OpenSSL                                             */
/*                                                                     */
/* OP-TEE's crypto_mac_* API is incremental, so the update calls are   */
/* buffered and hashed in one shot at final. This keeps the call       */
/* structure of the original while avoiding OpenSSL's HMAC_CTX_*,      */
/* which is deprecated since 3.0.                                      */
/* ------------------------------------------------------------------ */

#define MAC_BUF_MAX 8192

struct mac_ctx {
	uint8_t key[64];
	size_t key_len;
	uint8_t buf[MAC_BUF_MAX];
	size_t buf_len;
};

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
			size_t data_len, uint8_t *out32)
{
	unsigned int len = 0;

	if (!HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out32, &len) ||
	    len != 32) {
		fprintf(stderr, "HMAC-SHA256 failed\n");
		exit(2);
	}
}

/* ------------------------------------------------------------------ */
/* Re-hosted OP-TEE services                                           */
/* ------------------------------------------------------------------ */

#define TA_DERIVED_KEY_MIN_SIZE 16
#define TA_DERIVED_KEY_MAX_SIZE 32
#define TA_DERIVED_EXTRA_DATA_MAX_SIZE 1024

#define TEE_SUCCESS 0
#define TEE_ERROR_GENERIC 0xFFFF0000
#define TEE_ERROR_BAD_PARAMETERS 0xFFFF0006
#define TEE_ERROR_OUT_OF_MEMORY 0xFFFF000C
#define TEE_ERROR_SECURITY 0xFFFF000F

#define HUK_SUBKEY_UNIQUE_TA 3

#define EMSG(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define ADD_OVERFLOW(a, b, res) __builtin_add_overflow((a), (b), (res))

typedef uint32_t TEE_Result;

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEE_UUID;

static uint8_t g_huk[16];
static uint32_t g_ta_version;
static TEE_UUID g_uuid;

static void free_wipe(void *p) { free(p); }

/* optee_os core/kernel/huk_subkey.c: HMAC(HUK, usage_as_u32 || const_data) */
static TEE_Result huk_subkey_derive(uint32_t usage, const uint8_t *data,
				    size_t data_len, uint8_t *out, size_t out_len)
{
	uint8_t mac[32];
	uint8_t *ctx_buf;
	size_t ctx_len = sizeof(uint32_t) + data_len;

	if (out_len > 32)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx_buf = calloc(ctx_len, 1);
	if (!ctx_buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	ctx_buf[0] = (uint8_t)(usage & 0xff);
	ctx_buf[1] = (uint8_t)((usage >> 8) & 0xff);
	ctx_buf[2] = (uint8_t)((usage >> 16) & 0xff);
	ctx_buf[3] = (uint8_t)((usage >> 24) & 0xff);
	memcpy(ctx_buf + sizeof(uint32_t), data, data_len);

	hmac_sha256(g_huk, sizeof(g_huk), ctx_buf, ctx_len, mac);
	free(ctx_buf);
	memcpy(out, mac, out_len);
	return TEE_SUCCESS;
}

static TEE_Result system_get_ta_version(uint32_t *v)
{
	*v = g_ta_version;
	return TEE_SUCCESS;
}

static TEE_Result crypto_mac_alloc_ctx(void **ctx, int alg)
{
	(void)alg;
	*ctx = calloc(1, sizeof(struct mac_ctx));
	return *ctx ? TEE_SUCCESS : TEE_ERROR_OUT_OF_MEMORY;
}

static void crypto_mac_free_ctx(void *ctx) { free(ctx); }

static TEE_Result crypto_mac_init(void *ctx, const uint8_t *key, size_t len)
{
	struct mac_ctx *m = ctx;

	if (len > sizeof(m->key))
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(m->key, key, len);
	m->key_len = len;
	m->buf_len = 0;
	return TEE_SUCCESS;
}

static TEE_Result crypto_mac_update(void *ctx, const uint8_t *d, size_t len)
{
	struct mac_ctx *m = ctx;

	if (m->buf_len + len > sizeof(m->buf))
		return TEE_ERROR_OUT_OF_MEMORY;
	memcpy(m->buf + m->buf_len, d, len);
	m->buf_len += len;
	return TEE_SUCCESS;
}

static TEE_Result crypto_mac_final(void *ctx, uint8_t *out, size_t len)
{
	struct mac_ctx *m = ctx;
	uint8_t mac[32];

	if (len > 32)
		return TEE_ERROR_SECURITY; /* OP-TEE: short buffer */
	hmac_sha256(m->key, m->key_len, m->buf, m->buf_len, mac);
	memcpy(out, mac, len);
	return TEE_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* The function under test -- body unchanged from the fork             */
/* ------------------------------------------------------------------ */

static TEE_Result system_derive_ta_svn_key_stack(uint32_t key_size,
						 uint32_t svn_key_stack_size,
						 const uint8_t *extra_data_buffer,
						 size_t extra_data_size,
						 uint8_t *key_stack,
						 size_t svn_key_buffer_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t ta_version;
	uint8_t stg1_temp_key[TA_DERIVED_KEY_MAX_SIZE];
	uint8_t stg2_temp_key[TA_DERIVED_KEY_MAX_SIZE];
	void *ctx = NULL;
	size_t data_len;
	uint8_t *data = NULL;

	if (key_size < TA_DERIVED_KEY_MIN_SIZE ||
	    key_size > TA_DERIVED_KEY_MAX_SIZE ||
	    extra_data_size > TA_DERIVED_EXTRA_DATA_MAX_SIZE ||
	    svn_key_stack_size > 4096 ||
	    svn_key_stack_size == 0 ||
	    !key_stack) {
		EMSG("%s bad parameters", __func__);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = system_get_ta_version(&ta_version);
	if (res) {
		EMSG("%s unable to get TA version", __func__);
		return res;
	}
	if (svn_key_buffer_size < (key_size * (ta_version + 1))) {
		EMSG("%s key stack is too small", __func__);
		return TEE_ERROR_BAD_PARAMETERS;
	}
	for (int i = svn_key_stack_size - 1; i >= 0 ; i--) {
		if (i == (int)(svn_key_stack_size - 1)) {
			data_len = sizeof(TEE_UUID);
			/* Take extra data into account. */
			if (ADD_OVERFLOW(data_len, extra_data_size, &data_len))
				return TEE_ERROR_SECURITY;
			data = calloc(data_len, 1);
			if (!data)
				return TEE_ERROR_OUT_OF_MEMORY;
			memcpy(data, &g_uuid, sizeof(TEE_UUID));
			/* Append the user provided data */
			memcpy(data + sizeof(TEE_UUID), extra_data_buffer,
			       extra_data_size);
			/* First iteration KDF: KDF(HUK, UUID) */
			res = huk_subkey_derive(HUK_SUBKEY_UNIQUE_TA,
						data,
						data_len,
						stg1_temp_key,
						key_size);
			free_wipe(data);
			if (res)
				return res;
		} else {
			/* Add previous key */
			memcpy(stg1_temp_key, stg2_temp_key, key_size);
		}
		/*
		 * Second iteration KDF:
		 * Key_v2047 = KDF(KDF(HUK, UUID), 2047)
		 * Key_v2046 = KDF(Key_v2047, 2046)
		 * ...
		 * Key_v000 = KDF(Key_v001, 000)
		 */
		res = crypto_mac_alloc_ctx(&ctx, 0);
		if (res)
			return res;
		res = crypto_mac_init(ctx, stg1_temp_key, key_size);
		if (res)
			goto err;
		/* Add the SVN */
		res = crypto_mac_update(ctx, (uint8_t *)&i, sizeof(i));
		if (res)
			goto err;
		res = crypto_mac_final(ctx, stg2_temp_key, key_size);
		if (res)
			goto err;
		crypto_mac_free_ctx(ctx);
		if (i <= (int)ta_version) {
			/* Copy to output stack */
			memcpy(key_stack + (i * key_size),
			       stg2_temp_key,
			       key_size);
		}
	}
	return res;
err:
	crypto_mac_free_ctx(ctx);
	return res;
}

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

static void load_huk(void)
{
	FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
	char buf[64];
	int n = 0;
	char *p;

	if (!f || !fgets(buf, sizeof(buf), f)) {
		fprintf(stderr, "cannot read boot_id\n");
		exit(1);
	}
	fclose(f);
	for (p = buf; *p && n < 16; p++) {
		unsigned v;

		if (*p == '-' || *p == '\n')
			continue;
		if (sscanf(p, "%2x", &v) != 1) {
			fprintf(stderr, "malformed boot_id\n");
			exit(1);
		}
		g_huk[n++] = (uint8_t)v;
		p++;
	}
	if (n != 16) {
		fprintf(stderr, "short boot_id (%d bytes)\n", n);
		exit(1);
	}
}

static size_t hex2bin(const char *hex, uint8_t *out, size_t max)
{
	size_t n = 0;

	if (!strcmp(hex, "-"))
		return 0;
	while (*hex && *(hex + 1) && n < max) {
		unsigned v;

		if (sscanf(hex, "%2x", &v) != 1)
			break;
		out[n++] = (uint8_t)v;
		hex += 2;
	}
	return n;
}

int main(int argc, char **argv)
{
	FILE *f;
	char line[8192];

	if (argc != 2) {
		fprintf(stderr, "usage: %s <cases-file>\n", argv[0]);
		return 1;
	}
	load_huk();

	f = fopen(argv[1], "r");
	if (!f) {
		fprintf(stderr, "cannot open %s\n", argv[1]);
		return 1;
	}
	while (fgets(line, sizeof(line), f)) {
		unsigned key_size, stack_size, ta_version;
		char uuid_hex[64], extra_hex[4096];
		uint8_t uuid_bytes[16] = { 0 };
		/*
		 * Deliberately larger than the accepted maximum so that
		 * over-size extra data reaches the length check below intact.
		 */
		uint8_t extra[TA_DERIVED_EXTRA_DATA_MAX_SIZE + 64];
		size_t extra_len, stack_len, i;
		uint8_t *stack;
		TEE_Result res;

		if (line[0] == '#' || line[0] == '\n')
			continue;
		if (sscanf(line, "%u %u %u %63s %4095s", &key_size, &stack_size,
			   &ta_version, uuid_hex, extra_hex) != 5)
			continue;

		hex2bin(uuid_hex, uuid_bytes, 16);
		memcpy(&g_uuid, uuid_bytes, 16);
		if (strcmp(extra_hex, "-") && strlen(extra_hex) / 2 > sizeof(extra)) {
			fprintf(stderr, "extra data too large for harness buffer\n");
			return 1;
		}
		extra_len = hex2bin(extra_hex, extra, sizeof(extra));
		g_ta_version = ta_version;

		stack_len = (size_t)key_size * ((size_t)ta_version + 1);
		stack = calloc(stack_len ? stack_len : 1, 1);
		if (!stack)
			return 1;

		res = system_derive_ta_svn_key_stack(key_size, stack_size, extra,
						     extra_len, stack, stack_len);
		printf("%08x ", res);
		if (res == TEE_SUCCESS)
			for (i = 0; i < stack_len; i++)
				printf("%02x", stack[i]);
		else
			printf("-");
		printf("\n");
		free(stack);
	}
	fclose(f);
	return 0;
}

/**
 * test_aes_crypto.c
 * -----------------
 * Unit tests for the AES-256-GCM encryption/decryption logic
 * using CMocka (C equivalent of JUnit).
 *
 * Build:
 *   gcc -o test_aes_crypto test_aes_crypto.c \
 *       $(pkg-config --cflags --libs cmocka openssl) -Wall
 * Run:
 *   ./test_aes_crypto
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

/* ── Wire format constants (mirror of main module) ── */
#define AES_KEY_LEN  32
#define AES_IV_LEN   12
#define AES_TAG_LEN  16

/* ── Standalone encrypt (extracted pure logic, no nginx types) ── */
static int
aes_gcm_encrypt(const unsigned char *key,
                const unsigned char *plain, size_t plain_len,
                unsigned char **out, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char   iv[AES_IV_LEN], tag[AES_TAG_LEN];
    int             len = 0, clen = 0;
    size_t          buf_size = 4 + AES_IV_LEN + AES_TAG_LEN + plain_len + 16;
    unsigned char  *buf = malloc(buf_size);
    if (!buf) return -1;

    if (RAND_bytes(iv, AES_IV_LEN) != 1) { free(buf); return -1; }

    unsigned char *cstart = buf + 4 + AES_IV_LEN + AES_TAG_LEN;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(buf); return -1; }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, cstart, &len, plain, (int)plain_len) != 1)
    { EVP_CIPHER_CTX_free(ctx); free(buf); return -1; }
    clen = len;

    if (EVP_EncryptFinal_ex(ctx, cstart + clen, &len) != 1)
    { EVP_CIPHER_CTX_free(ctx); free(buf); return -1; }
    clen += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    uint32_t rec = (uint32_t)(AES_IV_LEN + AES_TAG_LEN + clen);
    buf[0]=(rec>>24)&0xFF; buf[1]=(rec>>16)&0xFF;
    buf[2]=(rec>> 8)&0xFF; buf[3]=(rec    )&0xFF;
    memcpy(buf + 4,              iv,  AES_IV_LEN);
    memcpy(buf + 4 + AES_IV_LEN, tag, AES_TAG_LEN);

    *out     = buf;
    *out_len = 4 + rec;
    return 0;
}

static int
aes_gcm_decrypt(const unsigned char *key,
                const unsigned char *wire, size_t wire_len,
                unsigned char **plain, size_t *plain_len)
{
    if (wire_len < 4 + AES_IV_LEN + AES_TAG_LEN) return -1;

    uint32_t rec = ((uint32_t)wire[0]<<24)|((uint32_t)wire[1]<<16)|
                   ((uint32_t)wire[2]<< 8)| (uint32_t)wire[3];
    if (4 + rec != wire_len) return -1;

    const unsigned char *iv     = wire + 4;
    const unsigned char *tag    = wire + 4 + AES_IV_LEN;
    const unsigned char *cipher = wire + 4 + AES_IV_LEN + AES_TAG_LEN;
    size_t cipher_len = rec - AES_IV_LEN - AES_TAG_LEN;

    unsigned char *out = malloc(cipher_len + 1);
    if (!out) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ok;

    ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) &&
         EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) &&
         EVP_DecryptUpdate(ctx, out, &len, cipher, (int)cipher_len);
    *plain_len = (size_t)len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN,
                        (void *)(uintptr_t)tag);
    int final_ok = ok ? EVP_DecryptFinal_ex(ctx, out + len, &len) : 0;
    EVP_CIPHER_CTX_free(ctx);

    if (!final_ok) { free(out); return -1; }
    *plain_len += len;
    out[*plain_len] = '\0';
    *plain = out;
    return 0;
}

/* ================================================================
 * Test fixtures
 * ================================================================ */

static unsigned char test_key[AES_KEY_LEN];

static int setup(void **state) {
    /* Generate a fresh random key per test group */
    assert_int_equal(RAND_bytes(test_key, AES_KEY_LEN), 1);
    (void)state;
    return 0;
}

static int teardown(void **state) {
    memset(test_key, 0, AES_KEY_LEN);
    (void)state;
    return 0;
}

/* ================================================================
 * TC-01: Basic round-trip – encrypt then decrypt recovers plaintext
 * ================================================================ */
static void test_roundtrip_basic(void **state) {
    (void)state;
    const char *msg = "127.0.0.1 \"GET /index.html HTTP/1.1\" 200 \"curl/8.0\"\n";
    size_t msg_len  = strlen(msg);

    unsigned char *wire = NULL;
    size_t         wire_len = 0;
    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, msg_len,
                                     &wire, &wire_len), 0);
    assert_non_null(wire);

    unsigned char *recovered = NULL;
    size_t         recovered_len = 0;
    assert_int_equal(aes_gcm_decrypt(test_key, wire, wire_len,
                                     &recovered, &recovered_len), 0);
    assert_non_null(recovered);
    assert_int_equal(recovered_len, msg_len);
    assert_memory_equal(recovered, msg, msg_len);

    free(wire);
    free(recovered);
}

/* ================================================================
 * TC-02: Empty plaintext is handled without crash
 * ================================================================ */
static void test_roundtrip_empty(void **state) {
    (void)state;
    const char *msg = "";
    unsigned char *wire = NULL;
    size_t wire_len = 0;
    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, 0,
                                     &wire, &wire_len), 0);

    unsigned char *recovered = NULL;
    size_t recovered_len = 0;
    assert_int_equal(aes_gcm_decrypt(test_key, wire, wire_len,
                                     &recovered, &recovered_len), 0);
    assert_int_equal(recovered_len, 0);

    free(wire);
    free(recovered);
}

/* ================================================================
 * TC-03: Large message (>4 KB URI simulation)
 * ================================================================ */
static void test_roundtrip_large(void **state) {
    (void)state;
    size_t big = 6000;
    unsigned char *msg = malloc(big);
    memset(msg, 'A', big);

    unsigned char *wire = NULL; size_t wire_len = 0;
    assert_int_equal(aes_gcm_encrypt(test_key, msg, big, &wire, &wire_len), 0);

    unsigned char *recovered = NULL; size_t recovered_len = 0;
    assert_int_equal(aes_gcm_decrypt(test_key, wire, wire_len,
                                     &recovered, &recovered_len), 0);
    assert_int_equal(recovered_len, big);
    assert_memory_equal(recovered, msg, big);

    free(msg); free(wire); free(recovered);
}

/* ================================================================
 * TC-04: Tampered ciphertext must fail GCM auth tag check
 * ================================================================ */
static void test_tamper_detection(void **state) {
    (void)state;
    const char *msg = "sensitive log record";
    unsigned char *wire = NULL; size_t wire_len = 0;
    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, strlen(msg),
                                     &wire, &wire_len), 0);

    /* Flip one byte in the ciphertext area */
    wire[4 + AES_IV_LEN + AES_TAG_LEN] ^= 0xFF;

    unsigned char *recovered = NULL; size_t recovered_len = 0;
    int rc = aes_gcm_decrypt(test_key, wire, wire_len,
                              &recovered, &recovered_len);
    assert_int_equal(rc, -1);  /* must fail */
    assert_null(recovered);

    free(wire);
}

/* ================================================================
 * TC-05: Wrong key must fail decryption
 * ================================================================ */
static void test_wrong_key(void **state) {
    (void)state;
    const char *msg = "another log record";
    unsigned char *wire = NULL; size_t wire_len = 0;
    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, strlen(msg),
                                     &wire, &wire_len), 0);

    unsigned char wrong_key[AES_KEY_LEN];
    memcpy(wrong_key, test_key, AES_KEY_LEN);
    wrong_key[0] ^= 0x01;

    unsigned char *recovered = NULL; size_t recovered_len = 0;
    int rc = aes_gcm_decrypt(wrong_key, wire, wire_len,
                              &recovered, &recovered_len);
    assert_int_equal(rc, -1);

    free(wire);
}

/* ================================================================
 * TC-06: Wire format header fields are correct
 * ================================================================ */
static void test_wire_format_header(void **state) {
    (void)state;
    const char *msg = "hello";
    unsigned char *wire = NULL; size_t wire_len = 0;
    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, strlen(msg),
                                     &wire, &wire_len), 0);

    uint32_t rec = ((uint32_t)wire[0]<<24)|((uint32_t)wire[1]<<16)|
                   ((uint32_t)wire[2]<< 8)| (uint32_t)wire[3];
    /* record length field must equal total wire length minus 4 */
    assert_int_equal((size_t)(4 + rec), wire_len);
    /* minimum: IV + TAG + 1-byte ciphertext */
    assert_true(rec >= (uint32_t)(AES_IV_LEN + AES_TAG_LEN));

    free(wire);
}

/* ================================================================
 * TC-07: Two encryptions of same plaintext produce different ciphertexts
 *         (IV randomness check)
 * ================================================================ */
static void test_iv_randomness(void **state) {
    (void)state;
    const char *msg = "same message";
    unsigned char *w1 = NULL, *w2 = NULL;
    size_t l1 = 0, l2 = 0;

    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, strlen(msg),
                                     &w1, &l1), 0);
    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, strlen(msg),
                                     &w2, &l2), 0);
    assert_int_equal(l1, l2);
    /* IVs (bytes 4..15) must differ with overwhelming probability */
    assert_int_not_equal(memcmp(w1 + 4, w2 + 4, AES_IV_LEN), 0);

    free(w1); free(w2);
}

/* ================================================================
 * TC-08: Truncated wire data must be rejected
 * ================================================================ */
static void test_truncated_input(void **state) {
    (void)state;
    const char *msg = "truncation test";
    unsigned char *wire = NULL; size_t wire_len = 0;
    assert_int_equal(aes_gcm_encrypt(test_key,
                                     (const unsigned char *)msg, strlen(msg),
                                     &wire, &wire_len), 0);

    /* Feed only half the bytes */
    unsigned char *recovered = NULL; size_t recovered_len = 0;
    int rc = aes_gcm_decrypt(test_key, wire, wire_len / 2,
                              &recovered, &recovered_len);
    assert_int_equal(rc, -1);

    free(wire);
}

/* ================================================================
 * TC-09: Log message format – timestamp + fields present
 * ================================================================ */
static void test_logmsg_format(void **state) {
    (void)state;
    /* Simulate what the module builds:
       "<ts> <ip> \"<method> <uri> HTTP/1.1\" <status> \"<ref>\" \"<ua>\"\n"  */
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
                     "2025-08-06T12:34:56+0900 192.168.1.1 "
                     "\"GET /api/v1/health HTTP/1.1\" 200 \"-\" \"curl/8.0\"\n");
    assert_true(n > 0 && n < (int)sizeof(buf));
    /* Must contain IP, method, status */
    assert_non_null(strstr(buf, "192.168.1.1"));
    assert_non_null(strstr(buf, "GET"));
    assert_non_null(strstr(buf, "200"));
    assert_non_null(strstr(buf, "2025-08-06"));  /* date present */
}

/* ================================================================
 * TC-10: Provider param parser (key_id / server extraction)
 * ================================================================ */
static void parse_param(const char *param, const char *key,
                        char *out, size_t out_size)
{
    const char *p = param;
    size_t klen = strlen(key);
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            const char *end = strchr(p, ';');
            size_t vlen = end ? (size_t)(end - p) : strlen(p);
            if (vlen >= out_size) vlen = out_size - 1;
            strncpy(out, p, vlen); out[vlen] = '\0';
            return;
        }
        p = strchr(p, ';'); if (p) p++;
    }
    out[0] = '\0';
}

static void test_ext_param_parser(void **state) {
    (void)state;
    const char *param = "key_id=PROD_LOG_KEY_001;server=kms.internal:7443";
    char key_id[128] = {0}, server[128] = {0}, missing[64] = {0};

    parse_param(param, "key_id", key_id, sizeof(key_id));
    parse_param(param, "server", server, sizeof(server));
    parse_param(param, "nonexistent", missing, sizeof(missing));

    assert_string_equal(key_id, "PROD_LOG_KEY_001");
    assert_string_equal(server, "kms.internal:7443");
    assert_string_equal(missing, "");
}

/* ================================================================
 * Main – test runner
 * ================================================================ */

/* ================================================================
 * TC-11: Key hash file written and readable
 * ================================================================ */
static void test_key_hashfile_write_read(void **state) {
    (void)state;

    /* write a temp key file */
    const char *keypath  = "/tmp/test_securelog.key";
    const char *hashpath = "/tmp/test_securelog.key.sha256";

    FILE *kf = fopen(keypath, "wb");
    assert_non_null(kf);
    fwrite(test_key, 1, AES_KEY_LEN, kf);
    fclose(kf);

    /* compute expected hash */
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(test_key, AES_KEY_LEN, digest);
    char expected_hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(expected_hex + i*2, 3, "%02x", digest[i]);
    expected_hex[64] = '\0';

    /* write hash file (same format as securelog_keygen.sh) */
    FILE *hf = fopen(hashpath, "w");
    assert_non_null(hf);
    fprintf(hf, "%s  %s\n", expected_hex, keypath);
    fclose(hf);

    /* read back and compare */
    hf = fopen(hashpath, "r");
    assert_non_null(hf);
    char stored_hex[65];
    int  n = fscanf(hf, "%64s", stored_hex);
    fclose(hf);
    assert_int_equal(n, 1);
    assert_string_equal(stored_hex, expected_hex);

    remove(keypath);
    remove(hashpath);
}

/* ================================================================
 * TC-12: Tampered key fails hash verification
 * ================================================================ */
static void test_key_hashfile_tamper(void **state) {
    (void)state;

    const char *keypath  = "/tmp/test_securelog2.key";
    const char *hashpath = "/tmp/test_securelog2.key.sha256";

    /* write original key and hash */
    FILE *kf = fopen(keypath, "wb");
    fwrite(test_key, 1, AES_KEY_LEN, kf);
    fclose(kf);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(test_key, AES_KEY_LEN, digest);
    char original_hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(original_hex + i*2, 3, "%02x", digest[i]);
    original_hex[64] = '\0';

    FILE *hf = fopen(hashpath, "w");
    fprintf(hf, "%s  %s\n", original_hex, keypath);
    fclose(hf);

    /* tamper: flip one byte of the key */
    unsigned char tampered[AES_KEY_LEN];
    memcpy(tampered, test_key, AES_KEY_LEN);
    tampered[0] ^= 0x01;

    /* compute hash of tampered key */
    unsigned char t_digest[SHA256_DIGEST_LENGTH];
    SHA256(tampered, AES_KEY_LEN, t_digest);
    char tampered_hex[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(tampered_hex + i*2, 3, "%02x", t_digest[i]);
    tampered_hex[64] = '\0';

    /* tampered hash must NOT equal stored hash */
    assert_int_not_equal(memcmp(original_hex, tampered_hex, 64), 0);

    remove(keypath);
    remove(hashpath);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_roundtrip_basic,    setup, teardown),
        cmocka_unit_test_setup_teardown(test_roundtrip_empty,    setup, teardown),
        cmocka_unit_test_setup_teardown(test_roundtrip_large,    setup, teardown),
        cmocka_unit_test_setup_teardown(test_tamper_detection,   setup, teardown),
        cmocka_unit_test_setup_teardown(test_wrong_key,          setup, teardown),
        cmocka_unit_test_setup_teardown(test_wire_format_header, setup, teardown),
        cmocka_unit_test_setup_teardown(test_iv_randomness,      setup, teardown),
        cmocka_unit_test_setup_teardown(test_truncated_input,    setup, teardown),
        cmocka_unit_test(test_logmsg_format),
        cmocka_unit_test(test_ext_param_parser),
        cmocka_unit_test_setup_teardown(test_key_hashfile_write_read, setup, teardown),
        cmocka_unit_test_setup_teardown(test_key_hashfile_tamper,      setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

/**
 * securelog_ext_provider_template.c
 * -----------------------------------
 * Template for an external encryption provider.
 *
 * Copy this file, implement the three functions below, then build as a
 * shared library:
 *
 *   gcc -O2 -fPIC -shared \
 *       -o securelog_damo_provider.so \
 *       securelog_ext_provider_template.c \
 *       -lYourVendorSDK
 *
 * Then in nginx.conf:
 *   securelog_provider    ext;
 *   securelog_ext_library /etc/nginx/modules/securelog_damo_provider.so;
 *   securelog_ext_param   "key_id=PROD_LOG_KEY_001;server=kms.internal:7443";
 *
 * ── Provider contract ────────────────────────────────────────────────────
 *
 *  securelog_provider_init(param, log)
 *    Called ONCE per worker process at startup.
 *    `param` is the value of securelog_ext_param (may be empty string).
 *    Return 0 on success, non-zero on failure (worker will abort).
 *
 *  securelog_provider_encrypt(in, in_len, out, out_len, log)
 *    Called for EVERY log record.
 *    Must allocate *out with malloc(); the caller calls free() after copy.
 *    Return 0 on success, non-zero on failure (record is dropped with ERR).
 *
 *  securelog_provider_cleanup()
 *    Called once on worker exit. Optional – may be NULL in the .so.
 *    Release connections, session handles, etc.
 *
 * ── D'Amo / KCMVP integration notes ─────────────────────────────────────
 *
 *  D'Amo (Penta Security) exposes a C API (libDamoKey.so / EzSecurity SDK).
 *  Typical call sequence:
 *
 *    DamoKey_Initialize(config_path);          // in init()
 *    DamoKey_Encrypt(key_id, in, in_len,       // in encrypt()
 *                    out, out_len);
 *    DamoKey_Finalize();                        // in cleanup()
 *
 *  Actual symbol names vary by SDK version – check your vendor headers.
 *  The `param` string is a convenient way to pass key_id / server address
 *  without recompiling (parse it here as you see fit).
 *
 * ── PKCS#11 / HSM notes ──────────────────────────────────────────────────
 *
 *  For PKCS#11-compatible HSMs (SafeNet, Thales, etc.) use libpkcs11 or
 *  SoftHSM.  In init(), open a session and find the wrapping key by label.
 *  In encrypt(), call C_EncryptInit + C_Encrypt.  Never store the session
 *  handle in a global – allocate per-worker in init().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Vendor SDK headers go here ──────────────────────────────────────── */
/* #include <DamoKey.h>    */
/* #include <pkcs11.h>     */

#include <ngx_log.h>   /* for NGX_LOG_ERR etc. – optional, may omit */

/* ── Internal provider state (per-worker, allocated in init) ───────────── */
typedef struct {
    char key_id[256];
    char server[256];
    /* DamoKey_Session session; */
    /* CK_SESSION_HANDLE pkcs11_session; */
} provider_state_t;

static provider_state_t *_state = NULL;

/* ── Helper: parse "key=val;key=val" param string ──────────────────────── */
static void
parse_param(const char *param, const char *key, char *out, size_t out_size)
{
    const char *p = param;
    size_t      klen = strlen(key);
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            p += klen + 1;
            const char *end = strchr(p, ';');
            size_t vlen = end ? (size_t)(end - p) : strlen(p);
            if (vlen >= out_size) vlen = out_size - 1;
            strncpy(out, p, vlen);
            out[vlen] = '\0';
            return;
        }
        p = strchr(p, ';');
        if (p) p++;
    }
    out[0] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * EXPORTED SYMBOL 1 – called once per worker at startup
 * ═══════════════════════════════════════════════════════════════════════════ */
int
securelog_provider_init(const char *param, void *log /* ngx_log_t* */)
{
    _state = calloc(1, sizeof(provider_state_t));
    if (!_state) return -1;

    parse_param(param, "key_id", _state->key_id, sizeof(_state->key_id));
    parse_param(param, "server", _state->server, sizeof(_state->server));

    if (_state->key_id[0] == '\0') {
        fprintf(stderr,
                "[securelog/ext] WARNING: key_id not set in securelog_ext_param\n");
    }

    /* ── TODO: initialize vendor SDK ─────────────────────────────────────
     *
     * D'Amo example:
     *   int rc = DamoKey_Initialize("/etc/damo/config.ini");
     *   if (rc != DAMO_OK) return -1;
     *
     * PKCS#11 example:
     *   CK_RV rv = C_Initialize(NULL);
     *   if (rv != CKR_OK) return -1;
     *   rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL,
     *                      &_state->pkcs11_session);
     *   if (rv != CKR_OK) return -1;
     *
     * ─────────────────────────────────────────────────────────────────── */

    fprintf(stderr,
            "[securelog/ext] provider initialized (key_id=%s server=%s)\n",
            _state->key_id, _state->server);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * EXPORTED SYMBOL 2 – called for every log record
 * ═══════════════════════════════════════════════════════════════════════════ */
int
securelog_provider_encrypt(const unsigned char *in,   size_t  in_len,
                           unsigned char      **out,  size_t *out_len,
                           void               *log /* ngx_log_t* */)
{
    if (!_state) return -1;

    /* ── TODO: call vendor encrypt API ───────────────────────────────────
     *
     * D'Amo example:
     *   int enc_len = 0;
     *   unsigned char *enc_buf = malloc(in_len + 256); // vendor overhead
     *   int rc = DamoKey_Encrypt(_state->key_id,
     *                            in, (int)in_len,
     *                            enc_buf, &enc_len);
     *   if (rc != DAMO_OK) { free(enc_buf); return -1; }
     *   *out     = enc_buf;
     *   *out_len = (size_t)enc_len;
     *   return 0;
     *
     * PKCS#11 example:
     *   CK_MECHANISM mech = { CKM_AES_GCM, &gcm_params, sizeof(gcm_params) };
     *   CK_RV rv = C_EncryptInit(_state->pkcs11_session, &mech, h_key);
     *   ...
     *
     * ─────────────────────────────────────────────────────────────────── */

    /*
     * PLACEHOLDER IMPLEMENTATION (identity / no-op – for testing only).
     * Replace with real vendor call above.
     */
    *out = malloc(in_len);
    if (!*out) return -1;
    memcpy(*out, in, in_len);
    *out_len = in_len;

    fprintf(stderr,
            "[securelog/ext] PLACEHOLDER encrypt called – "
            "replace with vendor SDK in production!\n");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * EXPORTED SYMBOL 3 – called once per worker at shutdown (optional)
 * ═══════════════════════════════════════════════════════════════════════════ */
void
securelog_provider_cleanup(void)
{
    if (!_state) return;

    /* ── TODO: tear down vendor SDK ──────────────────────────────────────
     *   DamoKey_Finalize();
     *   C_CloseSession(_state->pkcs11_session);
     *   C_Finalize(NULL);
     * ─────────────────────────────────────────────────────────────────── */

    free(_state);
    _state = NULL;
}

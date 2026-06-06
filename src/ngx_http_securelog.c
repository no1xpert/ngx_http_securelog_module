/**
 * ngx_http_securelog.c
 * -------------------------
 * Author: Bongshin Choi
 * Version: 0.9.0-beta
 * Date: 2026-06-06
 *
 * Summary:
 *   NGINX module for secure encrypted logging.
 *   Supports pluggable encryption providers:
 *     - GPG  : asymmetric encryption via GPGME (default)
 *     - AES  : symmetric AES-256-GCM via OpenSSL (built-in)
 *     - EXT  : external provider via shared library (.so) for
 *              enterprise KMS / HSM integration (D'Amo, SafeNet, etc.)
 *
 * Directives:
 *   securelog_provider   gpg | aes | ext;
 *
 *   # GPG provider
 *   securelog_gpg_pubkey    /path/to/public.key;
 *   securelog_gpg_keyid     FINGERPRINT_OR_KEYID;   # optional, recommended
 *
 *   # AES provider
 *   securelog_aes_keyfile   /path/to/aes.key;       # 32-byte raw key file
 *
 *   # EXT provider
 *   securelog_ext_library   /path/to/provider.so;
 *   securelog_ext_param     "key_id=damo_key_001";  # provider-specific
 *
 *   # Common
 *   securelog_dir           /var/log/securelog;
 *   securelog_rotate        daily | hourly | size:64M;
 *
 * Build (dynamic module):
 *   ./configure --with-compat \
 *               --add-dynamic-module=/path/to/ngx_http_securelog_module
 *   make modules
 *
 * nginx.conf:
 *   load_module modules/ngx_http_securelog.so;
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <locale.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include <gpgme.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

#define SECURELOG_VERSION       "0.9.0-beta"
#define DEFAULT_LOG_DIR         "/var/log/securelog"
#define MAX_LOGMSG_SIZE         (8 * 1024)       /* 8 KB - dynamic alloc */
#define AES_KEY_LEN             32               /* AES-256 */
#define AES_IV_LEN              12               /* GCM standard IV */
#define AES_TAG_LEN             16               /* GCM auth tag */

/* =========================================================================
 * Provider types
 * ========================================================================= */

typedef enum {
    SECURELOG_PROVIDER_UNSET = 0,
    SECURELOG_PROVIDER_GPG,
    SECURELOG_PROVIDER_AES,
    SECURELOG_PROVIDER_EXT
} securelog_provider_t;

typedef enum {
    SECURELOG_ROTATE_DAILY = 0,
    SECURELOG_ROTATE_HOURLY,
    SECURELOG_ROTATE_SIZE
} securelog_rotate_t;

/* =========================================================================
 * External provider interface
 *   The .so must export these two symbols.
 * ========================================================================= */

typedef int (*securelog_ext_init_fn)(const char *param, ngx_log_t *log);
typedef int (*securelog_ext_encrypt_fn)(
    const unsigned char *in,  size_t  in_len,
    unsigned char      **out, size_t *out_len,
    ngx_log_t          *log
);
typedef void (*securelog_ext_cleanup_fn)(void);

typedef struct {
    void                    *handle;     /* dlopen handle */
    securelog_ext_init_fn    init;
    securelog_ext_encrypt_fn encrypt;
    securelog_ext_cleanup_fn cleanup;
} securelog_ext_provider_t;

/* =========================================================================
 * Per-worker state  (initialized in init_process, not in master)
 * ========================================================================= */

typedef struct {
    /* GPG */
    gpgme_ctx_t              gpg_ctx;
    gpgme_key_t              gpg_key;

    /* AES-256-GCM */
    unsigned char            aes_key[AES_KEY_LEN];
    int                      aes_key_loaded;

    /* EXT */
    securelog_ext_provider_t ext;

    /* active provider */
    securelog_provider_t     active_provider;

    /* current log fd (worker-local, no cross-process locking needed) */
    ngx_fd_t                 log_fd;
    u_char                   log_path[NGX_MAX_PATH];
    time_t                   log_day;    /* day stamp for rotation */
    off_t                    log_size;   /* byte counter for size rotation */
} securelog_worker_state_t;

static securelog_worker_state_t  *worker_state = NULL;

/* =========================================================================
 * Module configuration
 * ========================================================================= */

typedef struct {
    securelog_provider_t  provider;

    /* GPG */
    ngx_str_t             gpg_pubkey;
    ngx_str_t             gpg_keyid;

    /* AES */
    ngx_str_t             aes_keyfile;

    /* EXT */
    ngx_str_t             ext_library;
    ngx_str_t             ext_param;

    /* common */
    ngx_str_t             log_dir;
    securelog_rotate_t    rotate_mode;
    off_t                 rotate_size;   /* bytes, for ROTATE_SIZE */
} ngx_http_securelog_conf_t;

/* forward declarations */
extern ngx_module_t ngx_http_securelog;

/* =========================================================================
 * Helpers
 * ========================================================================= */

static ngx_fd_t
securelog_open_log(ngx_http_securelog_conf_t *cf,
                   securelog_worker_state_t  *ws,
                   ngx_log_t *log)
{
    time_t     now = ngx_time();
    struct tm  tm;
    u_char     path[NGX_MAX_PATH];

    localtime_r(&now, &tm);

    switch (cf->rotate_mode) {
    case SECURELOG_ROTATE_HOURLY:
        ngx_snprintf(path, NGX_MAX_PATH,
                     "%V/nginx-%04d%02d%02d-%02d.log.enc%Z",
                     &cf->log_dir,
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour);
        ws->log_day = now / 3600;
        break;
    case SECURELOG_ROTATE_SIZE:
        ngx_snprintf(path, NGX_MAX_PATH,
                     "%V/nginx-%04d%02d%02d-%02d%02d%02d.log.enc%Z",
                     &cf->log_dir,
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                     tm.tm_hour, tm.tm_min, tm.tm_sec);
        ws->log_size = 0;
        break;
    default: /* DAILY */
        ngx_snprintf(path, NGX_MAX_PATH,
                     "%V/nginx-%04d%02d%02d.log.enc%Z",
                     &cf->log_dir,
                     tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
        ws->log_day = now / 86400;
        break;
    }

    ngx_cpystrn(ws->log_path, path, NGX_MAX_PATH);

    ngx_fd_t fd = ngx_open_file(path,
                                NGX_FILE_WRONLY,
                                NGX_FILE_CREATE_OR_OPEN | NGX_FILE_APPEND,
                                NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "securelog: failed to open log file \"%s\"", path);
    }
    return fd;
}

static int
securelog_needs_rotate(ngx_http_securelog_conf_t *cf,
                       securelog_worker_state_t  *ws,
                       size_t written_len)
{
    time_t now;

    if (ws->log_fd == NGX_INVALID_FILE) return 1;

    now = ngx_time();
    switch (cf->rotate_mode) {
    case SECURELOG_ROTATE_HOURLY:
        return (now / 3600) != ws->log_day;
    case SECURELOG_ROTATE_SIZE:
        ws->log_size += (off_t)written_len;
        return ws->log_size >= cf->rotate_size;
    default:
        return (now / 86400) != ws->log_day;
    }
}

/* =========================================================================
 * GPG provider
 * ========================================================================= */

static ngx_int_t
securelog_gpg_init(ngx_http_securelog_conf_t *cf,
                   securelog_worker_state_t  *ws,
                   ngx_log_t *log)
{
    gpgme_error_t  err;

    setlocale(LC_ALL, "");
    gpgme_check_version(NULL);

    err = gpgme_new(&ws->gpg_ctx);
    if (err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/gpg: gpgme_new() failed: %s",
                      gpgme_strerror(err));
        return NGX_ERROR;
    }

    /* Import public key from file */
    FILE *f = fopen((char *)cf->gpg_pubkey.data, "r");
    if (!f) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "securelog/gpg: cannot open pubkey file \"%V\"",
                      &cf->gpg_pubkey);
        return NGX_ERROR;
    }

    gpgme_data_t keydata;
    err = gpgme_data_new_from_stream(&keydata, f);
    fclose(f);
    if (err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/gpg: gpgme_data_new_from_stream() failed: %s",
                      gpgme_strerror(err));
        return NGX_ERROR;
    }

    err = gpgme_op_import(ws->gpg_ctx, keydata);
    gpgme_data_release(keydata);
    if (err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/gpg: gpgme_op_import() failed: %s",
                      gpgme_strerror(err));
        return NGX_ERROR;
    }

    /* Locate the key - by fingerprint/keyid if specified, else first key */
    const char *keyid = (cf->gpg_keyid.len > 0)
                        ? (const char *)cf->gpg_keyid.data
                        : NULL;

    err = gpgme_op_keylist_start(ws->gpg_ctx, keyid, 0);
    if (err) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/gpg: gpgme_op_keylist_start() failed: %s",
                      gpgme_strerror(err));
        return NGX_ERROR;
    }

    err = gpgme_op_keylist_next(ws->gpg_ctx, &ws->gpg_key);
    gpgme_op_keylist_end(ws->gpg_ctx);

    if (err || ws->gpg_key == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/gpg: key not found (keyid=\"%s\"): %s",
                      keyid ? keyid : "(first available)",
                      gpgme_strerror(err));
        return NGX_ERROR;
    }

    gpgme_set_armor(ws->gpg_ctx, 1);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "securelog/gpg: initialized, key fingerprint=%s",
                  ws->gpg_key->subkeys->fpr);
    return NGX_OK;
}

static ngx_int_t
securelog_gpg_encrypt(securelog_worker_state_t *ws,
                      ngx_pool_t *pool,
                      const u_char *plain, size_t plain_len,
                      u_char **out, size_t *out_len)
{
    gpgme_data_t   plain_d, cipher_d;
    gpgme_error_t  err;

    err = gpgme_data_new_from_mem(&plain_d, (const char *)plain, plain_len, 0);
    if (err) return NGX_ERROR;

    err = gpgme_data_new(&cipher_d);
    if (err) { gpgme_data_release(plain_d); return NGX_ERROR; }

    gpgme_key_t keys[] = { ws->gpg_key, NULL };
    err = gpgme_op_encrypt(ws->gpg_ctx, keys,
                           GPGME_ENCRYPT_ALWAYS_TRUST,
                           plain_d, cipher_d);
    gpgme_data_release(plain_d);
    if (err) { gpgme_data_release(cipher_d); return NGX_ERROR; }

    off_t size = gpgme_data_seek(cipher_d, 0, SEEK_END);
    gpgme_data_seek(cipher_d, 0, SEEK_SET);

    u_char *buf = ngx_palloc(pool, size + 2); /* +newline separator */
    if (!buf) { gpgme_data_release(cipher_d); return NGX_ERROR; }

    ssize_t rd = gpgme_data_read(cipher_d, buf, size);
    gpgme_data_release(cipher_d);
    if (rd < 0) return NGX_ERROR;

    /* Ensure armored block ends with newline (block separator) */
    if (rd > 0 && buf[rd - 1] != '\n') buf[rd++] = '\n';

    *out     = buf;
    *out_len = (size_t)rd;
    return NGX_OK;
}

/* =========================================================================
 * AES-256-GCM provider
 *
 * Wire format per record (all fields concatenated, no framing overhead):
 *   [4 bytes big-endian: total record length]
 *   [12 bytes: IV / nonce   - random per record]
 *   [16 bytes: GCM auth tag]
 *   [N  bytes: ciphertext  ]
 *
 * The 4-byte length prefix lets a reader reliably parse the stream.
 * ========================================================================= */

/* =========================================================================
 * AES key integrity verification
 *
 * If <keyfile>.sha256 exists, compute SHA-256 of the loaded key and
 * compare against the stored hash. Mismatch -> worker refuses to start.
 *
 * Hash file format (same as sha256sum output):
 *   <64-hex-chars>  <filename>\n
 * ========================================================================= */

static ngx_int_t
securelog_aes_verify_key(const unsigned char *key, size_t key_len,
                          const char *keyfile_path, ngx_log_t *log)
{
    char      hashfile[NGX_MAX_PATH];
    FILE     *hf;
    char      stored_hex[65];   /* 64 hex chars + NUL */
    char      computed_hex[65];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int  i;

    /* Build hash file path: <keyfile>.sha256 */
    snprintf(hashfile, sizeof(hashfile), "%s.sha256", keyfile_path);

    hf = fopen(hashfile, "r");
    if (!hf) {
        /* Hash file absent - skip verification, log a warning */
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "securelog/aes: no hash file found at "%s" "
                      "- key integrity not verified. "
                      "Run securelog_keygen.sh to generate both files.",
                      hashfile);
        return NGX_OK;
    }

    /* Read first 64 characters (hex digest) */
    if (fscanf(hf, "%64s", stored_hex) != 1) {
        fclose(hf);
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/aes: cannot parse hash file "%s"",
                      hashfile);
        return NGX_ERROR;
    }
    fclose(hf);

    /* Compute SHA-256 of the key bytes */
    SHA256(key, key_len, digest);
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(computed_hex + i * 2, 3, "%02x", digest[i]);
    }
    computed_hex[64] = '\0';

    /* Constant-time comparison to avoid timing side-channel */
    if (CRYPTO_memcmp(stored_hex, computed_hex, 64) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "securelog/aes: KEY INTEGRITY CHECK FAILED for "%s" "
                      "- stored hash does not match. "
                      "Key file may have been tampered with. "
                      "Worker startup aborted.",
                      keyfile_path);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "securelog/aes: key integrity verified OK (SHA-256 match)");
    return NGX_OK;
}

static ngx_int_t
securelog_aes_init(ngx_http_securelog_conf_t *cf,
                   securelog_worker_state_t  *ws,
                   ngx_log_t *log)
{
    int  fd;
    ssize_t n;

    fd = open((char *)cf->aes_keyfile.data, O_RDONLY);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "securelog/aes: cannot open keyfile \"%V\"",
                      &cf->aes_keyfile);
        return NGX_ERROR;
    }

    n = read(fd, ws->aes_key, AES_KEY_LEN);
    close(fd);

    if (n != AES_KEY_LEN) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/aes: keyfile must be exactly %d bytes "
                      "(got %z)", AES_KEY_LEN, n);
        ngx_explicit_memzero(ws->aes_key, AES_KEY_LEN);
        return NGX_ERROR;
    }

    /* === Key integrity verification === */
    if (securelog_aes_verify_key(ws->aes_key, AES_KEY_LEN,
                                  (const char *)cf->aes_keyfile.data,
                                  log) != NGX_OK) {
        ngx_explicit_memzero(ws->aes_key, AES_KEY_LEN);
        return NGX_ERROR;
    }

    ws->aes_key_loaded = 1;
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "securelog/aes: AES-256-GCM provider initialized");
    return NGX_OK;
}

static ngx_int_t
securelog_aes_encrypt(securelog_worker_state_t *ws,
                      ngx_pool_t *pool,
                      const u_char *plain, size_t plain_len,
                      u_char **out, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char   iv[AES_IV_LEN];
    unsigned char   tag[AES_TAG_LEN];
    int             len = 0, clen = 0;

    if (RAND_bytes(iv, AES_IV_LEN) != 1) return NGX_ERROR;

    /* allocate: 4 (len) + 12 (iv) + 16 (tag) + plain_len + 16 (cipher slack) */
    size_t  buf_size = 4 + AES_IV_LEN + AES_TAG_LEN + plain_len + 16;
    u_char *buf      = ngx_palloc(pool, buf_size);
    if (!buf) return NGX_ERROR;

    u_char *cipher_start = buf + 4 + AES_IV_LEN + AES_TAG_LEN;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NGX_ERROR;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, ws->aes_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, cipher_start, &len, plain, (int)plain_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }
    clen = len;

    if (EVP_EncryptFinal_ex(ctx, cipher_start + clen, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }
    clen += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NGX_ERROR;
    }
    EVP_CIPHER_CTX_free(ctx);

    /* Build wire format */
    uint32_t record_len = (uint32_t)(AES_IV_LEN + AES_TAG_LEN + clen);
    buf[0] = (record_len >> 24) & 0xFF;
    buf[1] = (record_len >> 16) & 0xFF;
    buf[2] = (record_len >>  8) & 0xFF;
    buf[3] = (record_len      ) & 0xFF;
    ngx_memcpy(buf + 4,                        iv,  AES_IV_LEN);
    ngx_memcpy(buf + 4 + AES_IV_LEN,           tag, AES_TAG_LEN);
    /* cipher bytes already written to cipher_start */

    *out     = buf;
    *out_len = (size_t)(4 + record_len);
    return NGX_OK;
}

/* =========================================================================
 * EXT provider  (dynamic .so)
 * ========================================================================= */

static ngx_int_t
securelog_ext_init(ngx_http_securelog_conf_t *cf,
                   securelog_worker_state_t  *ws,
                   ngx_log_t *log)
{
    ws->ext.handle = dlopen((char *)cf->ext_library.data, RTLD_NOW | RTLD_LOCAL);
    if (!ws->ext.handle) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/ext: dlopen(\"%V\") failed: %s",
                      &cf->ext_library, dlerror());
        return NGX_ERROR;
    }

    ws->ext.init    = dlsym(ws->ext.handle, "securelog_provider_init");
    ws->ext.encrypt = dlsym(ws->ext.handle, "securelog_provider_encrypt");
    ws->ext.cleanup = dlsym(ws->ext.handle, "securelog_provider_cleanup");

    if (!ws->ext.init || !ws->ext.encrypt) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/ext: provider \"%V\" missing required symbols "
                      "(securelog_provider_init / securelog_provider_encrypt)",
                      &cf->ext_library);
        dlclose(ws->ext.handle);
        ws->ext.handle = NULL;
        return NGX_ERROR;
    }

    const char *param = (cf->ext_param.len > 0)
                        ? (const char *)cf->ext_param.data
                        : "";

    if (ws->ext.init(param, log) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "securelog/ext: provider init() returned error");
        dlclose(ws->ext.handle);
        ws->ext.handle = NULL;
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "securelog/ext: provider \"%V\" initialized (param=\"%V\")",
                  &cf->ext_library, &cf->ext_param);
    return NGX_OK;
}

static ngx_int_t
securelog_ext_encrypt(securelog_worker_state_t *ws,
                      ngx_pool_t *pool,
                      const u_char *plain, size_t plain_len,
                      u_char **out, size_t *out_len)
{
    unsigned char *provider_out = NULL;
    size_t         provider_out_len = 0;

    if (ws->ext.encrypt(plain, plain_len,
                        &provider_out, &provider_out_len,
                        ngx_cycle->log) != 0 || !provider_out)
    {
        return NGX_ERROR;
    }

    /* Copy into nginx pool so the provider can free its own buffer */
    u_char *buf = ngx_palloc(pool, provider_out_len);
    if (!buf) { free(provider_out); return NGX_ERROR; }

    ngx_memcpy(buf, provider_out, provider_out_len);
    free(provider_out);

    *out     = buf;
    *out_len = provider_out_len;
    return NGX_OK;
}

/* =========================================================================
 * Worker process init / exit
 * ========================================================================= */

static ngx_int_t
securelog_init_process(ngx_cycle_t *cycle)
{
    ngx_http_securelog_conf_t *cf;
    ngx_int_t                  rc;

    cf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_securelog);
    if (cf == NULL || cf->provider == SECURELOG_PROVIDER_UNSET) {
        return NGX_OK;
    }

    worker_state = ngx_pcalloc(cycle->pool, sizeof(securelog_worker_state_t));
    if (worker_state == NULL) return NGX_ERROR;

    worker_state->log_fd          = NGX_INVALID_FILE;
    worker_state->active_provider = cf->provider;

    switch (cf->provider) {
    case SECURELOG_PROVIDER_GPG:
        rc = securelog_gpg_init(cf, worker_state, cycle->log);
        break;
    case SECURELOG_PROVIDER_AES:
        rc = securelog_aes_init(cf, worker_state, cycle->log);
        break;
    case SECURELOG_PROVIDER_EXT:
        rc = securelog_ext_init(cf, worker_state, cycle->log);
        break;
    default:
        rc = NGX_ERROR;
    }

    return rc;
}

static void
securelog_exit_process(ngx_cycle_t *cycle)
{
    if (worker_state == NULL) return;

    if (worker_state->log_fd != NGX_INVALID_FILE) {
        ngx_close_file(worker_state->log_fd);
        worker_state->log_fd = NGX_INVALID_FILE;
    }

    if (worker_state->active_provider == SECURELOG_PROVIDER_GPG) {
        if (worker_state->gpg_key) {
            gpgme_key_release(worker_state->gpg_key);
            worker_state->gpg_key = NULL;
        }
        if (worker_state->gpg_ctx) {
            gpgme_release(worker_state->gpg_ctx);
            worker_state->gpg_ctx = NULL;
        }
    }

    if (worker_state->active_provider == SECURELOG_PROVIDER_AES) {
        ngx_explicit_memzero(worker_state->aes_key, AES_KEY_LEN);
    }

    if (worker_state->active_provider == SECURELOG_PROVIDER_EXT) {
        if (worker_state->ext.cleanup) worker_state->ext.cleanup();
        if (worker_state->ext.handle)  dlclose(worker_state->ext.handle);
    }

    worker_state = NULL;
}

/* =========================================================================
 * Log phase handler
 * ========================================================================= */

static ngx_int_t
ngx_http_securelog_handler(ngx_http_request_t *r)
{
    ngx_http_securelog_conf_t *cf;
    u_char                    *plain, *enc_out;
    size_t                     plain_len, enc_len;
    ngx_int_t                  rc;

    cf = ngx_http_get_module_main_conf(r, ngx_http_securelog);

    if (cf->provider == SECURELOG_PROVIDER_UNSET || worker_state == NULL) {
        return NGX_DECLINED;
    }

    /* ---- Build log message (dynamic pool allocation, no fixed buffer) ---- */
    ngx_str_t  null_str = ngx_null_string;
    ngx_str_t *ua  = r->headers_in.user_agent
                     ? &r->headers_in.user_agent->value : &null_str;
    ngx_str_t *ref = r->headers_in.referer
                     ? &r->headers_in.referer->value    : &null_str;

    /* ISO-8601 timestamp */
    u_char  tsbuf[32];
    time_t  now = ngx_time();
    struct  tm tm;
    localtime_r(&now, &tm);
    strftime((char *)tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%S%z", &tm);

    plain = ngx_pnalloc(r->pool, MAX_LOGMSG_SIZE);
    if (plain == NULL) return NGX_ERROR;

    u_char *p = ngx_snprintf(plain, MAX_LOGMSG_SIZE,
        "%s %V \"%V %V HTTP/%d.%d\" %ui \"%V\" \"%V\"\n",
        tsbuf,
        &r->connection->addr_text,
        &r->method_name,
        &r->uri,
        r->http_major, r->http_minor,
        r->headers_out.status,
        ref,
        ua);

    plain_len = (size_t)(p - plain);

    /* ---- Encrypt ---- */
    switch (worker_state->active_provider) {
    case SECURELOG_PROVIDER_GPG:
        rc = securelog_gpg_encrypt(worker_state, r->pool,
                                   plain, plain_len, &enc_out, &enc_len);
        break;
    case SECURELOG_PROVIDER_AES:
        rc = securelog_aes_encrypt(worker_state, r->pool,
                                   plain, plain_len, &enc_out, &enc_len);
        break;
    case SECURELOG_PROVIDER_EXT:
        rc = securelog_ext_encrypt(worker_state, r->pool,
                                   plain, plain_len, &enc_out, &enc_len);
        break;
    default:
        return NGX_DECLINED;
    }

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "securelog: encryption failed (provider=%d)",
                      worker_state->active_provider);
        return NGX_ERROR;
    }

    /* ---- Log rotation check ---- */
    if (securelog_needs_rotate(cf, worker_state, enc_len)) {
        if (worker_state->log_fd != NGX_INVALID_FILE) {
            ngx_close_file(worker_state->log_fd);
        }
        worker_state->log_fd = securelog_open_log(cf, worker_state,
                                                  r->connection->log);
        if (worker_state->log_fd == NGX_INVALID_FILE) return NGX_ERROR;
    }

    /* ---- Write (worker-local fd, no cross-process locking needed) ---- */
    ssize_t written = ngx_write_fd(worker_state->log_fd, enc_out, enc_len);
    if (written < 0 || (size_t)written != enc_len) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "securelog: write to \"%s\" failed",
                      worker_state->log_path);
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* =========================================================================
 * Post-config - register log phase handler
 * ========================================================================= */

static ngx_int_t
ngx_http_securelog_postconfig(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt       *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h    = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) return NGX_ERROR;

    *h = ngx_http_securelog_handler;
    return NGX_OK;
}

/* =========================================================================
 * Configuration create / merge
 * ========================================================================= */

static void *
ngx_http_securelog_create_conf(ngx_conf_t *cf)
{
    ngx_http_securelog_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_securelog_conf_t));
    if (conf == NULL) return NULL;

    conf->provider     = SECURELOG_PROVIDER_UNSET;
    conf->rotate_mode  = SECURELOG_ROTATE_DAILY;
    conf->rotate_size  = (off_t)(64 * 1024 * 1024); /* 64 MB default */

    /* log_dir default is applied in init_conf, NOT here.
     * ngx_conf_set_str_slot checks data != NULL to detect duplicates,
     * so pre-setting a value here would trigger "duplicate directive". */
    conf->log_dir.data = NULL;
    conf->log_dir.len  = 0;
    return conf;
}

static char *
ngx_http_securelog_init_conf(ngx_conf_t *cf, void *conf_v)
{
    ngx_http_securelog_conf_t *conf = conf_v;

    if (conf->provider == SECURELOG_PROVIDER_UNSET) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
            "securelog: securelog_provider not set - module is inactive");
        return NGX_CONF_OK;
    }

    /* Validate provider-specific required directives */
    switch (conf->provider) {
    case SECURELOG_PROVIDER_GPG:
        if (conf->gpg_pubkey.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "securelog: securelog_gpg_pubkey required for gpg provider");
            return NGX_CONF_ERROR;
        }
        break;
    case SECURELOG_PROVIDER_AES:
        if (conf->aes_keyfile.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "securelog: securelog_aes_keyfile required for aes provider");
            return NGX_CONF_ERROR;
        }
        break;
    case SECURELOG_PROVIDER_EXT:
        if (conf->ext_library.len == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "securelog: securelog_ext_library required for ext provider");
            return NGX_CONF_ERROR;
        }
        break;
    default:
        break;
    }

    /* Apply default log_dir if not set by directive */
    if (conf->log_dir.len == 0 || conf->log_dir.data == NULL) {
        ngx_str_set(&conf->log_dir, DEFAULT_LOG_DIR);
    }

    /* Ensure log directory exists */
    if (ngx_create_dir((char *)conf->log_dir.data, 0750) == NGX_FILE_ERROR
        && ngx_errno != NGX_EEXIST)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
            "securelog: cannot create log dir \"%V\"", &conf->log_dir);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/* =========================================================================
 * Custom directive handler: securelog_provider gpg|aes|ext
 * ========================================================================= */

static char *
ngx_http_securelog_set_provider(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_v)
{
    ngx_http_securelog_conf_t *conf = conf_v;
    ngx_str_t                 *value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *)"gpg") == 0) {
        conf->provider = SECURELOG_PROVIDER_GPG;
    } else if (ngx_strcasecmp(value[1].data, (u_char *)"aes") == 0) {
        conf->provider = SECURELOG_PROVIDER_AES;
    } else if (ngx_strcasecmp(value[1].data, (u_char *)"ext") == 0) {
        conf->provider = SECURELOG_PROVIDER_EXT;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "securelog: unknown provider \"%V\" (valid: gpg, aes, ext)",
            &value[1]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/* =========================================================================
 * Custom directive handler: securelog_rotate daily|hourly|size:NM
 * ========================================================================= */

static char *
ngx_http_securelog_set_rotate(ngx_conf_t *cf, ngx_command_t *cmd, void *conf_v)
{
    ngx_http_securelog_conf_t *conf = conf_v;
    ngx_str_t                 *value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *)"daily") == 0) {
        conf->rotate_mode = SECURELOG_ROTATE_DAILY;
    } else if (ngx_strcasecmp(value[1].data, (u_char *)"hourly") == 0) {
        conf->rotate_mode = SECURELOG_ROTATE_HOURLY;
    } else if (ngx_strncasecmp(value[1].data, (u_char *)"size:", 5) == 0) {
        conf->rotate_mode = SECURELOG_ROTATE_SIZE;
        /* Parse "size:64M" / "size:512K" / "size:1G" */
        u_char  *sz   = value[1].data + 5;
        off_t    mult = 1;
        size_t   slen = value[1].len - 5;
        if (slen > 0) {
            u_char last = sz[slen - 1];
            if (last == 'G' || last == 'g') { mult = 1024*1024*1024LL; slen--; }
            else if (last == 'M' || last == 'm') { mult = 1024*1024; slen--; }
            else if (last == 'K' || last == 'k') { mult = 1024; slen--; }
        }
        conf->rotate_size = (off_t)ngx_atoof(sz, slen) * mult;
        if (conf->rotate_size <= 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "securelog: invalid rotate size \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "securelog: unknown rotate value \"%V\" "
            "(valid: daily, hourly, size:NM)", &value[1]);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

/* =========================================================================
 * Directives table
 * ========================================================================= */

static ngx_command_t ngx_http_securelog_commands[] = {

    { ngx_string("securelog_provider"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_securelog_set_provider,
      NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },

    /* GPG */
    { ngx_string("securelog_gpg_pubkey"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_securelog_conf_t, gpg_pubkey), NULL },

    { ngx_string("securelog_gpg_keyid"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_securelog_conf_t, gpg_keyid), NULL },

    /* AES */
    { ngx_string("securelog_aes_keyfile"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_securelog_conf_t, aes_keyfile), NULL },

    /* EXT */
    { ngx_string("securelog_ext_library"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_securelog_conf_t, ext_library), NULL },

    { ngx_string("securelog_ext_param"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_securelog_conf_t, ext_param), NULL },

    /* Common */
    { ngx_string("securelog_dir"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_securelog_conf_t, log_dir), NULL },

    { ngx_string("securelog_rotate"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_securelog_set_rotate,
      NGX_HTTP_MAIN_CONF_OFFSET, 0, NULL },

    ngx_null_command
};

/* =========================================================================
 * Module context & definition
 * ========================================================================= */

static ngx_http_module_t ngx_http_securelog_module_ctx = {
    NULL,                              /* preconfiguration  */
    ngx_http_securelog_postconfig,     /* postconfiguration */

    ngx_http_securelog_create_conf,    /* create main conf  */
    ngx_http_securelog_init_conf,      /* init main conf    */

    NULL, NULL,                        /* server conf       */
    NULL, NULL                         /* location conf     */
};

ngx_module_t ngx_http_securelog = {
    NGX_MODULE_V1,
    &ngx_http_securelog_module_ctx,
    ngx_http_securelog_commands,
    NGX_HTTP_MODULE,
    NULL,                              /* init master       */
    NULL,                              /* init module       */
    securelog_init_process,            /* init process      */
    NULL,                              /* init thread       */
    NULL,                              /* exit thread       */
    securelog_exit_process,            /* exit process      */
    NULL,                              /* exit master       */
    NGX_MODULE_V1_PADDING
};

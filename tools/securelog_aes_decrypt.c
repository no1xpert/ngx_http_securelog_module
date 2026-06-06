/**
 * securelog_aes_decrypt.c
 * -----------------------
 * Reads a securelog AES-256-GCM binary log file and prints
 * each decrypted record to stdout.
 *
 * Wire format per record:
 *   [4 bytes BE : total_len = IV_LEN + TAG_LEN + cipher_len]
 *   [12 bytes   : IV / nonce]
 *   [16 bytes   : GCM auth tag]
 *   [N  bytes   : ciphertext]
 *
 * Build:
 *   gcc -O2 -o securelog_aes_decrypt securelog_aes_decrypt.c -lcrypto
 *
 * Usage:
 *   securelog_aes_decrypt <keyfile> <logfile>
 *   securelog_aes_decrypt /etc/securelog/aes.key /var/log/securelog/nginx-20250806.log.enc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

#define AES_KEY_LEN  32
#define AES_IV_LEN   12
#define AES_TAG_LEN  16

static int
decrypt_record(const unsigned char *key,
               const unsigned char *iv,
               const unsigned char *tag,
               const unsigned char *cipher, size_t cipher_len,
               unsigned char *plain, int *plain_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, ok = 0;

    ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL) &&
         EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) &&
         EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len);

    *plain_len = len;

    if (!ok) { EVP_CIPHER_CTX_free(ctx); return -1; }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN,
                        (void *)(uintptr_t)tag);

    int final_ok = EVP_DecryptFinal_ex(ctx, plain + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (!final_ok) {
        fprintf(stderr, "securelog_aes_decrypt: GCM auth tag mismatch "
                        "(record tampered or wrong key)\n");
        return -1;
    }
    *plain_len += len;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <keyfile> <logfile>\n", argv[0]);
        return 1;
    }

    /* Load key */
    unsigned char key[AES_KEY_LEN];
    FILE *kf = fopen(argv[1], "rb");
    if (!kf) { perror("open keyfile"); return 1; }
    if (fread(key, 1, AES_KEY_LEN, kf) != AES_KEY_LEN) {
        fprintf(stderr, "keyfile must be exactly %d bytes\n", AES_KEY_LEN);
        fclose(kf); return 1;
    }
    fclose(kf);

    /* Open log */
    FILE *lf = fopen(argv[2], "rb");
    if (!lf) { perror("open logfile"); return 1; }

    unsigned char  hdr[4];
    unsigned long  record_no = 0;
    int            errors    = 0;

    while (fread(hdr, 1, 4, lf) == 4) {
        uint32_t total_len = ((uint32_t)hdr[0] << 24)
                           | ((uint32_t)hdr[1] << 16)
                           | ((uint32_t)hdr[2] <<  8)
                           |  (uint32_t)hdr[3];

        if (total_len < AES_IV_LEN + AES_TAG_LEN) {
            fprintf(stderr, "record %lu: invalid length %u\n",
                    record_no, total_len);
            break;
        }

        size_t cipher_len = total_len - AES_IV_LEN - AES_TAG_LEN;

        unsigned char *buf = malloc(total_len + 1);
        if (!buf) { perror("malloc"); break; }

        if (fread(buf, 1, total_len, lf) != total_len) {
            fprintf(stderr, "record %lu: truncated\n", record_no);
            free(buf); break;
        }

        unsigned char *iv     = buf;
        unsigned char *tag    = buf + AES_IV_LEN;
        unsigned char *cipher = buf + AES_IV_LEN + AES_TAG_LEN;
        unsigned char *plain  = malloc(cipher_len + 1);
        int            plain_len = 0;

        if (!plain) { perror("malloc"); free(buf); break; }

        if (decrypt_record(key, iv, tag, cipher, cipher_len,
                           plain, &plain_len) == 0) {
            fwrite(plain, 1, plain_len, stdout);
        } else {
            fprintf(stderr, "record %lu: decryption failed\n", record_no);
            errors++;
        }

        free(plain);
        free(buf);
        record_no++;
    }

    fclose(lf);
    fprintf(stderr, "[securelog_aes_decrypt] %lu records, %d error(s)\n",
            record_no, errors);
    return errors ? 1 : 0;
}

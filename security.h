/**
 *
 * Encryption (XOR), integrity (CRC-32), message ID generation.
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <stddef.h>
#include <stdint.h>

#define SEC_KEY_LEN 16
#define SEC_DEFAULT_KEY "DistribSys2025!!"

#define SEC_OK 0
#define SEC_ERR_OVERFLOW -1
#define SEC_ERR_VERIFY -2
#define SEC_ERR_PARAM -3

/* Initialization ------------------------------------------------ */
void sec_init(const char *key);

/* Encryption / decryption (XOR) --------------------------------- */
int sec_encrypt(const uint8_t *in, size_t in_len, uint8_t *out,
                size_t *out_len);
int sec_decrypt(const uint8_t *in, size_t in_len, uint8_t *out,
                size_t *out_len);

/* Integrity ----------------------------------------------------- */
uint32_t sec_crc32(const uint8_t *data, size_t len);
int sec_verify_integrity(const uint8_t *data, size_t len,
                         uint32_t expected_crc);

/* Message ID generation ----------------------------------------- */
uint32_t sec_generate_msg_id(void);

#endif /* SECURITY_H */

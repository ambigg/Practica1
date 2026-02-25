/**
 * XOR encryption, CRC-32 integrity, message ID generation.
 */

#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint8_t g_key[SEC_KEY_LEN];
static int g_initialized = 0;

/* CRC-32 table (IEEE 802.3) --------------------------------------- */
static uint32_t crc_table[256];
static int crc_table_ready = 0;

static void build_crc_table(void) {
  if (crc_table_ready)
    return;
  uint32_t poly = 0xEDB88320u;
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int j = 0; j < 8; j++)
      c = (c & 1) ? (poly ^ (c >> 1)) : (c >> 1);
    crc_table[i] = c;
  }
  crc_table_ready = 1;
}

/* Implementation -------------------------------------------------- */

void sec_init(const char *key) {
  if (!key)
    key = SEC_DEFAULT_KEY;
  for (int i = 0; i < SEC_KEY_LEN; i++) {
    size_t key_len = strlen(key);
    g_key[i] = (uint8_t)key[i % key_len];
  }
  build_crc_table();
  srand((unsigned)time(NULL));
  g_initialized = 1;
  fprintf(stderr, "[SEC] Layer 3 initialized.\n");
}

/* XOR with rotating key (encryption = decryption) */
static int xor_transform(const uint8_t *in, size_t in_len, uint8_t *out,
                         size_t *out_len) {
  if (!g_initialized)
    sec_init(NULL);
  if (!in || !out || !out_len)
    return SEC_ERR_PARAM;
  if (in_len == 0) {
    *out_len = 0;
    return SEC_OK;
  }

  for (size_t i = 0; i < in_len; i++)
    out[i] = in[i] ^ g_key[i % SEC_KEY_LEN];
  *out_len = in_len;
  return SEC_OK;
}

int sec_encrypt(const uint8_t *in, size_t in_len, uint8_t *out,
                size_t *out_len) {
  return xor_transform(in, in_len, out, out_len);
}

int sec_decrypt(const uint8_t *in, size_t in_len, uint8_t *out,
                size_t *out_len) {
  return xor_transform(in, in_len, out, out_len);
}

uint32_t sec_crc32(const uint8_t *data, size_t len) {
  build_crc_table();
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++)
    crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
  return crc ^ 0xFFFFFFFFu;
}

int sec_verify_integrity(const uint8_t *data, size_t len,
                         uint32_t expected_crc) {
  uint32_t actual = sec_crc32(data, len);
  if (actual != expected_crc) {
    fprintf(stderr, "[SEC] Integrity fail: expected=0x%08X actual=0x%08X\n",
            expected_crc, actual);
    return SEC_ERR_VERIFY;
  }
  return SEC_OK;
}

uint32_t sec_generate_msg_id(void) {
  if (!g_initialized)
    sec_init(NULL);
  uint32_t t = (uint32_t)(time(NULL) & 0xFFFF);
  uint32_t rnd = (uint32_t)(rand() & 0xFFFF);
  return (t << 16) | rnd;
}

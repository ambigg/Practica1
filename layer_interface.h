/**
 * layer_interface.h
 * Communication contract between layers.
 */

#ifndef LAYER_INTERFACE_H
#define LAYER_INTERFACE_H

#include <stddef.h>
#include <stdint.h>

/* Default ports ---------------------------------------------------- */
#define DEFAULT_PORT 9000
#define BROADCAST_PORT 9001
#define LOG_PORT 9002

/* Limits ---------------------------------------------------------- */
#define MAX_PAYLOAD_SIZE 4096
#define MAX_FILENAME_LEN 256
#define MAX_IP_STR_LEN 16
#define PROTOCOL_VERSION 1
#define MAGIC_BYTES 0xABCD

/* Message types --------------------------------------------------- */
typedef enum {
  /* Client requests */
  MSG_REQ_FILE_INFO = 0x01, /* Request file attributes          */
  MSG_REQ_DIR_LIST = 0x02,  /* Request directory list           */
  MSG_REQ_USE_FILE = 0x03,  /* Request to read/write a file     */
  MSG_REQ_SYNC_FILE = 0x04, /* Sync changes to owner             */

  /* Server responses */
  MSG_RES_FILE_ATTRS = 0x10,    /* File attributes (authoritative)  */
  MSG_RES_FILE_OWNER = 0x11,    /* Owner IP (non‑authoritative)     */
  MSG_RES_NACK = 0x12,          /* Not known (non‑authoritative)    */
  MSG_RES_DIR_LIST = 0x13,      /* List of shared files             */
  MSG_RES_FILE_DATA = 0x14,     /* File contents                    */
  MSG_RES_ACK = 0x15,           /* Generic acknowledgement          */
  MSG_RES_SYNC_OK = 0x16,       /* Sync accepted                    */
  MSG_RES_SYNC_CONFLICT = 0x17, /* Version conflict                 */

  /* Server‑server */
  MSG_SRV_PUBLISH = 0x20,      /* Publish new file                 */
  MSG_SRV_UPDATE_OWNER = 0x21, /* Notify owner change              */
  MSG_SRV_INVALIDATE = 0x22,   /* File no longer exists            */
  MSG_SRV_HEARTBEAT = 0x23,    /* Keep‑alive + file list           */
} MessageType;

/* Header flags ---------------------------------------------------- */
#define FLAG_AUTHORITATIVE 0x01 /* Authoritative response          */
#define FLAG_ENCRYPTED 0x02     /* Payload encrypted               */
#define FLAG_COMPRESSED 0x04    /* Reserved for compression        */
#define FLAG_BROADCAST 0x08     /* Broadcast message               */
#define FLAG_LAST_FRAGMENT 0x10 /* Last fragment (large files)     */

/* Protocol header (26 bytes) -------------------------------------- */
#pragma pack(push, 1)
typedef struct {
  uint16_t magic;       /* Protocol identifier (0xABCD)          */
  uint8_t version;      /* Protocol version                      */
  uint8_t msg_type;     /* MessageType                           */
  uint32_t msg_id;      /* Unique message ID                     */
  uint32_t source_ip;   /* Source IP (network byte order)        */
  uint32_t dest_ip;     /* Destination IP (network byte order)   */
  uint32_t payload_len; /* Length of encrypted payload           */
  uint32_t checksum;    /* CRC32 of encrypted payload            */
  uint8_t flags;        /* Flags (authoritative, encrypted, ...) */
  uint8_t ttl;          /* Resource TTL (0 = permanent)          */
} ProtocolHeader;
#pragma pack(pop)

/* File attributes (payload of MSG_RES_FILE_ATTRS) ----------------- */
#pragma pack(push, 1)
typedef struct {
  char filename[MAX_FILENAME_LEN];
  char extension[16];
  uint64_t size_bytes;
  int64_t created_at;
  int64_t modified_at;
  uint8_t ttl;
  char owner_ip[MAX_IP_STR_LEN];
  uint32_t owner_port;
  uint32_t version;
} FileAttributes;
#pragma pack(pop)

/* Complete message used by Layer 2 -------------------------------- */
typedef struct {
  ProtocolHeader header;
  uint8_t payload[MAX_PAYLOAD_SIZE];
} Message;

/* Callbacks ------------------------------------------------------- */
/* Registered by Layer 4 (Javier) to send raw UDP bytes. */
typedef int (*net_send_fn_t)(const uint8_t *data, size_t len,
                             const char *dest_ip, uint16_t dest_port);

/* Registered by Layer 5 (César) to receive parsed messages. */
typedef void (*msg_recv_fn_t)(const Message *msg, const char *src_ip,
                              uint16_t src_port);

#endif /* LAYER_INTERFACE_H */

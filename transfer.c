#include "transfer.h"
#include "security.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static char g_my_ip[MAX_IP_STR_LEN] = "127.0.0.1";
static net_send_fn_t g_send_fn = NULL;
static msg_recv_fn_t g_recv_fn = NULL;

#define WIRE_HEADER_SIZE sizeof(ProtocolHeader)

void transfer_init(const char *my_ip) {
  if (my_ip) {
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);
    g_my_ip[MAX_IP_STR_LEN - 1] = '\0';
  }
  sec_init(NULL);
  fprintf(stderr, "[TRANSFER] Capa 2 inicializada. IP local: %s\n", g_my_ip);
}

void transfer_register_send_fn(net_send_fn_t fn) {
  g_send_fn = fn;
  fprintf(stderr, "[TRANSFER] Función de envío (Capa 4) registrada.\n");
}

void transfer_register_recv_fn(msg_recv_fn_t fn) {
  g_recv_fn = fn;
  fprintf(stderr, "[TRANSFER] Callback de recepción (Capa 5) registrado.\n");
}

uint32_t transfer_ip_to_uint32(const char *ip_str) {
  struct in_addr addr;
  if (inet_pton(AF_INET, ip_str, &addr) != 1)
    return 0;
  return ntohl(addr.s_addr);
}

void transfer_uint32_to_ip(uint32_t ip, char *out_str) {
  struct in_addr addr;
  addr.s_addr = htonl(ip);
  inet_ntop(AF_INET, &addr, out_str, MAX_IP_STR_LEN);
}

static void init_header(Message *msg, MessageType type, uint8_t flags,
                        uint8_t ttl) {
  memset(msg, 0, sizeof(Message));
  msg->header.magic = htons(MAGIC_BYTES);
  msg->header.version = PROTOCOL_VERSION;
  msg->header.msg_type = (uint8_t)type;
  msg->header.msg_id = htonl(sec_generate_msg_id());
  msg->header.source_ip = htonl(transfer_ip_to_uint32(g_my_ip));
  msg->header.flags = flags;
  msg->header.ttl = ttl;
}

int transfer_send_message(const Message *msg, const char *dest_ip,
                          uint16_t dest_port) {
  if (!g_send_fn) {
    fprintf(stderr, "[TRANSFER] ERROR: send_fn no registrada.\n");
    return -1;
  }

  uint32_t payload_len = ntohl(msg->header.payload_len);
  uint8_t enc_payload[MAX_PAYLOAD_SIZE];
  size_t enc_len = 0;

  if (payload_len > 0) {
    int rc = sec_encrypt(msg->payload, payload_len, enc_payload, &enc_len);
    if (rc != SEC_OK) {
      fprintf(stderr, "[TRANSFER] Error al cifrar payload: %d\n", rc);
      return -2;
    }
  }

  uint8_t wire_buf[WIRE_MAX_SIZE];
  ProtocolHeader wire_hdr = msg->header;

  wire_hdr.checksum = htonl(sec_crc32(enc_payload, enc_len));
  wire_hdr.payload_len = htonl((uint32_t)enc_len);
  wire_hdr.dest_ip = htonl(transfer_ip_to_uint32(dest_ip));
  wire_hdr.flags |= FLAG_ENCRYPTED;

  memcpy(wire_buf, &wire_hdr, WIRE_HEADER_SIZE);
  if (enc_len > 0) {
    memcpy(wire_buf + WIRE_HEADER_SIZE, enc_payload, enc_len);
  }

  size_t total = WIRE_HEADER_SIZE + enc_len;
  int sent = g_send_fn(wire_buf, total, dest_ip, dest_port);
  if (sent < 0) {
    fprintf(stderr, "[TRANSFER] Error en Capa 4 al enviar a %s:%d\n", dest_ip,
            dest_port);
    return -3;
  }

  fprintf(stderr,
          "[TRANSFER] Enviado msg_id=0x%08X tipo=0x%02X a %s:%d (%zu bytes)\n",
          ntohl(wire_hdr.msg_id), wire_hdr.msg_type, dest_ip, dest_port, total);
  return 0;
}

void transfer_on_raw_receive(const uint8_t *raw, size_t raw_len,
                             const char *src_ip, uint16_t src_port) {
  if (raw_len < WIRE_HEADER_SIZE) {
    fprintf(stderr, "[TRANSFER] Paquete demasiado pequeño (%zu bytes)\n",
            raw_len);
    return;
  }

  Message msg;
  memcpy(&msg.header, raw, WIRE_HEADER_SIZE);

  if (ntohs(msg.header.magic) != MAGIC_BYTES) {
    fprintf(stderr, "[TRANSFER] Magic inválido: 0x%04X\n",
            ntohs(msg.header.magic));
    return;
  }
  if (msg.header.version != PROTOCOL_VERSION) {
    fprintf(stderr, "[TRANSFER] Versión de protocolo no soportada: %d\n",
            msg.header.version);
    return;
  }

  uint32_t enc_len = ntohl(msg.header.payload_len);

  if (enc_len > 0) {
    if (raw_len < WIRE_HEADER_SIZE + enc_len) {
      fprintf(stderr, "[TRANSFER] Payload incompleto\n");
      return;
    }
    const uint8_t *enc_payload = raw + WIRE_HEADER_SIZE;
    int ok =
        sec_verify_integrity(enc_payload, enc_len, ntohl(msg.header.checksum));
    if (ok != SEC_OK) {
      fprintf(stderr, "[TRANSFER] Integridad fallida para msg de %s\n", src_ip);
      return;
    }

    size_t plain_len = 0;
    int rc = sec_decrypt(enc_payload, enc_len, msg.payload, &plain_len);
    if (rc != SEC_OK) {
      fprintf(stderr, "[TRANSFER] Error al descifrar payload\n");
      return;
    }
    msg.header.payload_len = htonl((uint32_t)plain_len);
    msg.header.flags &= (uint8_t)~FLAG_ENCRYPTED;
  }

  fprintf(stderr, "[TRANSFER] Recibido msg_id=0x%08X tipo=0x%02X de %s:%d\n",
          ntohl(msg.header.msg_id), msg.header.msg_type, src_ip, src_port);

  if (g_recv_fn) {
    g_recv_fn(&msg, src_ip, src_port);
  } else {
    fprintf(
        stderr,
        "[TRANSFER] ADVERTENCIA: recv_fn no registrada. Mensaje descartado.\n");
  }
}

int transfer_build_req_file_info(Message *msg, const char *filename,
                                 const char *my_ip) {
  if (!msg || !filename)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  init_header(msg, MSG_REQ_FILE_INFO, 0, 0);
  size_t fn_len = strnlen(filename, MAX_FILENAME_LEN - 1);
  memcpy(msg->payload, filename, fn_len);
  msg->payload[fn_len] = '\0';
  msg->header.payload_len = htonl((uint32_t)(fn_len + 1));
  return 0;
}

int transfer_build_req_dir_list(Message *msg, const char *my_ip) {
  if (!msg)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  init_header(msg, MSG_REQ_DIR_LIST, 0, 0);
  msg->header.payload_len = htonl(0);
  return 0;
}

int transfer_build_req_use_file(Message *msg, const char *filename,
                                const char *my_ip) {
  if (!msg || !filename)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  init_header(msg, MSG_REQ_USE_FILE, 0, 0);
  size_t fn_len = strnlen(filename, MAX_FILENAME_LEN - 1);
  memcpy(msg->payload, filename, fn_len);
  msg->payload[fn_len] = '\0';
  msg->header.payload_len = htonl((uint32_t)(fn_len + 1));
  return 0;
}

int transfer_build_res_file_attrs(Message *msg, const FileAttributes *attrs,
                                  const char *my_ip, int authoritative) {
  if (!msg || !attrs)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  uint8_t flags = authoritative ? FLAG_AUTHORITATIVE : 0;
  init_header(msg, MSG_RES_FILE_ATTRS, flags, attrs->ttl);
  memcpy(msg->payload, attrs, sizeof(FileAttributes));
  msg->header.payload_len = htonl(sizeof(FileAttributes));
  return 0;
}

int transfer_build_res_file_owner(Message *msg, const char *owner_ip,
                                  uint16_t owner_port, const char *my_ip) {
  if (!msg || !owner_ip)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  init_header(msg, MSG_RES_FILE_OWNER, 0, 0);
  int n = snprintf((char *)msg->payload, MAX_PAYLOAD_SIZE, "%s:%d", owner_ip,
                   owner_port);
  msg->header.payload_len = htonl((uint32_t)(n + 1));
  return 0;
}

int transfer_build_res_nack(Message *msg, const char *my_ip,
                            const char *reason) {
  if (!msg)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  init_header(msg, MSG_RES_NACK, 0, 0);
  if (reason) {
    size_t rlen = strnlen(reason, MAX_PAYLOAD_SIZE - 1);
    memcpy(msg->payload, reason, rlen);
    msg->payload[rlen] = '\0';
    msg->header.payload_len = htonl((uint32_t)(rlen + 1));
  } else {
    msg->header.payload_len = htonl(0);
  }
  return 0;
}

int transfer_build_res_ack(Message *msg, const char *my_ip, uint32_t ref_id) {
  if (!msg)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  init_header(msg, MSG_RES_ACK, FLAG_AUTHORITATIVE, 0);
  uint32_t net_id = htonl(ref_id);
  memcpy(msg->payload, &net_id, sizeof(uint32_t));
  msg->header.payload_len = htonl(sizeof(uint32_t));
  return 0;
}

int transfer_build_srv_publish(Message *msg, const FileAttributes *attrs,
                               const char *my_ip) {
  if (!msg || !attrs)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  init_header(msg, MSG_SRV_PUBLISH, FLAG_AUTHORITATIVE, attrs->ttl);
  memcpy(msg->payload, attrs, sizeof(FileAttributes));
  msg->header.payload_len = htonl(sizeof(FileAttributes));
  return 0;
}

int transfer_build_res_file_data(Message *msg, const char *filename,
                                 const uint8_t *data, size_t data_len,
                                 const char *my_ip) {
  if (!msg || !data)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  if (MAX_FILENAME_LEN + data_len > MAX_PAYLOAD_SIZE) {
    fprintf(stderr, "[TRANSFER] Archivo demasiado grande para un mensaje\n");
    return -2;
  }

  init_header(msg, MSG_RES_FILE_DATA, FLAG_AUTHORITATIVE, 0);
  memset(msg->payload, 0, MAX_FILENAME_LEN);
  strncpy((char *)msg->payload, filename, MAX_FILENAME_LEN - 1);
  memcpy(msg->payload + MAX_FILENAME_LEN, data, data_len);
  msg->header.payload_len = htonl((uint32_t)(MAX_FILENAME_LEN + data_len));
  return 0;
}

int transfer_build_req_sync(Message *msg, const char *filename,
                            const uint8_t *data, size_t data_len,
                            uint32_t version, const char *my_ip) {
  if (!msg || !data)
    return -1;
  if (my_ip)
    strncpy(g_my_ip, my_ip, MAX_IP_STR_LEN - 1);

  if (MAX_FILENAME_LEN + sizeof(uint32_t) + data_len > MAX_PAYLOAD_SIZE)
    return -2;

  init_header(msg, MSG_REQ_SYNC_FILE, 0, 0);
  uint8_t *p = msg->payload;
  memset(p, 0, MAX_FILENAME_LEN);
  strncpy((char *)p, filename, MAX_FILENAME_LEN - 1);
  p += MAX_FILENAME_LEN;

  uint32_t net_ver = htonl(version);
  memcpy(p, &net_ver, sizeof(uint32_t));
  p += sizeof(uint32_t);

  memcpy(p, data, data_len);
  msg->header.payload_len =
      htonl((uint32_t)(MAX_FILENAME_LEN + sizeof(uint32_t) + data_len));
  return 0;
}

int transfer_is_authoritative(const Message *msg) {
  return (msg->header.flags & FLAG_AUTHORITATIVE) ? 1 : 0;
}

MessageType transfer_get_type(const Message *msg) {
  return (MessageType)msg->header.msg_type;
}

int transfer_parse_file_attrs(const Message *msg, FileAttributes *out) {
  if (!msg || !out)
    return -1;
  if (ntohl(msg->header.payload_len) < sizeof(FileAttributes))
    return -2;
  memcpy(out, msg->payload, sizeof(FileAttributes));
  return 0;
}

int transfer_parse_owner_ip(const Message *msg, char *out_ip,
                            uint16_t *out_port) {
  if (!msg || !out_ip || !out_port)
    return -1;
  char tmp[MAX_IP_STR_LEN + 8];
  uint32_t plen = ntohl(msg->header.payload_len);
  if (plen == 0 || plen > sizeof(tmp))
    return -2;
  memcpy(tmp, msg->payload, plen);
  tmp[plen - 1] = '\0';

  char *colon = strchr(tmp, ':');
  if (!colon)
    return -3;
  *colon = '\0';
  strncpy(out_ip, tmp, MAX_IP_STR_LEN - 1);
  out_ip[MAX_IP_STR_LEN - 1] = '\0';
  *out_port = (uint16_t)atoi(colon + 1);
  return 0;
}

int transfer_parse_file_data(const Message *msg, uint8_t *out_data,
                             size_t *out_len) {
  if (!msg || !out_data || !out_len)
    return -1;
  uint32_t plen = ntohl(msg->header.payload_len);
  if (plen <= MAX_FILENAME_LEN)
    return -2;

  size_t data_len = plen - MAX_FILENAME_LEN;
  memcpy(out_data, msg->payload + MAX_FILENAME_LEN, data_len);
  *out_len = data_len;
  return 0;
}

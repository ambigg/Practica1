/**
 * transfer.h - Layer 2: Transfer
 *
 * Builds/parses protocol messages, calls security layer.
 * Provides callbacks for Layer 4 (send) and Layer 5 (receive).
 */
#ifndef TRANSFER_H
#define TRANSFER_H

#include "../layer_interface.h"

#define WIRE_MAX_SIZE (sizeof(ProtocolHeader) + MAX_PAYLOAD_SIZE)

/* Initialization ------------------------------------------------------ */

void transfer_init(const char *my_ip);
void transfer_register_send_fn(net_send_fn_t fn);
void transfer_register_recv_fn(msg_recv_fn_t fn);

/* Send API (Layer 5 → Layer 2) ---------------------------------------- */

int transfer_send_message(const Message *msg, const char *dest_ip,
                          uint16_t dest_port);

/* Receive API (Layer 4 → Layer 2) ------------------------------------- */

void transfer_on_raw_receive(const uint8_t *raw, size_t raw_len,
                             const char *src_ip, uint16_t src_port);

/* Message constructors ------------------------------------------------ */

int transfer_build_req_file_info(Message *msg, const char *filename,
                                 const char *my_ip);
int transfer_build_req_dir_list(Message *msg, const char *my_ip);
int transfer_build_req_use_file(Message *msg, const char *filename,
                                const char *my_ip);
int transfer_build_res_file_attrs(Message *msg, const FileAttributes *attrs,
                                  const char *my_ip, int authoritative);
int transfer_build_res_file_owner(Message *msg, const char *owner_ip,
                                  uint16_t owner_port, const char *my_ip);
int transfer_build_res_nack(Message *msg, const char *my_ip,
                            const char *reason);
int transfer_build_res_ack(Message *msg, const char *my_ip, uint32_t ref_id);
int transfer_build_srv_publish(Message *msg, const FileAttributes *attrs,
                               const char *my_ip);
int transfer_build_res_file_data(Message *msg, const char *filename,
                                 const uint8_t *data, size_t data_len,
                                 const char *my_ip);
int transfer_build_req_sync(Message *msg, const char *filename,
                            const uint8_t *data, size_t data_len,
                            uint32_t version, const char *my_ip);

/* Utilities ----------------------------------------------------------- */

int transfer_is_authoritative(const Message *msg);
MessageType transfer_get_type(const Message *msg);
int transfer_parse_file_attrs(const Message *msg, FileAttributes *out);
int transfer_parse_owner_ip(const Message *msg, char *out_ip,
                            uint16_t *out_port);
int transfer_parse_file_data(const Message *msg, uint8_t *out_data,
                             size_t *out_len);

uint32_t transfer_ip_to_uint32(const char *ip_str);
void transfer_uint32_to_ip(uint32_t ip, char *out_str);

#endif

/**
 * @file common.h
 * @brief Общие определения, константы и макросы для OverProto
 */

#ifndef OVERPROTO_COMMON_H
#define OVERPROTO_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET op_socket_t;
#define OP_INVALID_SOCKET INVALID_SOCKET
#else
typedef int op_socket_t;
#define OP_INVALID_SOCKET (-1)
#endif

/* Константы протокола */
#define OP_MAGIC               0xABCD
#define OP_VERSION             0x01
#define OP_HEADER_SIZE         24
#define OP_FRAG_MTU_DEFAULT    1400

/* Флаги пакета */
#define OP_FLAG_FRAGMENT       0x01
#define OP_FLAG_COMPRESSED     0x02
#define OP_FLAG_ENCRYPTED      0x04
#define OP_FLAG_RELIABLE       0x08
#define OP_FLAG_ACK            0x10

/* Opcode операции */
#define OP_DATA                0x01
#define OP_CONTROL             0x02
#define OP_ACK                 0x03
#define OP_PING                0x04
#define OP_PONG                0x05

/* Тип протокола */
#define OP_PROTO_TCP           0x01
#define OP_PROTO_UDP           0x02
#define OP_PROTO_HTTP          0x03

/* Макросы логирования (базовые заглушки для Phase 1) */
#define OP_LOG_DEBUG(fmt, ...) \
    do { \
        fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define OP_LOG_INFO(fmt, ...) \
    do { \
        fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define OP_LOG_WARN(fmt, ...) \
    do { \
        fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define OP_LOG_ERROR(fmt, ...) \
    do { \
        fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

/**
 * @brief Конфигурация OverProto
 */
typedef struct {
    uint16_t tcp_port;          /* TCP порт по умолчанию */
    uint16_t udp_port;          /* UDP порт по умолчанию */
    size_t mtu;                 /* MTU по умолчанию (1400 для UDP) */
    int non_blocking;           /* Non-blocking режим сокетов */
} OpConfig;

/**
 * @brief Инициализация конфигурации значениями по умолчанию
 * @param cfg Указатель на структуру конфигурации
 */
static inline void op_config_init(OpConfig *cfg)
{
    if (cfg == NULL) {
        return;
    }
    cfg->tcp_port = 8080;
    cfg->udp_port = 8080;
    cfg->mtu = 1400;
    cfg->non_blocking = 0;
}

#endif /* OVERPROTO_COMMON_H */

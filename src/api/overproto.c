/**
 * @file overproto.c
 * @brief Реализация публичного API библиотеки OverProto
 */

#include "overproto.h"
#include "../transport/reliable.h"
#include "../core/fragment.h"
#include "../optimize/compress.h"
#include "../optimize/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#define OP_MUTEX_TYPE SRWLOCK
#define OP_MUTEX_INITIALIZER SRWLOCK_INIT
#define OP_MUTEX_LOCK(mtx) AcquireSRWLockExclusive((mtx))
#define OP_MUTEX_UNLOCK(mtx) ReleaseSRWLockExclusive((mtx))
#else
#include <pthread.h>
#define OP_MUTEX_TYPE pthread_mutex_t
#define OP_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#define OP_MUTEX_LOCK(mtx) pthread_mutex_lock((mtx))
#define OP_MUTEX_UNLOCK(mtx) pthread_mutex_unlock((mtx))
#endif

/* Глобальная конфигурация */
static OpConfig g_config;
static int g_initialized = 0;
static OP_MUTEX_TYPE g_config_mutex = OP_MUTEX_INITIALIZER;

/* Callback для приёма пакетов */
static op_recv_cb g_recv_callback = NULL;
static void *g_recv_ctx = NULL;
static OP_MUTEX_TYPE g_callback_mutex = OP_MUTEX_INITIALIZER;

int op_init(const OpConfig *cfg)
{
    int result = 0;

    OP_MUTEX_LOCK(&g_config_mutex);

    if (g_initialized) {
        OP_LOG_WARN("OverProto already initialized");
        OP_MUTEX_UNLOCK(&g_config_mutex);
        return 0;
    }

#ifdef _WIN32
    {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            errno = EIO;
            OP_MUTEX_UNLOCK(&g_config_mutex);
            OP_LOG_ERROR("WSAStartup() failed");
            return -1;
        }
    }
#endif

    if (cfg != NULL) {
        memcpy(&g_config, cfg, sizeof(OpConfig));
    } else {
        /* Используем значения по умолчанию */
        op_config_init(&g_config);
    }

    g_initialized = 1;
    OP_LOG_INFO("OverProto initialized (TCP port: %u, UDP port: %u)",
                g_config.tcp_port, g_config.udp_port);

    OP_MUTEX_UNLOCK(&g_config_mutex);
    return result;
}

void op_shutdown(void)
{
    OP_MUTEX_LOCK(&g_config_mutex);

    if (!g_initialized) {
        OP_MUTEX_UNLOCK(&g_config_mutex);
        return;
    }

    /* Сбрасываем callback */
    OP_MUTEX_LOCK(&g_callback_mutex);
    g_recv_callback = NULL;
    g_recv_ctx = NULL;
    OP_MUTEX_UNLOCK(&g_callback_mutex);

    /* Сбрасываем конфигурацию */
    memset(&g_config, 0, sizeof(OpConfig));
    g_initialized = 0;

#ifdef _WIN32
    WSACleanup();
#endif

    OP_LOG_INFO("OverProto shut down");

    OP_MUTEX_UNLOCK(&g_config_mutex);
}

void op_set_handler(op_recv_cb callback, void *ctx)
{
    OP_MUTEX_LOCK(&g_callback_mutex);
    g_recv_callback = callback;
    g_recv_ctx = ctx;
    OP_MUTEX_UNLOCK(&g_callback_mutex);
}

ssize_t op_send(op_socket_t fd, uint32_t stream_id, uint8_t opcode, uint8_t proto,
                const void *data, size_t len, uint8_t flags)
{
    OverPacketHeader hdr;
    time_t now;
    const void *payload_data = data;
    size_t payload_len = len;
    void *compressed_data = NULL;
    size_t compressed_len = 0;
    void *encrypted_data = NULL;
    size_t encrypted_len = 0;
    uint8_t iv[OP_CRYPTO_IV_SIZE] = {0};
    int compress_result;
    int encrypt_result;
    int free_compressed = 0;
    int free_encrypted = 0;

    if (fd == OP_INVALID_SOCKET) {
        errno = EINVAL;
        return -1;
    }

    /* Проверка длины payload */
    if (len > UINT16_MAX) {
        OP_LOG_ERROR("Payload too large: %zu > %u", len, UINT16_MAX);
        errno = EINVAL;
        return -1;
    }

    /* Автоматическая компрессия если размер >= порога */
    if (len > 0 && op_should_compress(len) && (flags & OP_FLAG_COMPRESSED) == 0) {
        compress_result = op_compress(data, len, &compressed_data, &compressed_len);
        if (compress_result == 0) {
            /* Компрессия успешна и эффективна */
            payload_data = compressed_data;
            payload_len = compressed_len;
            flags |= OP_FLAG_COMPRESSED;
            free_compressed = 1;
            OP_LOG_DEBUG("Auto-compressed %zu bytes to %zu bytes", len, compressed_len);
        } else if (errno == EAGAIN) {
            /* Компрессия неэффективна, используем исходные данные */
            OP_LOG_DEBUG("Compression not effective, using original data");
        } else {
            /* Ошибка компрессии, используем исходные данные */
            OP_LOG_WARN("Compression failed, using original data: %s", strerror(errno));
        }
    }

    /* Шифрование если флаг установлен */
    if ((flags & OP_FLAG_ENCRYPTED) != 0 && payload_len > 0) {
        encrypt_result = op_encrypt(payload_data, payload_len,
                                    &encrypted_data, &encrypted_len, iv);
        if (encrypt_result == 0) {
            /* Шифрование успешно */
            payload_data = encrypted_data;
            payload_len = encrypted_len;
            free_encrypted = 1;
            OP_LOG_DEBUG("Encrypted %zu bytes to %zu bytes", 
                        free_compressed ? compressed_len : len, encrypted_len);
        } else {
            /* Ошибка шифрования */
            OP_LOG_ERROR("Encryption failed: %s", strerror(errno));
            /* Снимаем флаг шифрования, отправляем без шифрования */
            flags &= ~OP_FLAG_ENCRYPTED;
        }
    }

    /* Инициализируем заголовок */
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = OP_MAGIC;
    hdr.version = OP_VERSION;
    hdr.flags = flags;
    hdr.opcode = opcode;
    hdr.proto = proto;
    hdr.stream_id = stream_id;
    hdr.seq = 0;  /* TODO: Добавить sequence number management в Phase 2 */
    hdr.frag_id = 0;
    hdr.total_frags = 0;
    hdr.payload_len = (uint16_t)payload_len;
    
    /* Устанавливаем timestamp */
    now = time(NULL);
    if (now == (time_t)-1) {
        OP_LOG_WARN("time() failed: %s", strerror(errno));
        hdr.timestamp = 0;
    } else {
        hdr.timestamp = (uint32_t)now;
    }

    hdr.crc32 = 0;  /* CRC будет вычислен в op_serialize() */

    /* Отправляем пакет через выбранный транспорт */
    ssize_t result;
    if (proto == OP_PROTO_TCP) {
        result = op_tcp_send(fd, &hdr, payload_data);
    } else if (proto == OP_PROTO_UDP) {
        /* Проверяем флаг надёжности */
        if (flags & OP_FLAG_RELIABLE) {
            /* TODO: Использовать reliable transport для надёжной передачи */
            OP_LOG_WARN("Reliable UDP not yet fully integrated, using basic UDP");
        }
        
        /* Проверяем, нужна ли фрагментация */
        size_t packet_size = OP_HEADER_SIZE + payload_len + sizeof(uint32_t);
        if (packet_size > OP_FRAG_MTU_DEFAULT && (flags & OP_FLAG_FRAGMENT) == 0) {
            /* Автоматическая фрагментация для больших пакетов */
            /* TODO: Реализовать автоматическую фрагментацию */
            OP_LOG_WARN("Large packet (%zu bytes) without fragmentation flag", packet_size);
        }
        
        result = op_udp_send(fd, &hdr, payload_data, NULL, 0);
    } else {
        OP_LOG_ERROR("Unsupported protocol: %u", proto);
        errno = ENOTSUP;
        result = -1;
    }

    /* Освобождаем сжатые данные если были использованы */
    if (free_compressed && compressed_data != NULL) {
        free(compressed_data);
    }

    /* Освобождаем зашифрованные данные если были использованы */
    if (free_encrypted && encrypted_data != NULL) {
        free(encrypted_data);
    }

    return result;
}

/* Функция op_set_encryption_key реализована в src/optimize/crypto.c */

/* Функции op_udp_bind и op_udp_connect реализованы в src/transport/udp.c */

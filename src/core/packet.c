/**
 * @file packet.c
 * @brief Реализация сериализации/десериализации пакетов OverProto
 */

#include "packet.h"
#include "crc32.h"
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <time.h>
#include <stdlib.h>

int op_validate_header(const OverPacketHeader *hdr)
{
    if (hdr == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Проверка magic number (заголовок должен быть в host byte order) */
    if (hdr->magic != OP_MAGIC) {
        OP_LOG_WARN("Invalid magic: 0x%04X", hdr->magic);
        errno = EINVAL;
        return -1;
    }

    /* Проверка версии */
    if (hdr->version != OP_VERSION) {
        OP_LOG_WARN("Invalid version: %d", hdr->version);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

ssize_t op_serialize(const OverPacketHeader *hdr, const void *data,
                     uint8_t *buf, size_t buf_size)
{
    if (hdr == NULL || buf == NULL) {
        errno = EINVAL;
        return -1;
    }

    uint16_t payload_len = htons(hdr->payload_len);
    size_t total_size = OP_HEADER_SIZE + ntohs(payload_len) + sizeof(uint32_t);

    /* Проверка размера буфера */
    if (buf_size < total_size) {
        OP_LOG_ERROR("Buffer too small: %zu < %zu", buf_size, total_size);
        errno = EINVAL;
        return -1;
    }

    /* Проверка на переполнение payload_len */
    if (hdr->payload_len > 0 && data == NULL) {
        OP_LOG_ERROR("Payload data is NULL but payload_len > 0");
        errno = EINVAL;
        return -1;
    }

    uint8_t *ptr = buf;
    OpCrc32Ctx crc_ctx;
    uint32_t crc_value;

    /* Копируем заголовок с преобразованием в network byte order */
    OverPacketHeader hdr_net;
    memcpy(&hdr_net, hdr, sizeof(OverPacketHeader));
    
    /* Преобразуем multi-byte поля в network byte order */
    hdr_net.magic = htons(hdr->magic);
    hdr_net.stream_id = htonl(hdr->stream_id);
    hdr_net.seq = htonl(hdr->seq);
    hdr_net.frag_id = htons(hdr->frag_id);
    hdr_net.total_frags = htons(hdr->total_frags);
    hdr_net.payload_len = htons(hdr->payload_len);
    hdr_net.timestamp = htonl(hdr->timestamp);
    hdr_net.crc32 = 0;  /* CRC будет вычислен и записан позже */

    /* Инициализируем CRC32 */
    if (op_crc32_init(&crc_ctx) != 0) {
        return -1;
    }

    /* Копируем заголовок в буфер */
    memcpy(ptr, &hdr_net, OP_HEADER_SIZE);
    
    /* Обновляем CRC заголовком */
    if (op_crc32_update(&crc_ctx, ptr, OP_HEADER_SIZE) != 0) {
        return -1;
    }
    ptr += OP_HEADER_SIZE;

    /* Копируем payload если есть */
    if (hdr->payload_len > 0) {
        memcpy(ptr, data, hdr->payload_len);
        
        /* Обновляем CRC payload */
        if (op_crc32_update(&crc_ctx, ptr, hdr->payload_len) != 0) {
            return -1;
        }
        ptr += hdr->payload_len;
    }

    /* Вычисляем итоговый CRC32 */
    crc_value = op_crc32_final(&crc_ctx);
    
    /* Записываем CRC32 в конец */
    uint32_t crc_net = htonl(crc_value);
    memcpy(ptr, &crc_net, sizeof(uint32_t));

    return (ssize_t)total_size;
}

int op_deserialize(const uint8_t *buf, size_t len,
                   OverPacketHeader **hdr, void **data, size_t *data_len)
{
    if (buf == NULL || hdr == NULL || data == NULL || data_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Минимальный размер: заголовок + CRC32 */
    if (len < OP_HEADER_SIZE + sizeof(uint32_t)) {
        OP_LOG_ERROR("Buffer too small: %zu < %zu", len, OP_HEADER_SIZE + sizeof(uint32_t));
        errno = EINVAL;
        return -1;
    }

    /* Выделяем память для заголовка */
    *hdr = (OverPacketHeader *)malloc(sizeof(OverPacketHeader));
    if (*hdr == NULL) {
        OP_LOG_ERROR("Failed to allocate memory for header");
        errno = ENOMEM;
        return -1;
    }

    /* Копируем заголовок из буфера */
    memcpy(*hdr, buf, OP_HEADER_SIZE);

    /* Преобразуем multi-byte поля из network byte order */
    (*hdr)->magic = ntohs((*hdr)->magic);
    (*hdr)->stream_id = ntohl((*hdr)->stream_id);
    (*hdr)->seq = ntohl((*hdr)->seq);
    (*hdr)->frag_id = ntohs((*hdr)->frag_id);
    (*hdr)->total_frags = ntohs((*hdr)->total_frags);
    (*hdr)->payload_len = ntohs((*hdr)->payload_len);
    (*hdr)->timestamp = ntohl((*hdr)->timestamp);

    /* Проверяем заголовок (magic, version) */
    if (op_validate_header(*hdr) != 0) {
        free(*hdr);
        *hdr = NULL;
        return -1;
    }

    /* Читаем payload_len и проверяем размер буфера */
    uint16_t payload_len = (*hdr)->payload_len;
    size_t expected_size = OP_HEADER_SIZE + payload_len + sizeof(uint32_t);

    if (len < expected_size) {
        OP_LOG_ERROR("Buffer too small for payload: %zu < %zu", len, expected_size);
        free(*hdr);
        *hdr = NULL;
        errno = EINVAL;
        return -1;
    }

    /* Извлекаем CRC32 из буфера */
    uint32_t crc_received;
    const uint8_t *crc_ptr = buf + OP_HEADER_SIZE + payload_len;
    memcpy(&crc_received, crc_ptr, sizeof(uint32_t));
    crc_received = ntohl(crc_received);

    /* Вычисляем CRC32 для заголовка + payload */
    OpCrc32Ctx crc_ctx;
    if (op_crc32_init(&crc_ctx) != 0) {
        free(*hdr);
        *hdr = NULL;
        return -1;
    }

    /* Обновляем CRC заголовком */
    if (op_crc32_update(&crc_ctx, buf, OP_HEADER_SIZE) != 0) {
        free(*hdr);
        *hdr = NULL;
        return -1;
    }

    /* Обновляем CRC payload если есть */
    if (payload_len > 0) {
        if (op_crc32_update(&crc_ctx, buf + OP_HEADER_SIZE, payload_len) != 0) {
            free(*hdr);
            *hdr = NULL;
            return -1;
        }
    }

    uint32_t crc_computed = op_crc32_final(&crc_ctx);

    /* Проверяем CRC32 */
    if (crc_computed != crc_received) {
        OP_LOG_ERROR("CRC32 mismatch: computed=0x%08X, received=0x%08X",
                     crc_computed, crc_received);
        free(*hdr);
        *hdr = NULL;
        errno = EINVAL;
        return -1;
    }

    /* Сохраняем CRC32 в заголовке (в host byte order) */
    (*hdr)->crc32 = crc_received;

    /* Выделяем память для payload и копируем его */
    *data_len = payload_len;
    if (payload_len > 0) {
        *data = malloc(payload_len);
        if (*data == NULL) {
            OP_LOG_ERROR("Failed to allocate memory for payload");
            free(*hdr);
            *hdr = NULL;
            errno = ENOMEM;
            return -1;
        }
        memcpy(*data, buf + OP_HEADER_SIZE, payload_len);
    } else {
        *data = NULL;
    }

    return 0;
}

int op_process_payload_flags(const OverPacketHeader *hdr, void **data, size_t *data_len)
{
    void *processed_data = NULL;
    size_t processed_len = 0;

    if (hdr == NULL || data == NULL || data_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (*data == NULL || *data_len == 0) {
        /* Нет данных для обработки */
        return 0;
    }

    processed_data = *data;
    processed_len = *data_len;

    /* Обработка флагов в обратном порядке по сравнению с отправкой */
    /* При отправке: компрессия -> шифрование */
    /* При приёме: дешифрование -> декомпрессия */

    /* Обработка флага шифрования (первым, т.к. шифрование последнее при отправке) */
    /* TODO: Добавить реальную обработку декрипции через op_decrypt() */
    /* Декрипция обрабатывается на уровне API для избежания циклических зависимостей */
    if (hdr->flags & OP_FLAG_ENCRYPTED) {
        OP_LOG_DEBUG("Encrypted packet flag detected, decryption handled at API level");
        /* В будущем: вызов op_decrypt() здесь или в API слое */
    }

    /* Обработка флага компрессии (вторым, т.к. компрессия первая при отправке) */
    /* TODO: Добавить реальную обработку декомпрессии через op_decompress() */
    /* Декомпрессия обрабатывается на уровне API для избежания циклических зависимостей */
    if (hdr->flags & OP_FLAG_COMPRESSED) {
        OP_LOG_DEBUG("Compressed packet flag detected, decompression handled at API level");
        /* В будущем: вызов op_decompress() здесь или в API слое */
    }

    /* Обновляем указатели */
    *data = processed_data;
    *data_len = processed_len;

    return 0;
}

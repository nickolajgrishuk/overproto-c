/**
 * @file packet.h
 * @brief Структура пакета OverProto и сериализация/десериализация
 */

#ifndef OVERPROTO_PACKET_H
#define OVERPROTO_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "common.h"

#pragma pack(push, 1)
/**
 * @brief Заголовок пакета OverProto (24 байта)
 * 
 * Структура пакета:
 * [Header 24 bytes] [Payload N bytes] [CRC32 4 bytes]
 */
typedef struct {
    uint16_t magic;           /* 0xABCD - уникальная сигнатура */
    uint8_t  version;         /* 0x01 */
    uint8_t  flags;           /* FRAG|COMP|ENC|RELIABLE|ACK */
    uint8_t  opcode;          /* Тип операции */
    uint8_t  proto;           /* OverProto enum */
    uint32_t stream_id;       /* Мультиплексирование */
    uint32_t seq;             /* Порядковый номер */
    uint16_t frag_id;         /* ID фрагмента */
    uint16_t total_frags;     /* Всего фрагментов */
    uint16_t payload_len;     /* Длина данных */
    uint32_t timestamp;       /* Unix timestamp */
    uint32_t crc32;           /* В конце после payload */
} OverPacketHeader;
#pragma pack(pop)

/**
 * @brief Валидация заголовка пакета
 * @param hdr Указатель на заголовок пакета
 * @return 0 при успехе, -1 при ошибке (проверка magic, version)
 * @note Thread-safe: yes
 */
int op_validate_header(const OverPacketHeader *hdr);

/**
 * @brief Сериализация пакета в буфер (network byte order)
 * @param hdr Указатель на заголовок пакета (host byte order)
 * @param data Указатель на payload (может быть NULL если payload_len == 0)
 * @param buf Буфер для сериализованных данных (должен быть достаточно большим)
 * @param buf_size Размер буфера
 * @return Количество записанных байт при успехе, -1 при ошибке
 * @note Thread-safe: yes (если buf не разделяется между потоками)
 * 
 * Формат: [Header 24 bytes] [Payload N bytes] [CRC32 4 bytes]
 * CRC32 вычисляется для (Header + Payload), но записывается в конец
 */
ssize_t op_serialize(const OverPacketHeader *hdr, const void *data,
                     uint8_t *buf, size_t buf_size);

/**
 * @brief Десериализация пакета из буфера
 * @param buf Указатель на буфер с данными
 * @param len Длина буфера
 * @param hdr Указатель на указатель для заголовка (выделяется через malloc)
 * @param data Указатель на указатель для payload (выделяется через malloc, может быть NULL)
 * @param data_len Указатель на длину payload
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * @warning Вызывающий должен освободить память через free() для *hdr и *data
 * 
 * Формат: [Header 24 bytes] [Payload N bytes] [CRC32 4 bytes]
 * Проверяет magic, version и CRC32
 */
int op_deserialize(const uint8_t *buf, size_t len,
                   OverPacketHeader **hdr, void **data, size_t *data_len);

/**
 * @brief Обработка флагов payload после десериализации (декомпрессия и т.д.)
 * @param hdr Указатель на заголовок пакета
 * @param data Указатель на указатель payload (может быть изменён)
 * @param data_len Указатель на длину payload (может быть изменён)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * @warning Может изменить *data и *data_len (например, при декомпрессии)
 * 
 * Обрабатывает флаги пакета:
 * - OP_FLAG_COMPRESSED: распаковывает данные через zlib
 * - Другие флаги обрабатываются отдельно
 */
int op_process_payload_flags(const OverPacketHeader *hdr, void **data, size_t *data_len);

#endif /* OVERPROTO_PACKET_H */


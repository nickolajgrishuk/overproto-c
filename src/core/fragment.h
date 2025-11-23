/**
 * @file fragment.h
 * @brief Фрагментация и сборка пакетов OverProto
 * 
 * Фрагментация больших пакетов на части размером <= MTU для передачи по UDP.
 * Максимум 256 фрагментов на пакет, timeout сборки 30 секунд.
 */

#ifndef OVERPROTO_FRAGMENT_H
#define OVERPROTO_FRAGMENT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "common.h"
#include "packet.h"

/* Константы фрагментации */
#define OP_FRAG_MAX_FRAGMENTS    256
#define OP_FRAG_TIMEOUT_SEC      30
/* OP_FRAG_MTU_DEFAULT определена в common.h */

/**
 * @brief Контекст сборки фрагментов
 */
typedef struct {
    uint32_t stream_id;          /* ID потока для идентификации сессии */
    uint32_t seq;                /* Sequence number оригинального пакета */
    uint16_t total_frags;        /* Всего фрагментов */
    uint16_t received_frags;     /* Количество полученных фрагментов */
    uint8_t *fragments[OP_FRAG_MAX_FRAGMENTS];  /* Буферы для каждого фрагмента */
    uint16_t frag_sizes[OP_FRAG_MAX_FRAGMENTS]; /* Размеры фрагментов */
    time_t created_at;           /* Время создания (для timeout) */
    OverPacketHeader *header;    /* Заголовок оригинального пакета */
    size_t total_payload_size;   /* Общий размер payload */
    size_t received_payload_size;/* Полученный размер payload */
} OpFragmentCtx;

/**
 * @brief Фрагментировать пакет на части
 * @param hdr Указатель на заголовок пакета
 * @param data Указатель на payload
 * @param mtu MTU (максимальный размер пакета, по умолчанию 1400)
 * @param fragments Массив указателей на буферы фрагментов (выделяются через malloc)
 * @param frag_headers Массив заголовков для каждого фрагмента
 * @param frag_count Указатель на количество созданных фрагментов
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes (если fragments не разделяются между потоками)
 * @warning Вызывающий должен освободить память через free() для каждого фрагмента
 */
int op_fragment_packet(const OverPacketHeader *hdr, const void *data,
                       size_t mtu, uint8_t **fragments,
                       OverPacketHeader *frag_headers, uint16_t *frag_count);

/**
 * @brief Инициализация контекста сборки фрагментов
 * @param ctx Указатель на контекст
 * @param stream_id ID потока
 * @param seq Sequence number пакета
 * @param total_frags Количество фрагментов
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: no (ctx должен использоваться из одного потока)
 */
int op_fragment_ctx_init(OpFragmentCtx *ctx, uint32_t stream_id,
                         uint32_t seq, uint16_t total_frags);

/**
 * @brief Добавить фрагмент в контекст сборки
 * @param ctx Указатель на контекст сборки
 * @param frag_id ID фрагмента (0-based)
 * @param hdr Указатель на заголовок фрагмента
 * @param data Указатель на payload фрагмента
 * @param data_len Длина payload фрагмента
 * @return 0 при успехе, -1 при ошибке, 1 если все фрагменты собраны
 * @note Thread-safe: no (ctx должен использоваться из одного потока)
 * 
 * Проверяет, все ли фрагменты собраны. Если да, возвращает 1.
 */
int op_fragment_add(OpFragmentCtx *ctx, uint16_t frag_id,
                    const OverPacketHeader *hdr, const void *data,
                    size_t data_len);

/**
 * @brief Собрать полный пакет из фрагментов
 * @param ctx Указатель на контекст сборки
 * @param hdr Указатель на указатель для заголовка (выделяется через malloc)
 * @param data Указатель на указатель для payload (выделяется через malloc)
 * @param data_len Указатель на длину payload
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: no (ctx должен использоваться из одного потока)
 * @warning Вызывающий должен освободить память через free() для *hdr и *data
 * 
 * Собирает все фрагменты в один пакет. Контекст должен содержать все фрагменты.
 */
int op_fragment_assemble(OpFragmentCtx *ctx, OverPacketHeader **hdr,
                         void **data, size_t *data_len);

/**
 * @brief Проверка timeout сборки фрагментов
 * @param ctx Указатель на контекст сборки
 * @return 1 если timeout истёк, 0 если ещё валиден
 * @note Thread-safe: yes
 */
int op_fragment_is_timeout(const OpFragmentCtx *ctx);

/**
 * @brief Очистка контекста сборки фрагментов
 * @param ctx Указатель на контекст
 * @note Thread-safe: no (ctx должен использоваться из одного потока)
 * 
 * Освобождает все выделенные буферы и очищает контекст.
 */
void op_fragment_ctx_cleanup(OpFragmentCtx *ctx);

#endif /* OVERPROTO_FRAGMENT_H */


/**
 * @file fragment.c
 * @brief Реализация фрагментации и сборки пакетов OverProto
 * 
 * Алгоритм фрагментации:
 * 1. Разбиение payload на части размером <= (MTU - header_size - CRC32_size)
 * 2. Создание отдельного заголовка для каждого фрагмента с установкой OP_FLAG_FRAGMENT
 * 3. Каждый фрагмент содержит frag_id и total_frags
 * 
 * Алгоритм сборки:
 * 1. Буферизация фрагментов по frag_id
 * 2. Проверка наличия всех фрагментов
 * 3. Склейка payload в правильном порядке
 * 4. Проверка timeout (30 секунд)
 */

#include "fragment.h"
#include "crc32.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

int op_fragment_packet(const OverPacketHeader *hdr, const void *data,
                       size_t mtu, uint8_t **fragments,
                       OverPacketHeader *frag_headers, uint16_t *frag_count)
{
    size_t payload_size;
    size_t max_frag_payload;
    size_t frag_payload_size;
    uint16_t total_frags;
    uint16_t i;
    uint8_t *frag_buf = NULL;
    size_t frag_buf_size;
    const uint8_t *payload_ptr;

    if (hdr == NULL || fragments == NULL || frag_headers == NULL || frag_count == NULL) {
        errno = EINVAL;
        return -1;
    }

    payload_size = hdr->payload_len;

    /* Если payload помещается в один пакет, фрагментация не нужна */
    if (payload_size == 0) {
        *frag_count = 0;
        return 0;
    }

    /* Вычисляем максимальный размер payload для одного фрагмента */
    /* MTU - заголовок (24) - CRC32 (4) = доступное место для payload */
    if (mtu < OP_HEADER_SIZE + sizeof(uint32_t) + 1) {
        OP_LOG_ERROR("MTU too small: %zu (minimum %zu)",
                     mtu, OP_HEADER_SIZE + sizeof(uint32_t) + 1);
        errno = EINVAL;
        return -1;
    }

    max_frag_payload = mtu - OP_HEADER_SIZE - sizeof(uint32_t);

    /* Вычисляем количество фрагментов */
    total_frags = (uint16_t)((payload_size + max_frag_payload - 1) / max_frag_payload);

    if (total_frags > OP_FRAG_MAX_FRAGMENTS) {
        OP_LOG_ERROR("Too many fragments: %u > %d", total_frags, OP_FRAG_MAX_FRAGMENTS);
        errno = EINVAL;
        return -1;
    }

    if (total_frags <= 1) {
        /* Фрагментация не нужна */
        *frag_count = 0;
        return 0;
    }

    /* Инициализируем массивы */
    memset(fragments, 0, sizeof(uint8_t *) * total_frags);
    memset(frag_headers, 0, sizeof(OverPacketHeader) * total_frags);

    payload_ptr = (const uint8_t *)data;
    size_t remaining = payload_size;

    /* Создаём каждый фрагмент */
    for (i = 0; i < total_frags; i++) {
        /* Вычисляем размер payload для этого фрагмента */
        frag_payload_size = (remaining > max_frag_payload) ? max_frag_payload : remaining;

        /* Вычисляем размер буфера для фрагмента */
        frag_buf_size = OP_HEADER_SIZE + frag_payload_size + sizeof(uint32_t);

        /* Выделяем буфер для фрагмента */
        frag_buf = (uint8_t *)malloc(frag_buf_size);
        if (frag_buf == NULL) {
            OP_LOG_ERROR("Failed to allocate memory for fragment %u", i);
            /* Освобождаем уже выделенные буферы */
            for (uint16_t j = 0; j < i; j++) {
                if (fragments[j] != NULL) {
                    free(fragments[j]);
                    fragments[j] = NULL;
                }
            }
            errno = ENOMEM;
            return -1;
        }

        /* Копируем заголовок и модифицируем для фрагмента */
        memcpy(&frag_headers[i], hdr, sizeof(OverPacketHeader));
        frag_headers[i].flags |= OP_FLAG_FRAGMENT;
        frag_headers[i].frag_id = i;
        frag_headers[i].total_frags = total_frags;
        frag_headers[i].payload_len = (uint16_t)frag_payload_size;

        /* Сериализуем фрагмент */
        ssize_t serialized = op_serialize(&frag_headers[i], payload_ptr,
                                          frag_buf, frag_buf_size);
        if (serialized < 0) {
            OP_LOG_ERROR("Failed to serialize fragment %u", i);
            free(frag_buf);
            /* Освобождаем уже выделенные буферы */
            for (uint16_t j = 0; j < i; j++) {
                if (fragments[j] != NULL) {
                    free(fragments[j]);
                    fragments[j] = NULL;
                }
            }
            return -1;
        }

        fragments[i] = frag_buf;
        payload_ptr += frag_payload_size;
        remaining -= frag_payload_size;
    }

    *frag_count = total_frags;
    return 0;
}

int op_fragment_ctx_init(OpFragmentCtx *ctx, uint32_t stream_id,
                         uint32_t seq, uint16_t total_frags)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (total_frags == 0 || total_frags > OP_FRAG_MAX_FRAGMENTS) {
        OP_LOG_ERROR("Invalid total_frags: %u", total_frags);
        errno = EINVAL;
        return -1;
    }

    memset(ctx, 0, sizeof(OpFragmentCtx));
    ctx->stream_id = stream_id;
    ctx->seq = seq;
    ctx->total_frags = total_frags;
    ctx->received_frags = 0;
    ctx->created_at = time(NULL);
    if (ctx->created_at == (time_t)-1) {
        OP_LOG_WARN("time() failed: %s", strerror(errno));
        ctx->created_at = 0;
    }

    /* Выделяем память для заголовка */
    ctx->header = (OverPacketHeader *)malloc(sizeof(OverPacketHeader));
    if (ctx->header == NULL) {
        OP_LOG_ERROR("Failed to allocate memory for fragment header");
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

int op_fragment_add(OpFragmentCtx *ctx, uint16_t frag_id,
                    const OverPacketHeader *hdr, const void *data,
                    size_t data_len)
{
    uint8_t *frag_buf = NULL;

    if (ctx == NULL || hdr == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Проверка диапазона frag_id */
    if (frag_id >= ctx->total_frags) {
        OP_LOG_ERROR("Invalid frag_id: %u >= %u", frag_id, ctx->total_frags);
        errno = EINVAL;
        return -1;
    }

    /* Проверка, не добавлен ли уже этот фрагмент */
    if (ctx->fragments[frag_id] != NULL) {
        OP_LOG_WARN("Fragment %u already added", frag_id);
        return 0;  /* Уже добавлен, считаем успехом */
    }

    /* Сохраняем заголовок из первого фрагмента */
    if (ctx->received_frags == 0 && frag_id == 0) {
        memcpy(ctx->header, hdr, sizeof(OverPacketHeader));
        ctx->header->flags &= ~OP_FLAG_FRAGMENT;  /* Убираем флаг фрагмента */
        ctx->header->frag_id = 0;
        ctx->header->total_frags = 0;
    }

    /* Выделяем память для фрагмента */
    frag_buf = (uint8_t *)malloc(data_len);
    if (frag_buf == NULL) {
        OP_LOG_ERROR("Failed to allocate memory for fragment %u", frag_id);
        errno = ENOMEM;
        return -1;
    }

    /* Копируем данные фрагмента */
    if (data != NULL && data_len > 0) {
        memcpy(frag_buf, data, data_len);
    }

    ctx->fragments[frag_id] = frag_buf;
    ctx->frag_sizes[frag_id] = (uint16_t)data_len;
    ctx->received_payload_size += data_len;
    ctx->received_frags++;

    /* Проверяем, собраны ли все фрагменты */
    if (ctx->received_frags >= ctx->total_frags) {
        return 1;  /* Все фрагменты собраны */
    }

    return 0;
}

int op_fragment_assemble(OpFragmentCtx *ctx, OverPacketHeader **hdr,
                         void **data, size_t *data_len)
{
    uint8_t *assembled_payload = NULL;
    size_t offset = 0;
    uint16_t i;

    if (ctx == NULL || hdr == NULL || data == NULL || data_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Проверяем, что все фрагменты собраны */
    if (ctx->received_frags < ctx->total_frags) {
        OP_LOG_ERROR("Not all fragments received: %u/%u",
                     ctx->received_frags, ctx->total_frags);
        errno = EINVAL;
        return -1;
    }

    /* Выделяем память для заголовка */
    *hdr = (OverPacketHeader *)malloc(sizeof(OverPacketHeader));
    if (*hdr == NULL) {
        OP_LOG_ERROR("Failed to allocate memory for assembled header");
        errno = ENOMEM;
        return -1;
    }

    /* Копируем заголовок */
    memcpy(*hdr, ctx->header, sizeof(OverPacketHeader));
    (*hdr)->payload_len = (uint16_t)ctx->received_payload_size;

    /* Выделяем память для собранного payload */
    if (ctx->received_payload_size > 0) {
        assembled_payload = (uint8_t *)malloc(ctx->received_payload_size);
        if (assembled_payload == NULL) {
            OP_LOG_ERROR("Failed to allocate memory for assembled payload");
            free(*hdr);
            *hdr = NULL;
            errno = ENOMEM;
            return -1;
        }

        /* Склеиваем фрагменты в правильном порядке */
        for (i = 0; i < ctx->total_frags; i++) {
            if (ctx->fragments[i] != NULL && ctx->frag_sizes[i] > 0) {
                memcpy(assembled_payload + offset, ctx->fragments[i], ctx->frag_sizes[i]);
                offset += ctx->frag_sizes[i];
            }
        }
    }

    *data = assembled_payload;
    *data_len = ctx->received_payload_size;

    return 0;
}

int op_fragment_is_timeout(const OpFragmentCtx *ctx)
{
    time_t now;
    time_t elapsed;

    if (ctx == NULL) {
        return 1;  /* Считаем timeout для NULL */
    }

    if (ctx->created_at == 0) {
        return 0;  /* Если время не установлено, timeout не проверяем */
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        return 0;  /* Ошибка получения времени, не считаем timeout */
    }

    elapsed = now - ctx->created_at;
    if (elapsed < 0) {
        return 0;  /* Отрицательное время, не считаем timeout */
    }

    return (elapsed >= OP_FRAG_TIMEOUT_SEC) ? 1 : 0;
}

void op_fragment_ctx_cleanup(OpFragmentCtx *ctx)
{
    uint16_t i;

    if (ctx == NULL) {
        return;
    }

    /* Освобождаем фрагменты */
    for (i = 0; i < OP_FRAG_MAX_FRAGMENTS; i++) {
        if (ctx->fragments[i] != NULL) {
            free(ctx->fragments[i]);
            ctx->fragments[i] = NULL;
        }
    }

    /* Освобождаем заголовок */
    if (ctx->header != NULL) {
        free(ctx->header);
        ctx->header = NULL;
    }

    /* Очищаем контекст */
    memset(ctx, 0, sizeof(OpFragmentCtx));
}


/**
 * @file crc32.c
 * @brief Реализация CRC32 с таблицей lookup (IEEE 802.3)
 * 
 * Алгоритм: CRC32 IEEE 802.3 (Ethernet)
 * Полином: 0x04C11DB7 (normal) = 0xEDB88320 (reversed)
 * Начальное значение: 0xFFFFFFFF
 * Final XOR: 0xFFFFFFFF
 */

#include "crc32.h"
#include "common.h"
#include <string.h>

/* Таблица lookup для CRC32 (256 элементов) */
static uint32_t crc32_table[256];
static int crc32_table_initialized = 0;

/**
 * @brief Инициализация таблицы lookup для CRC32
 * 
 * Генерирует таблицу для быстрого вычисления CRC32
 * Полином: 0xEDB88320 (reversed CRC32-IEEE 802.3)
 */
static void crc32_table_init(void)
{
    uint32_t polynomial = 0xEDB88320UL;
    uint32_t crc;
    int i, j;

    for (i = 0; i < 256; i++) {
        crc = i;
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ polynomial;
            } else {
                crc >>= 1;
            }
        }
        crc32_table[i] = crc;
    }
    crc32_table_initialized = 1;
}

int op_crc32_init(OpCrc32Ctx *ctx)
{
    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (!crc32_table_initialized) {
        crc32_table_init();
    }

    ctx->crc = 0xFFFFFFFFUL;
    return 0;
}

int op_crc32_update(OpCrc32Ctx *ctx, const void *data, size_t len)
{
    if (ctx == NULL || data == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (!crc32_table_initialized) {
        crc32_table_init();
    }

    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = ctx->crc;
    size_t i;

    for (i = 0; i < len; i++) {
        uint8_t idx = (uint8_t)(crc ^ bytes[i]);
        crc = (crc >> 8) ^ crc32_table[idx];
    }

    ctx->crc = crc;
    return 0;
}

uint32_t op_crc32_final(OpCrc32Ctx *ctx)
{
    if (ctx == NULL) {
        return 0;
    }

    /* Final XOR с 0xFFFFFFFF для IEEE 802.3 */
    return ctx->crc ^ 0xFFFFFFFFUL;
}

uint32_t op_crc32_compute(const void *data, size_t len)
{
    OpCrc32Ctx ctx;
    uint32_t result;

    if (data == NULL || len == 0) {
        return 0;
    }

    if (op_crc32_init(&ctx) != 0) {
        return 0;
    }

    if (op_crc32_update(&ctx, data, len) != 0) {
        return 0;
    }

    result = op_crc32_final(&ctx);
    return result;
}


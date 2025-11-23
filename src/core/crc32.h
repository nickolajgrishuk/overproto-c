/**
 * @file crc32.h
 * @brief CRC32 вычисление с таблицей lookup (IEEE 802.3)
 */

#ifndef OVERPROTO_CRC32_H
#define OVERPROTO_CRC32_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Контекст CRC32 для инкрементального вычисления
 */
typedef struct {
    uint32_t crc;
} OpCrc32Ctx;

/**
 * @brief Инициализация контекста CRC32
 * @param ctx Указатель на контекст CRC32
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes (если ctx не разделяется между потоками)
 */
int op_crc32_init(OpCrc32Ctx *ctx);

/**
 * @brief Обновление CRC32 новыми данными
 * @param ctx Указатель на контекст CRC32
 * @param data Указатель на данные для обработки
 * @param len Длина данных в байтах
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: no (ctx должен использоваться из одного потока)
 */
int op_crc32_update(OpCrc32Ctx *ctx, const void *data, size_t len);

/**
 * @brief Финализация CRC32 (возвращает итоговое значение)
 * @param ctx Указатель на контекст CRC32
 * @return Итоговое значение CRC32
 * @note Thread-safe: no (ctx должен использоваться из одного потока)
 */
uint32_t op_crc32_final(OpCrc32Ctx *ctx);

/**
 * @brief Вычисление CRC32 для блока данных (удобная функция-обёртка)
 * @param data Указатель на данные
 * @param len Длина данных в байтах
 * @return Значение CRC32
 * @note Thread-safe: yes
 */
uint32_t op_crc32_compute(const void *data, size_t len);

#endif /* OVERPROTO_CRC32_H */


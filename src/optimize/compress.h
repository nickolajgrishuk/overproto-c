/**
 * @file compress.h
 * @brief Компрессия данных через zlib для OverProto
 * 
 * Автоматическая компрессия payload пакетов если размер >= порога (512 байт).
 * Использует zlib deflate/inflate для сжатия данных.
 * Флаг OP_FLAG_COMPRESSED устанавливается в заголовке пакета.
 */

#ifndef OVERPROTO_COMPRESS_H
#define OVERPROTO_COMPRESS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "../core/common.h"

/* Константы компрессии */
#define OP_COMPRESS_THRESHOLD    512  /* Порог для компрессии (байт) */
#define OP_COMPRESS_LEVEL        6    /* Уровень компрессии zlib (1-9, 6 = баланс) */

/**
 * @brief Сжатие данных через zlib
 * @param input Указатель на исходные данные
 * @param input_len Длина исходных данных
 * @param output Указатель на буфер для сжатых данных (выделяется через malloc)
 * @param output_len Указатель на длину сжатых данных
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * @warning Вызывающий должен освободить память через free() для *output
 * 
 * Использует zlib deflate для сжатия данных.
 * Если сжатие неэффективно (размер увеличился), возвращает ошибку.
 */
int op_compress(const void *input, size_t input_len,
                void **output, size_t *output_len);

/**
 * @brief Распаковка данных через zlib
 * @param input Указатель на сжатые данные
 * @param input_len Длина сжатых данных
 * @param output Указатель на буфер для распакованных данных (выделяется через malloc)
 * @param output_len Указатель на длину распакованных данных
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * @warning Вызывающий должен освободить память через free() для *output
 * 
 * Использует zlib inflate для распаковки данных.
 * Автоматически определяет размер буфера из заголовка zlib.
 */
int op_decompress(const void *input, size_t input_len,
                  void **output, size_t *output_len);

/**
 * @brief Проверить, нужна ли компрессия для данных указанного размера
 * @param size Размер данных в байтах
 * @return 1 если нужна компрессия, 0 если не нужна
 * @note Thread-safe: yes
 * 
 * Проверяет, превышает ли размер порог компрессии.
 */
static inline int op_should_compress(size_t size)
{
    return (size >= OP_COMPRESS_THRESHOLD) ? 1 : 0;
}

/**
 * @brief Установить порог компрессии
 * @param threshold Новый порог в байтах (0 = отключить компрессию)
 * @note Thread-safe: yes
 * 
 * Изменяет порог, при превышении которого данные будут сжиматься.
 */
void op_set_compress_threshold(size_t threshold);

/**
 * @brief Получить текущий порог компрессии
 * @return Текущий порог в байтах
 * @note Thread-safe: yes
 */
size_t op_get_compress_threshold(void);

#endif /* OVERPROTO_COMPRESS_H */


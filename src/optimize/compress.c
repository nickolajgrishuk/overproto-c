/**
 * @file compress.c
 * @brief Реализация компрессии данных через zlib для OverProto
 * 
 * Использует zlib deflate/inflate для сжатия/распаковки данных.
 * Компрессия применяется автоматически если размер >= порога (512 байт).
 * Если сжатие неэффективно (размер увеличился), компрессия не применяется.
 */

#include "compress.h"
#include "../core/common.h"
#include <string.h>
#include <stdlib.h>
#include <zlib.h>
#include <pthread.h>

/* Глобальный порог компрессии */
static size_t g_compress_threshold = OP_COMPRESS_THRESHOLD;
static pthread_mutex_t g_threshold_mutex = PTHREAD_MUTEX_INITIALIZER;

int op_compress(const void *input, size_t input_len,
                void **output, size_t *output_len)
{
    z_stream strm;
    uint8_t *compressed = NULL;
    size_t compressed_size;
    int zlib_ret;

    if (input == NULL || output == NULL || output_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (input_len == 0) {
        *output = NULL;
        *output_len = 0;
        return 0;
    }

    /* Инициализируем структуру zlib */
    memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    /* Инициализация deflate с уровнем компрессии */
    zlib_ret = deflateInit(&strm, OP_COMPRESS_LEVEL);
    if (zlib_ret != Z_OK) {
        OP_LOG_ERROR("deflateInit failed: %s", zError(zlib_ret));
        errno = EINVAL;
        return -1;
    }

    /* Вычисляем максимальный размер сжатых данных */
    /* zlib гарантирует, что сжатые данные не превысят sourceLen + 0.1% + 12 байт */
    compressed_size = input_len + (input_len / 1000) + 12;
    
    /* Выделяем буфер для сжатых данных */
    compressed = (uint8_t *)malloc(compressed_size);
    if (compressed == NULL) {
        deflateEnd(&strm);
        OP_LOG_ERROR("Failed to allocate memory for compressed data");
        errno = ENOMEM;
        return -1;
    }

    /* Настраиваем входные/выходные буферы */
    strm.next_in = (z_const Bytef *)input;
    strm.avail_in = (uInt)input_len;
    strm.next_out = compressed;
    strm.avail_out = (uInt)compressed_size;

    /* Сжимаем данные */
    zlib_ret = deflate(&strm, Z_FINISH);
    
    if (zlib_ret != Z_STREAM_END) {
        OP_LOG_ERROR("deflate failed: %s", zError(zlib_ret));
        free(compressed);
        deflateEnd(&strm);
        errno = EINVAL;
        return -1;
    }

    /* Вычисляем фактический размер сжатых данных */
    compressed_size = (size_t)strm.total_out;

    /* Завершаем сжатие */
    deflateEnd(&strm);

    /* Проверяем, что сжатие было эффективным */
    if (compressed_size >= input_len) {
        /* Сжатие неэффективно - не применяем */
        OP_LOG_DEBUG("Compression not effective: %zu >= %zu", compressed_size, input_len);
        free(compressed);
        errno = EAGAIN;  /* Специальный код для "сжатие не нужно" */
        return -1;
    }

    /* Если размер уменьшился, уменьшаем буфер до фактического размера */
    if (compressed_size < (input_len + (input_len / 1000) + 12)) {
        uint8_t *resized = (uint8_t *)realloc(compressed, compressed_size);
        if (resized != NULL) {
            compressed = resized;
        }
    }

    *output = compressed;
    *output_len = compressed_size;

    OP_LOG_DEBUG("Compressed %zu bytes to %zu bytes (ratio: %.2f%%)",
                 input_len, compressed_size,
                 (double)compressed_size * 100.0 / (double)input_len);

    return 0;
}

int op_decompress(const void *input, size_t input_len,
                  void **output, size_t *output_len)
{
    z_stream strm;
    uint8_t *decompressed = NULL;
    size_t decompressed_size;
    size_t buffer_size;
    int zlib_ret;

    if (input == NULL || output == NULL || output_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (input_len == 0) {
        *output = NULL;
        *output_len = 0;
        return 0;
    }

    /* Инициализируем структуру zlib */
    memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    /* Инициализация inflate */
    zlib_ret = inflateInit(&strm);
    if (zlib_ret != Z_OK) {
        OP_LOG_ERROR("inflateInit failed: %s", zError(zlib_ret));
        errno = EINVAL;
        return -1;
    }

    /* Начальный размер буфера (предполагаем, что распакованные данные
       примерно в 2-3 раза больше сжатых) */
    buffer_size = input_len * 3;
    decompressed_size = 0;

    /* Выделяем начальный буфер */
    decompressed = (uint8_t *)malloc(buffer_size);
    if (decompressed == NULL) {
        inflateEnd(&strm);
        OP_LOG_ERROR("Failed to allocate memory for decompressed data");
        errno = ENOMEM;
        return -1;
    }

    /* Настраиваем входные/выходные буферы */
    strm.next_in = (z_const Bytef *)input;
    strm.avail_in = (uInt)input_len;
    strm.next_out = decompressed;
    strm.avail_out = (uInt)buffer_size;

    /* Распаковываем данные */
    do {
        zlib_ret = inflate(&strm, Z_NO_FLUSH);
        
        if (zlib_ret == Z_OK) {
            /* Нужно больше места в выходном буфере */
            buffer_size *= 2;
            uint8_t *resized = (uint8_t *)realloc(decompressed, buffer_size);
            if (resized == NULL) {
                free(decompressed);
                inflateEnd(&strm);
                OP_LOG_ERROR("Failed to reallocate memory for decompressed data");
                errno = ENOMEM;
                return -1;
            }
            decompressed = resized;
            
            /* Обновляем указатель на выходной буфер */
            strm.next_out = decompressed + strm.total_out;
            strm.avail_out = (uInt)(buffer_size - strm.total_out);
        } else if (zlib_ret != Z_STREAM_END) {
            OP_LOG_ERROR("inflate failed: %s", zError(zlib_ret));
            free(decompressed);
            inflateEnd(&strm);
            errno = EINVAL;
            return -1;
        }
    } while (zlib_ret == Z_OK);

    /* Вычисляем фактический размер распакованных данных */
    decompressed_size = (size_t)strm.total_out;

    /* Завершаем распаковку */
    inflateEnd(&strm);

    /* Уменьшаем буфер до фактического размера */
    if (decompressed_size < buffer_size) {
        uint8_t *resized = (uint8_t *)realloc(decompressed, decompressed_size);
        if (resized != NULL) {
            decompressed = resized;
        }
    }

    *output = decompressed;
    *output_len = decompressed_size;

    OP_LOG_DEBUG("Decompressed %zu bytes to %zu bytes",
                 input_len, decompressed_size);

    return 0;
}

void op_set_compress_threshold(size_t threshold)
{
    pthread_mutex_lock(&g_threshold_mutex);
    g_compress_threshold = threshold;
    pthread_mutex_unlock(&g_threshold_mutex);
    
    OP_LOG_INFO("Compression threshold set to %zu bytes", threshold);
}

size_t op_get_compress_threshold(void)
{
    size_t threshold;
    
    pthread_mutex_lock(&g_threshold_mutex);
    threshold = g_compress_threshold;
    pthread_mutex_unlock(&g_threshold_mutex);
    
    return threshold;
}


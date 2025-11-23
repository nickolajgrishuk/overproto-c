/**
 * @file crypto.h
 * @brief Шифрование данных через AES-GCM для OverProto
 * 
 * Шифрование payload пакетов через AES-GCM (AES-256-GCM).
 * Использует OpenSSL EVP API для шифрования/дешифрования.
 * Флаг OP_FLAG_ENCRYPTED устанавливается в заголовке пакета.
 * 
 * AES-GCM обеспечивает:
 * - Конфиденциальность (AES-256)
 * - Аутентификацию (GCM tag)
 * - Защиту от подмены данных
 */

#ifndef OVERPROTO_CRYPTO_H
#define OVERPROTO_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "../core/common.h"

/* Константы криптографии */
#define OP_CRYPTO_KEY_SIZE      32  /* 256 бит для AES-256 */
#define OP_CRYPTO_IV_SIZE       12  /* 96 бит для GCM (стандарт) */
#define OP_CRYPTO_TAG_SIZE      16  /* 128 бит для GCM tag */
#define OP_CRYPTO_MAX_OVERHEAD  (OP_CRYPTO_IV_SIZE + OP_CRYPTO_TAG_SIZE)  /* IV + tag */

/**
 * @brief Установка ключа шифрования
 * @param key Указатель на ключ (32 байта для AES-256)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * 
 * Устанавливает глобальный ключ шифрования для всех последующих операций.
 * Ключ хранится в памяти, не должен быть доступен через небезопасные каналы.
 */
int op_set_encryption_key(const uint8_t key[OP_CRYPTO_KEY_SIZE]);

/**
 * @brief Шифрование данных через AES-GCM
 * @param input Указатель на исходные данные
 * @param input_len Длина исходных данных
 * @param output Указатель на буфер для зашифрованных данных (выделяется через malloc)
 * @param output_len Указатель на длину зашифрованных данных
 * @param iv Указатель на буфер для IV (12 байт, генерируется случайно)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * @warning Вызывающий должен освободить память через free() для *output
 * 
 * Шифрует данные через AES-256-GCM.
 * Формат выходных данных: [IV 12 bytes] [Encrypted data] [Tag 16 bytes]
 */
int op_encrypt(const void *input, size_t input_len,
               void **output, size_t *output_len, uint8_t iv[OP_CRYPTO_IV_SIZE]);

/**
 * @brief Расшифровка данных через AES-GCM
 * @param input Указатель на зашифрованные данные (IV + encrypted + tag)
 * @param input_len Длина зашифрованных данных (включая IV и tag)
 * @param output Указатель на буфер для расшифрованных данных (выделяется через malloc)
 * @param output_len Указатель на длину расшифрованных данных
 * @param iv Указатель на IV (12 байт, извлекается из входных данных)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * @warning Вызывающий должен освободить память через free() для *output
 * 
 * Расшифровывает данные через AES-256-GCM и проверяет аутентификационный tag.
 * Формат входных данных: [IV 12 bytes] [Encrypted data] [Tag 16 bytes]
 */
int op_decrypt(const void *input, size_t input_len,
               void **output, size_t *output_len, const uint8_t iv[OP_CRYPTO_IV_SIZE]);

/**
 * @brief Проверка, установлен ли ключ шифрования
 * @return 1 если ключ установлен, 0 если нет
 * @note Thread-safe: yes
 */
int op_is_encryption_enabled(void);

/**
 * @brief Очистка ключа шифрования из памяти
 * @note Thread-safe: yes
 * 
 * Стирает ключ из памяти (заполняет нулями) для безопасности.
 */
void op_clear_encryption_key(void);

#endif /* OVERPROTO_CRYPTO_H */


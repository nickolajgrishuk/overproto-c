/**
 * @file crypto.c
 * @brief Реализация шифрования данных через AES-GCM для OverProto
 * 
 * Использует OpenSSL EVP API для шифрования/дешифрования через AES-256-GCM.
 * AES-GCM предоставляет конфиденциальность и аутентификацию в одной операции.
 */

#include "crypto.h"
#include "../core/common.h"
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
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

#ifdef OVERPROTO_USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* Глобальный ключ шифрования */
static uint8_t g_encryption_key[OP_CRYPTO_KEY_SIZE] = {0};
static int g_key_set = 0;
static OP_MUTEX_TYPE g_key_mutex = OP_MUTEX_INITIALIZER;

int op_set_encryption_key(const uint8_t key[OP_CRYPTO_KEY_SIZE])
{
    if (key == NULL) {
        errno = EINVAL;
        return -1;
    }

    OP_MUTEX_LOCK(&g_key_mutex);
    memcpy(g_encryption_key, key, OP_CRYPTO_KEY_SIZE);
    g_key_set = 1;
    OP_MUTEX_UNLOCK(&g_key_mutex);

    OP_LOG_INFO("Encryption key set (AES-256-GCM)");
    return 0;
}

int op_encrypt(const void *input, size_t input_len,
               void **output, size_t *output_len, uint8_t iv[OP_CRYPTO_IV_SIZE])
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *encrypted = NULL;
    size_t encrypted_size;
    int out_len;
    int final_len;

    if (input == NULL || output == NULL || output_len == NULL || iv == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (input_len == 0) {
        *output = NULL;
        *output_len = 0;
        return 0;
    }

    OP_MUTEX_LOCK(&g_key_mutex);
    if (!g_key_set) {
        OP_MUTEX_UNLOCK(&g_key_mutex);
        OP_LOG_ERROR("Encryption key not set");
        errno = EINVAL;
        return -1;
    }

    /* Создаём контекст шифрования */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OP_MUTEX_UNLOCK(&g_key_mutex);
        OP_LOG_ERROR("Failed to create encryption context");
        errno = ENOMEM;
        return -1;
    }

    /* Генерируем случайный IV */
    if (RAND_bytes(iv, OP_CRYPTO_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OP_MUTEX_UNLOCK(&g_key_mutex);
        OP_LOG_ERROR("Failed to generate IV: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EAGAIN;
        return -1;
    }

    /* Инициализируем шифрование */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, g_encryption_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OP_MUTEX_UNLOCK(&g_key_mutex);
        OP_LOG_ERROR("Failed to initialize encryption: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EINVAL;
        return -1;
    }

    OP_MUTEX_UNLOCK(&g_key_mutex);

    /* Вычисляем размер выходного буфера */
    /* IV + encrypted data + tag */
    encrypted_size = OP_CRYPTO_IV_SIZE + input_len + OP_CRYPTO_TAG_SIZE;

    /* Выделяем буфер для зашифрованных данных */
    encrypted = (uint8_t *)malloc(encrypted_size);
    if (encrypted == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to allocate memory for encrypted data");
        errno = ENOMEM;
        return -1;
    }

    /* Копируем IV в начало буфера */
    memcpy(encrypted, iv, OP_CRYPTO_IV_SIZE);

    /* Шифруем данные */
    if (EVP_EncryptUpdate(ctx, encrypted + OP_CRYPTO_IV_SIZE, &out_len,
                          (const unsigned char *)input, (int)input_len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to encrypt data: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EINVAL;
        return -1;
    }

    /* Финализируем шифрование и получаем tag */
    if (EVP_EncryptFinal_ex(ctx, encrypted + OP_CRYPTO_IV_SIZE + out_len, &final_len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to finalize encryption: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EINVAL;
        return -1;
    }

    /* Получаем аутентификационный tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, OP_CRYPTO_TAG_SIZE,
                            encrypted + OP_CRYPTO_IV_SIZE + out_len + final_len) != 1) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to get GCM tag: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EINVAL;
        return -1;
    }

    /* Освобождаем контекст */
    EVP_CIPHER_CTX_free(ctx);

    /* Вычисляем фактический размер зашифрованных данных */
    *output_len = OP_CRYPTO_IV_SIZE + out_len + final_len + OP_CRYPTO_TAG_SIZE;
    *output = encrypted;

    OP_LOG_DEBUG("Encrypted %zu bytes to %zu bytes", input_len, *output_len);
    return 0;
}

int op_decrypt(const void *input, size_t input_len,
               void **output, size_t *output_len, const uint8_t iv[OP_CRYPTO_IV_SIZE])
{
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *decrypted = NULL;
    size_t decrypted_size;
    const uint8_t *encrypted_data;
    const uint8_t *tag;
    const uint8_t *input_iv;
    size_t encrypted_len;
    int out_len;
    int final_len;

    if (input == NULL || output == NULL || output_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (input_len == 0 || input_len < OP_CRYPTO_IV_SIZE + OP_CRYPTO_TAG_SIZE) {
        OP_LOG_ERROR("Invalid encrypted data size: %zu", input_len);
        errno = EINVAL;
        return -1;
    }

    /* Проверяем размер данных */
    encrypted_len = input_len - OP_CRYPTO_IV_SIZE - OP_CRYPTO_TAG_SIZE;

    /* Извлекаем компоненты из входных данных */
    /* Формат: [IV] [Encrypted data] [Tag] */
    input_iv = (const uint8_t *)input;  /* IV в начале */
    encrypted_data = (const uint8_t *)input + OP_CRYPTO_IV_SIZE;
    tag = (const uint8_t *)input + OP_CRYPTO_IV_SIZE + encrypted_len;

    /* Используем IV из входных данных, если не передан отдельно */
    const uint8_t *use_iv = (iv != NULL) ? iv : input_iv;

    OP_MUTEX_LOCK(&g_key_mutex);
    if (!g_key_set) {
        OP_MUTEX_UNLOCK(&g_key_mutex);
        OP_LOG_ERROR("Encryption key not set");
        errno = EINVAL;
        return -1;
    }

    /* Создаём контекст дешифрования */
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        OP_MUTEX_UNLOCK(&g_key_mutex);
        OP_LOG_ERROR("Failed to create decryption context");
        errno = ENOMEM;
        return -1;
    }

    /* Инициализируем дешифрование */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, g_encryption_key, use_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OP_MUTEX_UNLOCK(&g_key_mutex);
        OP_LOG_ERROR("Failed to initialize decryption: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EINVAL;
        return -1;
    }

    OP_MUTEX_UNLOCK(&g_key_mutex);

    /* Выделяем буфер для расшифрованных данных */
    decrypted_size = encrypted_len;  /* Примерный размер (может быть немного меньше) */
    decrypted = (uint8_t *)malloc(decrypted_size);
    if (decrypted == NULL) {
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to allocate memory for decrypted data");
        errno = ENOMEM;
        return -1;
    }

    /* Расшифровываем данные */
    if (EVP_DecryptUpdate(ctx, decrypted, &out_len,
                          encrypted_data, (int)encrypted_len) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to decrypt data: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EINVAL;
        return -1;
    }

    /* Устанавливаем ожидаемый tag для проверки */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, OP_CRYPTO_TAG_SIZE, (void *)tag) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to set GCM tag: %s", ERR_error_string(ERR_get_error(), NULL));
        errno = EINVAL;
        return -1;
    }

    /* Финализируем дешифрование и проверяем tag */
    if (EVP_DecryptFinal_ex(ctx, decrypted + out_len, &final_len) != 1) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        OP_LOG_ERROR("Failed to verify GCM tag - authentication failed");
        errno = EINVAL;
        return -1;
    }

    /* Освобождаем контекст */
    EVP_CIPHER_CTX_free(ctx);

    /* Вычисляем фактический размер расшифрованных данных */
    *output_len = out_len + final_len;
    *output = decrypted;

    OP_LOG_DEBUG("Decrypted %zu bytes to %zu bytes", input_len, *output_len);
    return 0;
}

int op_is_encryption_enabled(void)
{
    int enabled;

    OP_MUTEX_LOCK(&g_key_mutex);
    enabled = g_key_set;
    OP_MUTEX_UNLOCK(&g_key_mutex);

    return enabled;
}

void op_clear_encryption_key(void)
{
    OP_MUTEX_LOCK(&g_key_mutex);
    memset(g_encryption_key, 0, OP_CRYPTO_KEY_SIZE);
    g_key_set = 0;
    OP_MUTEX_UNLOCK(&g_key_mutex);

    OP_LOG_INFO("Encryption key cleared");
}

#else /* OVERPROTO_USE_OPENSSL */

/* Заглушки для случая без OpenSSL */

int op_set_encryption_key(const uint8_t key[OP_CRYPTO_KEY_SIZE])
{
    (void)key;
    OP_LOG_ERROR("Encryption not supported - OpenSSL not compiled");
    errno = ENOTSUP;
    return -1;
}

int op_encrypt(const void *input, size_t input_len,
               void **output, size_t *output_len, uint8_t iv[OP_CRYPTO_IV_SIZE])
{
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_len;
    (void)iv;
    OP_LOG_ERROR("Encryption not supported - OpenSSL not compiled");
    errno = ENOTSUP;
    return -1;
}

int op_decrypt(const void *input, size_t input_len,
               void **output, size_t *output_len, const uint8_t iv[OP_CRYPTO_IV_SIZE])
{
    (void)input;
    (void)input_len;
    (void)output;
    (void)output_len;
    (void)iv;
    OP_LOG_ERROR("Decryption not supported - OpenSSL not compiled");
    errno = ENOTSUP;
    return -1;
}

int op_is_encryption_enabled(void)
{
    return 0;
}

void op_clear_encryption_key(void)
{
    /* Ничего не делаем */
}

#endif /* OVERPROTO_USE_OPENSSL */

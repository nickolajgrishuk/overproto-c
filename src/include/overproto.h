/**
 * @file overproto.h
 * @brief Публичный API библиотеки OverProto
 * 
 * Единая точка входа для использования протокола OverProto
 */

#ifndef OVERPROTO_H
#define OVERPROTO_H

#include <stdint.h>
#include <stddef.h>
#include "../core/common.h"
#include "../core/packet.h"
#include "../transport/tcp.h"
#include "../transport/udp.h"
#include "../optimize/crypto.h"

/**
 * @brief Callback функция для приёма пакетов
 * @param stream_id ID потока данных
 * @param opcode Код операции
 * @param data Указатель на payload
 * @param len Длина payload
 * @param ctx Пользовательский контекст
 * @note Thread-safe: зависит от реализации callback
 */
typedef void (*op_recv_cb)(uint32_t stream_id, uint8_t opcode,
                          const void *data, size_t len, void *ctx);

/**
 * @brief Инициализация библиотеки OverProto
 * @param cfg Указатель на конфигурацию (может быть NULL для значений по умолчанию)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * @note Должна быть вызвана перед использованием других функций
 */
int op_init(const OpConfig *cfg);

/**
 * @brief Завершение работы библиотеки OverProto
 * @note Thread-safe: yes
 * @note Освобождает все ресурсы, выделенные библиотекой
 */
void op_shutdown(void);

/**
 * @brief Установка callback функции для приёма пакетов
 * @param callback Callback функция (может быть NULL для отключения)
 * @param ctx Пользовательский контекст для передачи в callback
 * @note Thread-safe: yes
 * @note Callback будет вызываться из потока, читающего данные
 */
void op_set_handler(op_recv_cb callback, void *ctx);

/**
 * @brief Отправка пакета данных
 * @param fd File descriptor соединения
 * @param stream_id ID потока данных
 * @param opcode Код операции (OP_DATA, OP_CONTROL и т.д.)
 * @param proto Тип протокола (OP_PROTO_TCP, OP_PROTO_UDP и т.д.)
 * @param data Указатель на payload (может быть NULL если len == 0)
 * @param len Длина payload
 * @param flags Флаги пакета (OP_FLAG_RELIABLE и т.д.)
 * @return Количество отправленных байт при успехе, -1 при ошибке
 * @note Thread-safe: yes (если fd не разделяется между потоками для записи)
 * 
 * Удобная функция-обёртка для создания и отправки пакета
 */
ssize_t op_send(op_socket_t fd, uint32_t stream_id, uint8_t opcode, uint8_t proto,
                const void *data, size_t len, uint8_t flags);

/**
 * @brief Создание UDP сокета с привязкой к порту (bind)
 * @param port Порт для прослушивания (0 для любого доступного порта)
 * @return File descriptor UDP сокета при успехе, -1 при ошибке
 * @note Thread-safe: yes
 */
op_socket_t op_udp_bind(uint16_t port);

/**
 * @brief Создание UDP сокета с подключением к удалённому адресу
 * @param host Имя хоста или IP адрес
 * @param port Порт сервера
 * @return File descriptor UDP сокета при успехе, -1 при ошибке
 * @note Thread-safe: yes
 */
op_socket_t op_udp_connect(const char *host, uint16_t port);

/* Функция op_set_encryption_key объявлена в crypto.h */

#endif /* OVERPROTO_H */

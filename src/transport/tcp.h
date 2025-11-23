/**
 * @file tcp.h
 * @brief TCP транспорт с фреймингом пакетов OverProto
 */

#ifndef OVERPROTO_TCP_H
#define OVERPROTO_TCP_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include "../core/common.h"
#include "../core/packet.h"

/**
 * @brief Состояние TCP соединения
 */
typedef enum {
    OP_TCP_STATE_IDLE,
    OP_TCP_STATE_READING_HEADER,
    OP_TCP_STATE_READING_PAYLOAD,
    OP_TCP_STATE_READING_CRC,
    OP_TCP_STATE_READY
} OpTcpRecvState;

/**
 * @brief TCP соединение
 */
typedef struct {
    int fd;                         /* File descriptor сокета */
    OpTcpRecvState recv_state;      /* Состояние приёма */
    uint8_t *recv_buffer;           /* Буфер для чтения */
    size_t recv_buffer_size;        /* Размер буфера */
    size_t recv_bytes_read;         /* Количество прочитанных байт */
} OpTcpConnection;

/**
 * @brief Создание TCP сервера (bind + listen)
 * @param port Порт для прослушивания
 * @return File descriptor серверного сокета при успехе, -1 при ошибке
 * @note Thread-safe: yes
 */
int op_tcp_listen(uint16_t port);

/**
 * @brief Принятие соединения на серверном сокете
 * @param server_fd File descriptor серверного сокета
 * @return File descriptor клиентского сокета при успехе, -1 при ошибке
 * @note Thread-safe: yes (если server_fd не разделяется между потоками)
 * @note Блокирующий вызов. Для non-blocking использовать select/poll на server_fd
 */
int op_tcp_accept(int server_fd);

/**
 * @brief Подключение к TCP серверу
 * @param host Имя хоста или IP адрес
 * @param port Порт сервера
 * @return File descriptor соединения при успехе, -1 при ошибке
 * @note Thread-safe: yes
 */
int op_tcp_connect(const char *host, uint16_t port);

/**
 * @brief Инициализация структуры TCP соединения
 * @param conn Указатель на структуру соединения
 * @param fd File descriptor сокета
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: no (conn должен использоваться из одного потока)
 */
int op_tcp_connection_init(OpTcpConnection *conn, int fd);

/**
 * @brief Очистка ресурсов TCP соединения
 * @param conn Указатель на структуру соединения
 * @note Thread-safe: no (conn должен использоваться из одного потока)
 * @note Не закрывает fd, только освобождает буферы
 */
void op_tcp_connection_cleanup(OpTcpConnection *conn);

/**
 * @brief Отправка пакета через TCP
 * @param fd File descriptor TCP сокета
 * @param hdr Указатель на заголовок пакета
 * @param data Указатель на payload (может быть NULL если payload_len == 0)
 * @return Количество отправленных байт при успехе, -1 при ошибке
 * @note Thread-safe: yes (если fd не разделяется между потоками для записи)
 */
ssize_t op_tcp_send(int fd, const OverPacketHeader *hdr, const void *data);

/**
 * @brief Приём пакета через TCP (с state machine)
 * @param conn Указатель на структуру соединения
 * @param hdr Указатель на указатель для заголовка (выделяется через malloc)
 * @param data Указатель на указатель для payload (выделяется через malloc)
 * @param data_len Указатель на длину payload
 * @return 0 при успехе, -1 при ошибке, >0 количество прочитанных байт (в процессе)
 * @note Thread-safe: no (conn должен использоваться из одного потока)
 * @warning Вызывающий должен освободить память через free() для *hdr и *data
 * 
 * State machine: HEADER → PAYLOAD → CRC → VALIDATE
 * Может быть вызвана несколько раз для чтения полного пакета
 */
int op_tcp_recv(OpTcpConnection *conn,
                OverPacketHeader **hdr, void **data, size_t *data_len);

/**
 * @brief Закрытие TCP соединения
 * @param fd File descriptor сокета
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 */
int op_tcp_close(int fd);

#endif /* OVERPROTO_TCP_H */


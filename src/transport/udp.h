/**
 * @file udp.h
 * @brief UDP транспорт для OverProto
 * 
 * UDP транспорт с поддержкой фрагментации и MTU handling.
 * Для надёжной передачи используйте reliable.c (Selective Repeat).
 */

#ifndef OVERPROTO_UDP_H
#define OVERPROTO_UDP_H

#include <stdint.h>
#include <stddef.h>
#include "../core/common.h"
#include "../core/packet.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

/**
 * @brief UDP соединение/сокет
 */
typedef struct {
    op_socket_t fd;             /* Socket descriptor */
    struct sockaddr_in addr;    /* Адрес получателя/отправителя */
    socklen_t addr_len;         /* Длина адреса */
    size_t mtu;                 /* MTU для этого соединения */
} OpUdpConnection;

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
 * @note connect() на UDP сокете позволяет использовать send/recv вместо sendto/recvfrom
 */
op_socket_t op_udp_connect(const char *host, uint16_t port);

/**
 * @brief Инициализация UDP соединения из файлового дескриптора
 * @param conn Указатель на структуру соединения
 * @param fd File descriptor UDP сокета
 * @param addr Указатель на адрес (может быть NULL если не используется)
 * @param mtu MTU для этого соединения (по умолчанию 1400)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: no (conn должен использоваться из одного потока)
 */
int op_udp_connection_init(OpUdpConnection *conn, op_socket_t fd,
                           const struct sockaddr_in *addr, size_t mtu);

/**
 * @brief Отправка пакета через UDP
 * @param fd File descriptor UDP сокета
 * @param hdr Указатель на заголовок пакета
 * @param data Указатель на payload (может быть NULL если payload_len == 0)
 * @param addr Указатель на адрес получателя (NULL если сокет подключён)
 * @param addr_len Длина адреса (0 если сокет подключён)
 * @return Количество отправленных байт при успехе, -1 при ошибке
 * @note Thread-safe: yes (если fd не разделяется между потоками для записи)
 * @note Если пакет превышает MTU, используйте op_fragment_packet() перед отправкой
 */
ssize_t op_udp_send(op_socket_t fd, const OverPacketHeader *hdr, const void *data,
                    const struct sockaddr_in *addr, socklen_t addr_len);

/**
 * @brief Приём пакета через UDP
 * @param fd File descriptor UDP сокета
 * @param hdr Указатель на указатель для заголовка (выделяется через malloc)
 * @param data Указатель на указатель для payload (выделяется через malloc)
 * @param data_len Указатель на длину payload
 * @param addr Указатель на адрес отправителя (может быть NULL)
 * @param addr_len Указатель на длину адреса (может быть NULL)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes (если fd не разделяется между потоками для чтения)
 * @warning Вызывающий должен освободить память через free() для *hdr и *data
 * 
 * Принимает один UDP датаграмму и десериализует пакет.
 * Для фрагментированных пакетов используйте op_fragment_add().
 */
int op_udp_recv(op_socket_t fd, OverPacketHeader **hdr, void **data, size_t *data_len,
                struct sockaddr_in *addr, socklen_t *addr_len);

/**
 * @brief Закрытие UDP сокета
 * @param fd File descriptor сокета
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes
 */
int op_udp_close(op_socket_t fd);

/**
 * @brief Получить MTU для соединения
 * @param fd File descriptor UDP сокета
 * @return MTU в байтах при успехе, -1 при ошибке
 * @note Thread-safe: yes
 * 
 * Пытается определить MTU через getsockopt(IP_MTU), 
 * если не удаётся, возвращает значение по умолчанию (1400).
 */
size_t op_udp_get_mtu(op_socket_t fd);

#endif /* OVERPROTO_UDP_H */

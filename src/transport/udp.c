/**
 * @file udp.c
 * @brief Реализация UDP транспорта для OverProto
 * 
 * UDP транспорт с поддержкой MTU и фрагментации.
 * Использует sendto/recvfrom для отправки/приёма датаграмм.
 */

#include "udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define OP_UDP_RECV_BUFFER_SIZE (64 * 1024)  /* 64KB буфер для приёма */

int op_udp_bind(uint16_t port)
{
    int fd;
    struct sockaddr_in addr;
    int opt = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        OP_LOG_ERROR("socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Устанавливаем SO_REUSEADDR для переиспользования порта */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        OP_LOG_WARN("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
        /* Не критично, продолжаем */
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        OP_LOG_ERROR("bind() failed on port %u: %s", port, strerror(errno));
        close(fd);
        return -1;
    }

    OP_LOG_INFO("UDP server bound to port %u", port);
    return fd;
}

int op_udp_connect(const char *host, uint16_t port)
{
    int fd;
    struct sockaddr_in addr;

    if (host == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        OP_LOG_ERROR("socket() failed: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        OP_LOG_ERROR("Invalid IP address: %s", host);
        close(fd);
        errno = EINVAL;
        return -1;
    }

    /* connect() на UDP позволяет использовать send/recv вместо sendto/recvfrom */
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        OP_LOG_ERROR("connect() failed to %s:%u: %s", host, port, strerror(errno));
        close(fd);
        return -1;
    }

    OP_LOG_INFO("UDP connected to %s:%u", host, port);
    return fd;
}

int op_udp_connection_init(OpUdpConnection *conn, int fd,
                           const struct sockaddr_in *addr, size_t mtu)
{
    if (conn == NULL || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    memset(conn, 0, sizeof(OpUdpConnection));
    conn->fd = fd;
    conn->mtu = (mtu > 0) ? mtu : OP_FRAG_MTU_DEFAULT;
    conn->addr_len = sizeof(struct sockaddr_in);

    if (addr != NULL) {
        memcpy(&conn->addr, addr, sizeof(struct sockaddr_in));
    } else {
        memset(&conn->addr, 0, sizeof(struct sockaddr_in));
    }

    return 0;
}

ssize_t op_udp_send(int fd, const OverPacketHeader *hdr, const void *data,
                    const struct sockaddr_in *addr, socklen_t addr_len)
{
    uint8_t *send_buf = NULL;
    size_t send_buf_size;
    ssize_t result;
    ssize_t bytes_sent;

    if (fd < 0 || hdr == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Вычисляем размер сериализованного пакета */
    send_buf_size = OP_HEADER_SIZE + hdr->payload_len + sizeof(uint32_t);

    /* Проверка MTU - пакет должен помещаться в одну датаграмму */
    if (send_buf_size > OP_FRAG_MTU_DEFAULT) {
        OP_LOG_WARN("Packet size %zu > MTU %d, consider fragmentation",
                    send_buf_size, OP_FRAG_MTU_DEFAULT);
        /* Не блокируем, просто предупреждение */
    }

    /* Выделяем буфер для сериализации */
    send_buf = (uint8_t *)malloc(send_buf_size);
    if (send_buf == NULL) {
        OP_LOG_ERROR("Failed to allocate send buffer");
        errno = ENOMEM;
        return -1;
    }

    /* Сериализуем пакет */
    result = op_serialize(hdr, data, send_buf, send_buf_size);
    if (result < 0) {
        free(send_buf);
        return -1;
    }

    /* Отправляем датаграмму */
    if (addr != NULL && addr_len > 0) {
        /* Используем sendto для указанного адреса */
        bytes_sent = sendto(fd, send_buf, (size_t)result, 0,
                           (const struct sockaddr *)addr, addr_len);
    } else {
        /* Используем send для подключённого сокета */
        bytes_sent = send(fd, send_buf, (size_t)result, 0);
    }

    free(send_buf);

    if (bytes_sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            OP_LOG_WARN("send() would block");
        } else {
            OP_LOG_ERROR("send() failed: %s", strerror(errno));
        }
        return -1;
    }

    if ((size_t)bytes_sent != (size_t)result) {
        OP_LOG_WARN("Partial send: %zd/%zd bytes", bytes_sent, result);
    }

    return bytes_sent;
}

int op_udp_recv(int fd, OverPacketHeader **hdr, void **data, size_t *data_len,
                struct sockaddr_in *addr, socklen_t *addr_len)
{
    uint8_t *recv_buf = NULL;
    ssize_t n;
    int result;

    if (fd < 0 || hdr == NULL || data == NULL || data_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Инициализируем выходные параметры */
    *hdr = NULL;
    *data = NULL;
    *data_len = 0;

    /* Выделяем буфер для приёма */
    recv_buf = (uint8_t *)malloc(OP_UDP_RECV_BUFFER_SIZE);
    if (recv_buf == NULL) {
        OP_LOG_ERROR("Failed to allocate recv buffer");
        errno = ENOMEM;
        return -1;
    }

    /* Принимаем датаграмму */
    if (addr != NULL && addr_len != NULL) {
        /* Используем recvfrom для получения адреса отправителя */
        socklen_t addr_len_val = (socklen_t)(*addr_len);
        n = recvfrom(fd, recv_buf, OP_UDP_RECV_BUFFER_SIZE, 0,
                     (struct sockaddr *)addr, &addr_len_val);
        *addr_len = addr_len_val;
    } else {
        /* Используем recv для подключённого сокета */
        n = recv(fd, recv_buf, OP_UDP_RECV_BUFFER_SIZE, 0);
    }

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            OP_LOG_WARN("recv() would block");
        } else {
            OP_LOG_ERROR("recv() failed: %s", strerror(errno));
        }
        free(recv_buf);
        return -1;
    }

    if (n == 0) {
        /* UDP не возвращает 0 при закрытии, но на всякий случай */
        free(recv_buf);
        return 0;
    }

    /* Десериализуем пакет */
    result = op_deserialize(recv_buf, (size_t)n, hdr, data, data_len);
    
    free(recv_buf);

    if (result != 0) {
        /* op_deserialize освобождает память при ошибке */
        if (*hdr != NULL) {
            free(*hdr);
            *hdr = NULL;
        }
        if (*data != NULL) {
            free(*data);
            *data = NULL;
        }
        return -1;
    }

    return 0;
}

int op_udp_close(int fd)
{
    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }

    if (close(fd) < 0) {
        OP_LOG_ERROR("close() failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

size_t op_udp_get_mtu(int fd)
{
    int mtu_value;
    socklen_t len = sizeof(mtu_value);

    if (fd < 0) {
        errno = EINVAL;
        return 0;
    }

    /* Пытаемся получить MTU через getsockopt */
#ifdef IP_MTU
    if (getsockopt(fd, IPPROTO_IP, IP_MTU, &mtu_value, &len) == 0) {
        if (mtu_value > 0) {
            return (size_t)mtu_value;
        }
    }
#endif

    /* Если не удалось, возвращаем значение по умолчанию */
    return OP_FRAG_MTU_DEFAULT;
}


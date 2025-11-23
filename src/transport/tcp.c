/**
 * @file tcp.c
 * @brief Реализация TCP транспорта с фреймингом пакетов OverProto
 * 
 * Алгоритм TCP фрейминга:
 * 1. Чтение заголовка (24 байта) - гарантированное read_exact()
 * 2. Извлечение payload_len из заголовка
 * 3. Чтение payload (N байт) + CRC32 (4 байта)
 * 4. Валидация через op_deserialize()
 */

#include "tcp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define OP_TCP_BACKLOG 10
#define OP_TCP_RECV_BUFFER_SIZE (64 * 1024)  /* 64KB буфер по умолчанию */

/**
 * @brief Гарантированное чтение N байт из сокета
 * @param fd File descriptor сокета
 * @param buf Буфер для данных
 * @param len Количество байт для чтения
 * @return Количество прочитанных байт при успехе, -1 при ошибке, 0 при EOF
 * @note Блокирует до чтения len байт или ошибки/EOF
 */
static ssize_t read_exact(int fd, void *buf, size_t len)
{
    uint8_t *ptr = (uint8_t *)buf;
    size_t total_read = 0;
    ssize_t n;

    while (total_read < len) {
        n = read(fd, ptr + total_read, len - total_read);
        
        if (n < 0) {
            if (errno == EINTR) {
                continue;  /* Перезапускаем системный вызов */
            }
            OP_LOG_ERROR("read() failed: %s", strerror(errno));
            return -1;
        }
        
        if (n == 0) {
            /* EOF - соединение закрыто */
            return 0;
        }
        
        total_read += n;
    }

    return (ssize_t)total_read;
}

/**
 * @brief Гарантированная отправка N байт в сокет
 * @param fd File descriptor сокета
 * @param buf Буфер с данными
 * @param len Количество байт для отправки
 * @return Количество отправленных байт при успехе, -1 при ошибке
 * @note Блокирует до отправки len байт или ошибки
 */
static ssize_t send_exact(int fd, const void *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)buf;
    size_t total_sent = 0;
    ssize_t n;

    while (total_sent < len) {
        n = send(fd, ptr + total_sent, len - total_sent, 0);
        
        if (n < 0) {
            if (errno == EINTR) {
                continue;  /* Перезапускаем системный вызов */
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Non-blocking режим - нужно повторить позже */
                OP_LOG_WARN("send() would block");
                errno = EAGAIN;
                return -1;
            }
            OP_LOG_ERROR("send() failed: %s", strerror(errno));
            return -1;
        }
        
        if (n == 0) {
            /* Соединение закрыто */
            return 0;
        }
        
        total_sent += n;
    }

    return (ssize_t)total_sent;
}

int op_tcp_listen(uint16_t port)
{
    int fd;
    struct sockaddr_in addr;
    int opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        OP_LOG_ERROR("socket() failed: %s", strerror(errno));
        return -1;
    }

    /* Устанавливаем SO_REUSEADDR для переиспользования порта */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        OP_LOG_WARN("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
        close(fd);
        return -1;
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

    if (listen(fd, OP_TCP_BACKLOG) < 0) {
        OP_LOG_ERROR("listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    OP_LOG_INFO("TCP server listening on port %u", port);
    return fd;
}

int op_tcp_accept(int server_fd)
{
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int client_fd;

    client_fd = accept(server_fd, (struct sockaddr *)&addr, &addr_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            OP_LOG_ERROR("accept() failed: %s", strerror(errno));
        }
        return -1;
    }

    OP_LOG_INFO("TCP connection accepted from %s:%u",
                inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return client_fd;
}

int op_tcp_connect(const char *host, uint16_t port)
{
    int fd;
    struct sockaddr_in addr;

    if (host == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
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

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        OP_LOG_ERROR("connect() failed to %s:%u: %s", host, port, strerror(errno));
        close(fd);
        return -1;
    }

    OP_LOG_INFO("TCP connected to %s:%u", host, port);
    return fd;
}

int op_tcp_connection_init(OpTcpConnection *conn, int fd)
{
    if (conn == NULL || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    conn->fd = fd;
    conn->recv_state = OP_TCP_STATE_IDLE;
    conn->recv_buffer_size = OP_TCP_RECV_BUFFER_SIZE;
    conn->recv_bytes_read = 0;

    conn->recv_buffer = (uint8_t *)malloc(conn->recv_buffer_size);
    if (conn->recv_buffer == NULL) {
        OP_LOG_ERROR("Failed to allocate recv buffer");
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

void op_tcp_connection_cleanup(OpTcpConnection *conn)
{
    if (conn == NULL) {
        return;
    }

    if (conn->recv_buffer != NULL) {
        free(conn->recv_buffer);
        conn->recv_buffer = NULL;
    }

    conn->fd = -1;
    conn->recv_state = OP_TCP_STATE_IDLE;
    conn->recv_buffer_size = 0;
    conn->recv_bytes_read = 0;
}

ssize_t op_tcp_send(int fd, const OverPacketHeader *hdr, const void *data)
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

    /* Отправляем пакет */
    bytes_sent = send_exact(fd, send_buf, (size_t)result);
    
    free(send_buf);

    if (bytes_sent < 0) {
        return -1;
    }

    return bytes_sent;
}

int op_tcp_recv(OpTcpConnection *conn,
                OverPacketHeader **hdr, void **data, size_t *data_len)
{
    ssize_t n;
    OverPacketHeader hdr_temp;
    uint16_t payload_len;
    size_t total_packet_size;
    int result;

    if (conn == NULL || conn->fd < 0 || hdr == NULL || data == NULL || data_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    /* Инициализируем выходные параметры */
    *hdr = NULL;
    *data = NULL;
    *data_len = 0;

    /* State machine: HEADER → PAYLOAD → CRC → VALIDATE */
    switch (conn->recv_state) {
    case OP_TCP_STATE_IDLE:
    case OP_TCP_STATE_READING_HEADER:
        /* Читаем заголовок (24 байта) */
        n = read_exact(conn->fd, conn->recv_buffer, OP_HEADER_SIZE);
        if (n < 0) {
            return -1;
        }
        if (n == 0) {
            /* EOF - соединение закрыто */
            return 0;
        }
        if ((size_t)n < OP_HEADER_SIZE) {
            OP_LOG_ERROR("Incomplete header: read %zd < %d", n, OP_HEADER_SIZE);
            errno = EINVAL;
            return -1;
        }

        /* Копируем заголовок и преобразуем из network byte order */
        memcpy(&hdr_temp, conn->recv_buffer, OP_HEADER_SIZE);
        hdr_temp.magic = ntohs(hdr_temp.magic);
        hdr_temp.stream_id = ntohl(hdr_temp.stream_id);
        hdr_temp.seq = ntohl(hdr_temp.seq);
        hdr_temp.frag_id = ntohs(hdr_temp.frag_id);
        hdr_temp.total_frags = ntohs(hdr_temp.total_frags);
        hdr_temp.payload_len = ntohs(hdr_temp.payload_len);
        hdr_temp.timestamp = ntohl(hdr_temp.timestamp);

        /* Проверяем заголовок */
        if (op_validate_header(&hdr_temp) != 0) {
            return -1;
        }

        payload_len = hdr_temp.payload_len;
        total_packet_size = OP_HEADER_SIZE + payload_len + sizeof(uint32_t);

        /* Проверяем размер буфера */
        if (total_packet_size > conn->recv_buffer_size) {
            OP_LOG_ERROR("Packet too large: %zu > %zu", total_packet_size, conn->recv_buffer_size);
            errno = EINVAL;
            return -1;
        }

        /* Переходим к чтению payload + CRC */
        conn->recv_state = OP_TCP_STATE_READING_PAYLOAD;
        conn->recv_bytes_read = OP_HEADER_SIZE;

        /* Если payload_len == 0, пропускаем чтение payload */
        if (payload_len == 0) {
            /* Читаем только CRC32 */
            n = read_exact(conn->fd, conn->recv_buffer + OP_HEADER_SIZE, sizeof(uint32_t));
            if (n < 0) {
                conn->recv_state = OP_TCP_STATE_IDLE;
                return -1;
            }
            if (n == 0) {
                conn->recv_state = OP_TCP_STATE_IDLE;
                return 0;
            }
            if ((size_t)n < sizeof(uint32_t)) {
                OP_LOG_ERROR("Incomplete CRC: read %zd < %zu", n, sizeof(uint32_t));
                conn->recv_state = OP_TCP_STATE_IDLE;
                errno = EINVAL;
                return -1;
            }
            conn->recv_bytes_read = total_packet_size;
            conn->recv_state = OP_TCP_STATE_READY;
        }
        /* Продолжаем в следующем case для чтения payload */
        /* Fall through */

    case OP_TCP_STATE_READING_PAYLOAD:
        /* Читаем payload + CRC32 */
        payload_len = ntohs(((OverPacketHeader *)conn->recv_buffer)->payload_len);
        total_packet_size = OP_HEADER_SIZE + payload_len + sizeof(uint32_t);
        
        size_t remaining = total_packet_size - conn->recv_bytes_read;
        n = read_exact(conn->fd, conn->recv_buffer + conn->recv_bytes_read, remaining);
        if (n < 0) {
            conn->recv_state = OP_TCP_STATE_IDLE;
            return -1;
        }
        if (n == 0) {
            conn->recv_state = OP_TCP_STATE_IDLE;
            return 0;
        }
        if ((size_t)n < remaining) {
            OP_LOG_ERROR("Incomplete payload+CRC: read %zd < %zu", n, remaining);
            conn->recv_state = OP_TCP_STATE_IDLE;
            errno = EINVAL;
            return -1;
        }

        conn->recv_bytes_read = total_packet_size;
        conn->recv_state = OP_TCP_STATE_READY;
        /* Fall through */

    case OP_TCP_STATE_READY:
        /* Дезериализуем полный пакет */
        result = op_deserialize(conn->recv_buffer, conn->recv_bytes_read,
                                hdr, data, data_len);
        
        /* Сбрасываем состояние для следующего пакета */
        conn->recv_state = OP_TCP_STATE_IDLE;
        conn->recv_bytes_read = 0;

        return result;

    default:
        OP_LOG_ERROR("Invalid TCP receive state: %d", conn->recv_state);
        conn->recv_state = OP_TCP_STATE_IDLE;
        errno = EINVAL;
        return -1;
    }
}

int op_tcp_close(int fd)
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


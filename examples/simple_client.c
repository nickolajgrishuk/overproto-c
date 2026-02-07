/**
 * @file simple_client.c
 * @brief Простой пример TCP клиента на OverProto
 */

#include "../src/include/overproto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    const char *host = "127.0.0.1";
    uint16_t port = 8080;

    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = (uint16_t)atoi(argv[2]);
    }

    /* Инициализация библиотеки */
    OpConfig cfg;
    op_config_init(&cfg);
    
    if (op_init(&cfg) != 0) {
        fprintf(stderr, "Failed to initialize OverProto\n");
        return 1;
    }

    /* Подключение к серверу */
    op_socket_t fd = op_tcp_connect(host, port);
    if (fd == OP_INVALID_SOCKET) {
        fprintf(stderr, "Failed to connect to %s:%u\n", host, port);
        op_shutdown();
        return 1;
    }

    printf("Connected to %s:%u\n", host, port);

    /* Отправка данных */
    const char *message = "Hello, OverProto!";
    ssize_t sent = op_send(fd, 1, OP_DATA, OP_PROTO_TCP, 
                           message, strlen(message), 0);
    
    if (sent < 0) {
        fprintf(stderr, "Failed to send data\n");
    } else {
        printf("Sent %zd bytes: %s\n", sent, message);
    }

    /* Закрытие соединения */
    op_tcp_close(fd);
    op_shutdown();

    return 0;
}

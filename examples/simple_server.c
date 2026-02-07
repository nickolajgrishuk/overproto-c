/**
 * @file simple_server.c
 * @brief Простой пример TCP сервера на OverProto
 */

#include "../src/include/overproto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void recv_handler(uint32_t stream_id, uint8_t opcode,
                  const void *data, size_t len, void *ctx)
{
    (void)stream_id;
    (void)opcode;
    (void)ctx;
    
    printf("Received %zu bytes: %.*s\n", len, (int)len, (const char *)data);
}

int main(int argc, char *argv[])
{
    uint16_t port = 8080;

    if (argc > 1) {
        port = (uint16_t)atoi(argv[1]);
    }

    /* Инициализация библиотеки */
    OpConfig cfg;
    op_config_init(&cfg);
    cfg.tcp_port = port;
    
    if (op_init(&cfg) != 0) {
        fprintf(stderr, "Failed to initialize OverProto\n");
        return 1;
    }

    /* Установка обработчика приёма */
    op_set_handler(recv_handler, NULL);

    /* Создание TCP сервера */
    op_socket_t server_fd = op_tcp_listen(port);
    if (server_fd == OP_INVALID_SOCKET) {
        fprintf(stderr, "Failed to listen on port %u\n", port);
        op_shutdown();
        return 1;
    }

    printf("Server listening on port %u\n", port);

    /* Принятие соединения */
    op_socket_t client_fd = op_tcp_accept(server_fd);
    if (client_fd == OP_INVALID_SOCKET) {
        fprintf(stderr, "Failed to accept connection\n");
        op_tcp_close(server_fd);
        op_shutdown();
        return 1;
    }

    printf("Client connected\n");

    /* Создание соединения для приёма */
    OpTcpConnection conn;
    if (op_tcp_connection_init(&conn, client_fd) != 0) {
        fprintf(stderr, "Failed to initialize connection\n");
        op_tcp_close(client_fd);
        op_tcp_close(server_fd);
        op_shutdown();
        return 1;
    }

    /* Чтение пакетов */
    OverPacketHeader *hdr = NULL;
    void *data = NULL;
    size_t data_len = 0;

    int result = op_tcp_recv(&conn, &hdr, &data, &data_len);
    if (result == 0 && hdr != NULL) {
        /* Пакет получен, обработчик уже вызван через callback */
        free(hdr);
        if (data != NULL) {
            free(data);
        }
    }

    /* Очистка */
    op_tcp_connection_cleanup(&conn);
    op_tcp_close(client_fd);
    op_tcp_close(server_fd);
    op_shutdown();

    return 0;
}

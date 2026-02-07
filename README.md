# OverProto

OverProto network protocol library for high-performance data transfer over TCP/UDP with compression, encryption, and fragmentation support.

## Description

OverProto is a lightweight C library for creating network applications with advanced features:
- **Stream Multiplexing** - support for multiple data streams in a single connection
- **Compression** - automatic compression of large packets via zlib
- **Encryption** - data protection via AES-256-GCM (OpenSSL)
- **Fragmentation** - automatic splitting of large packets for UDP
- **Reliable Transmission** - reliable delivery mechanism via UDP (Selective Repeat)
- **Thread-safe API** - safe usage from multiple threads

## Features

### Transport Protocols
- **TCP** - stream transmission with packet framing
- **UDP** - datagram transmission with fragmentation and MTU handling support

### Optimizations
- **Automatic Compression** - data ≥512 bytes are compressed via zlib
- **AES-256-GCM Encryption** - confidentiality and data integrity protection
- **CRC32 Verification** - packet integrity check

### Protocol Features
- Header size: 24 bytes
- Stream data support (stream_id)
- Sequence numbers
- Large packet fragmentation
- Timestamp for packets

## Requirements

- **Compiler**: GCC or Clang with C99 support
- **CMake**: version 3.10 or higher
- **POSIX threads** on Linux / native Win32 synchronization on Windows
- **Winsock2** on Windows (linked automatically via `ws2_32`)
- **zlib** (optional): for data compression
- **OpenSSL** (optional): for data encryption

## Installation

### Linux Build

```bash
git clone https://github.com/nickolajgrishuk/overproto.git

cd overproto

mkdir build && cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DOVERPROTO_WITH_ZLIB=ON \
    -DOVERPROTO_WITH_OPENSSL=ON \
    -DOVERPROTO_BUILD_EXAMPLES=ON

make && sudo make install
```

### Windows Cross-Build (MinGW-w64 from Linux)

```bash
cmake -S . -B build_mingw \
    -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64.cmake \
    -DCMAKE_BUILD_TYPE=Release \
    -DOVERPROTO_WITH_ZLIB=OFF \
    -DOVERPROTO_WITH_OPENSSL=OFF \
    -DOVERPROTO_BUILD_EXAMPLES=ON

cmake --build build_mingw -j
```

### CMake Options

- `OVERPROTO_WITH_ZLIB` (ON/OFF) - enable zlib compression support (default: ON)
- `OVERPROTO_WITH_OPENSSL` (ON/OFF) - enable OpenSSL encryption support (default: OFF)
- `OVERPROTO_BUILD_EXAMPLES` (ON/OFF) - build usage examples (default: OFF)
- `CMAKE_TOOLCHAIN_FILE=cmake/toolchains/mingw-w64.cmake` - cross-build for Windows with MinGW-w64

## Usage

### Basic Example (TCP Client)

```c
#include <overproto.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    OpConfig cfg;
    op_config_init(&cfg);
    
    if (op_init(&cfg) != 0) {
        fprintf(stderr, "Failed to initialize OverProto\n");
        return 1;
    }

    op_socket_t fd = op_tcp_connect("127.0.0.1", 8080);
    if (fd == OP_INVALID_SOCKET) {
        fprintf(stderr, "Failed to connect\n");
        op_shutdown();
        return 1;
    }

    const char *message = "Hello, OverProto!";
    ssize_t sent = op_send(fd, 1, OP_DATA, OP_PROTO_TCP, 
                           message, strlen(message), 0);
    
    if (sent < 0) {
        fprintf(stderr, "Failed to send data\n");
    }

    op_tcp_close(fd);
    op_shutdown();

    return 0;
}
```

### TCP Server Example

```c
#include <overproto.h>
#include <stdio.h>

void recv_handler(uint32_t stream_id, uint8_t opcode,
                  const void *data, size_t len, void *ctx) {
    printf("Received %zu bytes on stream %u: %.*s\n", 
           len, stream_id, (int)len, (const char *)data);
}

int main(void) {
    OpConfig cfg;
    op_config_init(&cfg);
    cfg.tcp_port = 8080;
    
    if (op_init(&cfg) != 0) {
        fprintf(stderr, "Failed to initialize OverProto\n");
        return 1;
    }

    op_set_handler(recv_handler, NULL);

    op_socket_t server_fd = op_tcp_listen(8080);
    if (server_fd == OP_INVALID_SOCKET) {
        fprintf(stderr, "Failed to listen\n");
        op_shutdown();
        return 1;
    }

    printf("Server listening on port 8080\n");

    op_socket_t client_fd = op_tcp_accept(server_fd);
    if (client_fd == OP_INVALID_SOCKET) {
        op_tcp_close(server_fd);
        op_shutdown();
        return 1;
    }

    OpTcpConnection conn;
    if (op_tcp_connection_init(&conn, client_fd) == 0) {
        OverPacketHeader *hdr = NULL;
        void *data = NULL;
        size_t data_len = 0;

        op_tcp_recv(&conn, &hdr, &data, &data_len);
        
        if (hdr) free(hdr);
        if (data) free(data);
        
        op_tcp_connection_cleanup(&conn);
    }

    op_tcp_close(client_fd);
    op_tcp_close(server_fd);
    op_shutdown();

    return 0;
}
```

### Using Compression and Encryption

```c
// Set encryption key (32 bytes for AES-256)
uint8_t key[32] = {...}; // Your key
op_set_encryption_key(key);

// Send with automatic compression and encryption
ssize_t sent = op_send(fd, 1, OP_DATA, OP_PROTO_TCP,
                       data, data_len, 
                       OP_FLAG_COMPRESSED | OP_FLAG_ENCRYPTED);
```

## API

### Initialization

- `int op_init(const OpConfig *cfg)` - initialize the library
- `void op_shutdown(void)` - shutdown the library
- `void op_config_init(OpConfig *cfg)` - initialize configuration with default values

### Sending and Receiving

- `ssize_t op_send(op_socket_t fd, uint32_t stream_id, uint8_t opcode, uint8_t proto, const void *data, size_t len, uint8_t flags)` - send a packet
- `void op_set_handler(op_recv_cb callback, void *ctx)` - set packet receive handler

### TCP Transport

- `op_socket_t op_tcp_listen(uint16_t port)` - create TCP server
- `op_socket_t op_tcp_accept(op_socket_t server_fd)` - accept a connection
- `op_socket_t op_tcp_connect(const char *host, uint16_t port)` - connect to server
- `ssize_t op_tcp_send(op_socket_t fd, const OverPacketHeader *hdr, const void *data)` - send via TCP
- `int op_tcp_recv(OpTcpConnection *conn, OverPacketHeader **hdr, void **data, size_t *data_len)` - receive via TCP
- `int op_tcp_close(op_socket_t fd)` - close TCP connection

### UDP Transport

- `op_socket_t op_udp_bind(uint16_t port)` - bind UDP socket to port
- `op_socket_t op_udp_connect(const char *host, uint16_t port)` - connect UDP socket
- `ssize_t op_udp_send(op_socket_t fd, const OverPacketHeader *hdr, const void *data, const struct sockaddr_in *addr, socklen_t addr_len)` - send via UDP
- `int op_udp_recv(op_socket_t fd, OverPacketHeader **hdr, void **data, size_t *data_len, struct sockaddr_in *addr, socklen_t *addr_len)` - receive via UDP
- `int op_udp_close(op_socket_t fd)` - close UDP socket

### Security

- `int op_set_encryption_key(const uint8_t key[32])` - set encryption key
- `void op_clear_encryption_key(void)` - clear encryption key from memory
- `int op_is_encryption_enabled(void)` - check if encryption key is set

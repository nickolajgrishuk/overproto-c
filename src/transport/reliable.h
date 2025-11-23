/**
 * @file reliable.h
 * @brief Надёжная передача данных через UDP (Selective Repeat)
 * 
 * Реализация Selective Repeat ARQ с sliding window для надёжной передачи
 * данных через UDP. Поддерживает:
 * - Sliding window (по умолчанию 32 пакета)
 * - RTT estimation (Karn's algorithm)
 * - Exponential backoff для ретрансмиссий
 * - ACK подтверждения
 * 
 * Алгоритм: Selective Repeat Protocol (RFC 793 модификация для UDP)
 */

#ifndef OVERPROTO_RELIABLE_H
#define OVERPROTO_RELIABLE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "../core/common.h"
#include "../core/packet.h"

/* Константы надёжности */
#define OP_RELIABLE_WINDOW_SIZE     32
#define OP_RELIABLE_INITIAL_RTT_MS  100
#define OP_RELIABLE_MAX_RETRIES     5
#define OP_RELIABLE_TIMEOUT_MS      1000

/* Константы congestion control */
#define OP_RELIABLE_CWND_INITIAL    4    /* Начальный congestion window */
#define OP_RELIABLE_CWND_MIN        1    /* Минимальный congestion window */
#define OP_RELIABLE_CWND_MAX        32   /* Максимальный congestion window */
#define OP_RELIABLE_SSTHRESH_INIT   16   /* Начальный slow start threshold */

/**
 * @brief Состояние пакета в окне отправки
 */
typedef enum {
    OP_PKT_STATE_EMPTY,        /* Слот пуст */
    OP_PKT_STATE_SENT,         /* Отправлен, ожидает ACK */
    OP_PKT_STATE_ACKED,        /* Получен ACK */
    OP_PKT_STATE_RETRANSMIT    /* Требуется ретрансмиссия */
} OpPacketState;

/**
 * @brief Запись пакета в sliding window
 */
typedef struct {
    OverPacketHeader *header;   /* Заголовок пакета */
    uint8_t *data;              /* Payload пакета */
    size_t data_len;            /* Длина payload */
    uint8_t *serialized;        /* Сериализованный пакет */
    size_t serialized_len;      /* Длина сериализованного пакета */
    OpPacketState state;        /* Состояние пакета */
    time_t sent_at;            /* Время отправки */
    uint32_t retry_count;       /* Количество попыток отправки */
} OpWindowSlot;

/**
 * @brief RTT статистика (Karn's algorithm)
 */
typedef struct {
    uint32_t srtt_ms;          /* Smoothed RTT в миллисекундах */
    uint32_t rttvar_ms;        /* RTT variance */
    uint32_t rto_ms;           /* Retransmission timeout */
    time_t last_rtt_sample;    /* Время последнего измерения RTT */
    int samples_count;         /* Количество собранных образцов */
} OpRttStats;

/**
 * @brief Контекст надёжной передачи
 */
typedef struct {
    int fd;                     /* File descriptor UDP сокета */
    struct sockaddr_in addr;    /* Адрес получателя/отправителя */
    socklen_t addr_len;         /* Длина адреса */
    
    /* Sliding window */
    OpWindowSlot send_window[OP_RELIABLE_WINDOW_SIZE];
    uint32_t send_base;         /* Начало окна отправки (sequence number) */
    uint32_t next_seq;          /* Следующий sequence number для отправки */
    uint32_t window_size;       /* Размер окна */
    
    /* Приём */
    uint32_t recv_base;         /* Ожидаемый sequence number */
    uint8_t recv_window[OP_RELIABLE_WINDOW_SIZE];  /* Bitmap полученных пакетов */
    
    /* RTT и timeout */
    OpRttStats rtt;
    uint32_t timeout_ms;        /* Текущий timeout */
    
    /* Congestion control */
    uint32_t cwnd;              /* Congestion window (в пакетах) */
    uint32_t ssthresh;          /* Slow start threshold */
    uint32_t dup_ack_count;     /* Счётчик дубликатов ACK */
    uint32_t last_ack_seq;      /* Последний полученный ACK sequence */
    int in_slow_start;          /* Флаг slow start режима */
    
    /* Потокобезопасность */
    void *mutex;                /* Мьютекс для потокобезопасности (pthread_mutex_t) */
} OpReliableCtx;

/**
 * @brief Инициализация контекста надёжной передачи
 * @param ctx Указатель на контекст
 * @param fd File descriptor UDP сокета
 * @param addr Указатель на адрес получателя/отправителя
 * @param addr_len Длина адреса
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: no (ctx должен быть инициализирован из одного потока)
 */
int op_reliable_init(OpReliableCtx *ctx, int fd,
                     const struct sockaddr_in *addr, socklen_t addr_len);

/**
 * @brief Отправка пакета с надёжностью
 * @param ctx Указатель на контекст надёжности
 * @param hdr Указатель на заголовок пакета
 * @param data Указатель на payload (может быть NULL если payload_len == 0)
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes (если ctx защищён мьютексом)
 * 
 * Отправляет пакет и добавляет его в sliding window.
 * Автоматически ретранслирует при timeout.
 */
int op_reliable_send(OpReliableCtx *ctx, const OverPacketHeader *hdr,
                     const void *data);

/**
 * @brief Приём пакета с надёжностью
 * @param ctx Указатель на контекст надёжности
 * @param hdr Указатель на указатель для заголовка (выделяется через malloc)
 * @param data Указатель на указатель для payload (выделяется через malloc)
 * @param data_len Указатель на длину payload
 * @return 0 при успехе, -1 при ошибке, 1 если пакет уже получен (дубликат)
 * @note Thread-safe: yes (если ctx защищён мьютексом)
 * @warning Вызывающий должен освободить память через free() для *hdr и *data
 * 
 * Принимает пакет и отправляет ACK. Обрабатывает дубликаты.
 */
int op_reliable_recv(OpReliableCtx *ctx, OverPacketHeader **hdr,
                     void **data, size_t *data_len);

/**
 * @brief Обработка таймеров (retransmit timeout)
 * @param ctx Указатель на контекст надёжности
 * @return Количество ретранслированных пакетов, -1 при ошибке
 * @note Thread-safe: yes (если ctx защищён мьютексом)
 * 
 * Должна вызываться периодически для проверки timeout и ретрансмиссии.
 */
int op_reliable_process_timeouts(OpReliableCtx *ctx);

/**
 * @brief Обработка входящих ACK пакетов
 * @param ctx Указатель на контекст надёжности
 * @param ack_seq Sequence number подтверждённого пакета
 * @return 0 при успехе, -1 при ошибке
 * @note Thread-safe: yes (если ctx защищён мьютексом)
 * 
 * Обновляет sliding window на основе полученного ACK.
 */
int op_reliable_process_ack(OpReliableCtx *ctx, uint32_t ack_seq);

/**
 * @brief Очистка контекста надёжной передачи
 * @param ctx Указатель на контекст
 * @note Thread-safe: no
 * 
 * Освобождает все выделенные ресурсы.
 */
void op_reliable_cleanup(OpReliableCtx *ctx);

#endif /* OVERPROTO_RELIABLE_H */


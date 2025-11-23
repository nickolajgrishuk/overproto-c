/**
 * @file reliable.c
 * @brief Реализация надёжной передачи данных через UDP (Selective Repeat)
 * 
 * Алгоритм Selective Repeat:
 * 1. Sliding window для отправки/приёма
 * 2. ACK подтверждения для каждого пакета
 * 3. Retransmit timeout с exponential backoff
 * 4. RTT estimation для динамического timeout
 * 
 * Karn's algorithm для RTT:
 * - Измеряем RTT только для новых пакетов (не для ретрансмиссий)
 * - Используем формулу: RTO = SRTT + 4*RTTVAR
 */

#define _POSIX_C_SOURCE 200112L
#include "reliable.h"
#include "udp.h"
#include "../core/fragment.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

/* Вспомогательные функции */

/**
 * @brief Вычислить индекс в окне по sequence number
 */
static uint32_t seq_to_window_index(uint32_t seq, uint32_t base, uint32_t window_size)
{
    return (seq - base) % window_size;
}

/**
 * @brief Проверить, находится ли sequence number в окне
 */
static int is_in_window(uint32_t seq, uint32_t base, uint32_t window_size)
{
    uint32_t diff = seq - base;
    return (diff < window_size);
}

/**
 * @brief Обновить RTT статистику (Karn's algorithm)
 */
static void update_rtt(OpRttStats *rtt, uint32_t measured_rtt_ms)
{
    if (rtt == NULL) {
        return;
    }

    /* Первый образец */
    if (rtt->samples_count == 0) {
        rtt->srtt_ms = measured_rtt_ms;
        rtt->rttvar_ms = measured_rtt_ms / 2;
    } else {
        /* Обновляем smoothed RTT */
        int32_t error = (int32_t)measured_rtt_ms - (int32_t)rtt->srtt_ms;
        rtt->srtt_ms += error / 8;  /* alpha = 1/8 */
        
        /* Обновляем variance */
        if (error < 0) {
            error = -error;
        }
        rtt->rttvar_ms += (error - (int32_t)rtt->rttvar_ms) / 4;  /* beta = 1/4 */
    }

    /* Вычисляем RTO = SRTT + 4*RTTVAR */
    rtt->rto_ms = rtt->srtt_ms + 4 * rtt->rttvar_ms;
    
    /* Ограничиваем RTO разумными значениями */
    if (rtt->rto_ms < 100) {
        rtt->rto_ms = 100;  /* Минимум 100ms */
    }
    if (rtt->rto_ms > 60000) {
        rtt->rto_ms = 60000;  /* Максимум 60 секунд */
    }

    rtt->samples_count++;
}

int op_reliable_init(OpReliableCtx *ctx, int fd,
                     const struct sockaddr_in *addr, socklen_t addr_len)
{
    pthread_mutex_t *mutex = NULL;

    if (ctx == NULL || fd < 0) {
        errno = EINVAL;
        return -1;
    }

    memset(ctx, 0, sizeof(OpReliableCtx));
    ctx->fd = fd;
    ctx->window_size = OP_RELIABLE_WINDOW_SIZE;
    ctx->send_base = 0;
    ctx->next_seq = 0;
    ctx->recv_base = 0;
    ctx->timeout_ms = OP_RELIABLE_INITIAL_RTT_MS;

    if (addr != NULL && addr_len > 0) {
        memcpy(&ctx->addr, addr, sizeof(struct sockaddr_in));
        ctx->addr_len = addr_len;
    } else {
        memset(&ctx->addr, 0, sizeof(struct sockaddr_in));
        ctx->addr_len = sizeof(struct sockaddr_in);
    }

    /* Инициализируем RTT статистику */
    ctx->rtt.srtt_ms = OP_RELIABLE_INITIAL_RTT_MS;
    ctx->rtt.rttvar_ms = OP_RELIABLE_INITIAL_RTT_MS / 2;
    ctx->rtt.rto_ms = OP_RELIABLE_INITIAL_RTT_MS * 2;
    ctx->rtt.samples_count = 0;

    /* Инициализируем окно отправки */
    memset(ctx->send_window, 0, sizeof(ctx->send_window));
    for (uint32_t i = 0; i < OP_RELIABLE_WINDOW_SIZE; i++) {
        ctx->send_window[i].state = OP_PKT_STATE_EMPTY;
    }

    /* Инициализируем окно приёма */
    memset(ctx->recv_window, 0, sizeof(ctx->recv_window));

    /* Инициализируем congestion control */
    ctx->cwnd = OP_RELIABLE_CWND_INITIAL;
    ctx->ssthresh = OP_RELIABLE_SSTHRESH_INIT;
    ctx->dup_ack_count = 0;
    ctx->last_ack_seq = 0;
    ctx->in_slow_start = 1;

    /* Создаём мьютекс */
    mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
    if (mutex == NULL) {
        OP_LOG_ERROR("Failed to allocate memory for mutex");
        errno = ENOMEM;
        return -1;
    }

    if (pthread_mutex_init(mutex, NULL) != 0) {
        OP_LOG_ERROR("Failed to initialize mutex");
        free(mutex);
        errno = EAGAIN;
        return -1;
    }

    ctx->mutex = mutex;

    return 0;
}

int op_reliable_send(OpReliableCtx *ctx, const OverPacketHeader *hdr,
                     const void *data)
{
    pthread_mutex_t *mutex;
    uint32_t seq;
    uint32_t window_idx;
    OpWindowSlot *slot;
    uint8_t *serialized = NULL;
    size_t serialized_size;
    ssize_t result;
    time_t now;
    OverPacketHeader hdr_copy;

    if (ctx == NULL || hdr == NULL) {
        errno = EINVAL;
        return -1;
    }

    mutex = (pthread_mutex_t *)ctx->mutex;
    if (mutex == NULL) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(mutex);

    /* Проверяем, есть ли место в окне (с учётом congestion window) */
    uint32_t effective_window = (ctx->cwnd < ctx->window_size) ? ctx->cwnd : ctx->window_size;
    uint32_t unacked_packets = ctx->next_seq - ctx->send_base;
    
    if (unacked_packets >= effective_window) {
        OP_LOG_DEBUG("Congestion window full: %u/%u packets", unacked_packets, effective_window);
        pthread_mutex_unlock(mutex);
        errno = EAGAIN;
        return -1;
    }
    
    /* Проверяем также физический размер окна */
    if (!is_in_window(ctx->next_seq, ctx->send_base, ctx->window_size)) {
        OP_LOG_WARN("Window full, waiting for ACK");
        pthread_mutex_unlock(mutex);
        errno = EAGAIN;
        return -1;
    }

    /* Вычисляем индекс в окне */
    seq = ctx->next_seq;
    window_idx = seq_to_window_index(seq, ctx->send_base, ctx->window_size);
    slot = &ctx->send_window[window_idx];

    /* Проверяем, что слот пуст */
    if (slot->state != OP_PKT_STATE_EMPTY) {
        OP_LOG_ERROR("Window slot %u not empty", window_idx);
        pthread_mutex_unlock(mutex);
        errno = EINVAL;
        return -1;
    }

    /* Копируем заголовок и устанавливаем sequence number */
    memcpy(&hdr_copy, hdr, sizeof(OverPacketHeader));
    hdr_copy.seq = seq;
    hdr_copy.flags |= OP_FLAG_RELIABLE;  /* Устанавливаем флаг надёжности */

    /* Сериализуем пакет */
    serialized_size = OP_HEADER_SIZE + hdr->payload_len + sizeof(uint32_t);
    serialized = (uint8_t *)malloc(serialized_size);
    if (serialized == NULL) {
        OP_LOG_ERROR("Failed to allocate memory for serialized packet");
        pthread_mutex_unlock(mutex);
        errno = ENOMEM;
        return -1;
    }

    result = op_serialize(&hdr_copy, data, serialized, serialized_size);
    if (result < 0) {
        free(serialized);
        pthread_mutex_unlock(mutex);
        return -1;
    }

    /* Сохраняем в окне */
    slot->header = (OverPacketHeader *)malloc(sizeof(OverPacketHeader));
    if (slot->header == NULL) {
        free(serialized);
        pthread_mutex_unlock(mutex);
        errno = ENOMEM;
        return -1;
    }
    memcpy(slot->header, &hdr_copy, sizeof(OverPacketHeader));

    if (hdr->payload_len > 0 && data != NULL) {
        slot->data = (uint8_t *)malloc(hdr->payload_len);
        if (slot->data == NULL) {
            free(serialized);
            free(slot->header);
            slot->header = NULL;
            pthread_mutex_unlock(mutex);
            errno = ENOMEM;
            return -1;
        }
        memcpy(slot->data, data, hdr->payload_len);
    } else {
        slot->data = NULL;
    }

    slot->data_len = hdr->payload_len;
    slot->serialized = serialized;
    slot->serialized_len = (size_t)result;
    slot->state = OP_PKT_STATE_SENT;
    slot->retry_count = 0;
    
    now = time(NULL);
    if (now == (time_t)-1) {
        now = 0;
    }
    slot->sent_at = now;

    /* Отправляем пакет */
    ssize_t sent = sendto(ctx->fd, serialized, slot->serialized_len, 0,
                          (const struct sockaddr *)&ctx->addr, ctx->addr_len);
    if (sent < 0) {
        OP_LOG_ERROR("sendto() failed: %s", strerror(errno));
        slot->state = OP_PKT_STATE_EMPTY;
        free(serialized);
        free(slot->header);
        if (slot->data != NULL) {
            free(slot->data);
        }
        memset(slot, 0, sizeof(OpWindowSlot));
        pthread_mutex_unlock(mutex);
        return -1;
    }

    ctx->next_seq++;

    pthread_mutex_unlock(mutex);
    return 0;
}

int op_reliable_recv(OpReliableCtx *ctx, OverPacketHeader **hdr,
                     void **data, size_t *data_len)
{
    pthread_mutex_t *mutex;
    OverPacketHeader *recv_hdr = NULL;
    void *recv_data = NULL;
    size_t recv_data_len = 0;
    uint32_t seq;
    uint32_t window_idx;
    OverPacketHeader ack_hdr;
    uint8_t ack_buf[OP_HEADER_SIZE + sizeof(uint32_t)];
    ssize_t ack_serialized;
    ssize_t sent;

    if (ctx == NULL || hdr == NULL || data == NULL || data_len == NULL) {
        errno = EINVAL;
        return -1;
    }

    mutex = (pthread_mutex_t *)ctx->mutex;
    if (mutex == NULL) {
        errno = EINVAL;
        return -1;
    }

    *hdr = NULL;
    *data = NULL;
    *data_len = 0;

    /* Принимаем пакет через UDP */
    int result = op_udp_recv(ctx->fd, &recv_hdr, &recv_data, &recv_data_len,
                             NULL, NULL);
    if (result != 0) {
        return result;
    }

    if (recv_hdr == NULL) {
        return -1;
    }

    seq = recv_hdr->seq;

    pthread_mutex_lock(mutex);

    /* Проверяем, находится ли пакет в окне */
    if (!is_in_window(seq, ctx->recv_base, ctx->window_size)) {
        /* Пакет вне окна - возможно старый или будущий */
        OP_LOG_WARN("Packet seq %u outside receive window [%u, %u)",
                    seq, ctx->recv_base, ctx->recv_base + ctx->window_size);
        
        /* Всё равно отправляем ACK */
        goto send_ack;
    }

    window_idx = seq_to_window_index(seq, ctx->recv_base, ctx->window_size);

    /* Проверяем, не получен ли уже этот пакет */
    if (ctx->recv_window[window_idx] != 0) {
        /* Дубликат - отправляем ACK, но не обрабатываем */
        OP_LOG_DEBUG("Duplicate packet seq %u", seq);
        free(recv_hdr);
        if (recv_data != NULL) {
            free(recv_data);
        }
        pthread_mutex_unlock(mutex);
        
        /* Отправляем ACK без блокировки */
        goto send_ack_no_lock;
    }

    /* Помечаем пакет как полученный */
    ctx->recv_window[window_idx] = 1;

    /* Если это ожидаемый пакет (recv_base), сдвигаем окно */
    if (seq == ctx->recv_base) {
        /* Находим следующий неполученный пакет */
        while (ctx->recv_window[seq_to_window_index(ctx->recv_base,
                                                     ctx->recv_base,
                                                     ctx->window_size)] != 0) {
            uint32_t idx = seq_to_window_index(ctx->recv_base,
                                                ctx->recv_base,
                                                ctx->window_size);
            ctx->recv_window[idx] = 0;
            ctx->recv_base++;
        }
    }

    /* Возвращаем пакет */
    *hdr = recv_hdr;
    *data = recv_data;
    *data_len = recv_data_len;

    pthread_mutex_unlock(mutex);

send_ack:
    pthread_mutex_unlock(mutex);

send_ack_no_lock:
    /* Отправляем ACK */
    memset(&ack_hdr, 0, sizeof(ack_hdr));
    ack_hdr.magic = OP_MAGIC;
    ack_hdr.version = OP_VERSION;
    ack_hdr.flags = OP_FLAG_ACK | OP_FLAG_RELIABLE;
    ack_hdr.opcode = OP_ACK;
    ack_hdr.proto = OP_PROTO_UDP;
    ack_hdr.stream_id = recv_hdr->stream_id;
    ack_hdr.seq = seq;  /* ACK для этого sequence number */
    ack_hdr.payload_len = 0;
    ack_hdr.timestamp = (uint32_t)time(NULL);

    ack_serialized = op_serialize(&ack_hdr, NULL, ack_buf, sizeof(ack_buf));
    if (ack_serialized > 0) {
        sent = sendto(ctx->fd, ack_buf, (size_t)ack_serialized, 0,
                      (const struct sockaddr *)&ctx->addr, ctx->addr_len);
        if (sent < 0) {
            OP_LOG_WARN("Failed to send ACK: %s", strerror(errno));
        }
    }

    return 0;
}

int op_reliable_process_timeouts(OpReliableCtx *ctx)
{
    pthread_mutex_t *mutex;
    time_t now;
    uint32_t i;
    OpWindowSlot *slot;
    int retransmit_count = 0;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    mutex = (pthread_mutex_t *)ctx->mutex;
    if (mutex == NULL) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(mutex);

    now = time(NULL);
    if (now == (time_t)-1) {
        now = 0;
    }

    /* Проверяем все пакеты в окне */
    for (i = 0; i < ctx->window_size; i++) {
        slot = &ctx->send_window[i];

        if (slot->state == OP_PKT_STATE_SENT || slot->state == OP_PKT_STATE_RETRANSMIT) {
            time_t elapsed = now - slot->sent_at;

            /* Проверяем timeout */
            if (elapsed >= (time_t)(ctx->rtt.rto_ms / 1000) || 
                (elapsed > 0 && ctx->rtt.rto_ms < 1000)) {
                
                if (slot->retry_count >= OP_RELIABLE_MAX_RETRIES) {
                    /* Превышено максимальное количество попыток */
                    OP_LOG_ERROR("Max retries exceeded for seq %u", 
                                slot->header ? slot->header->seq : 0);
                    slot->state = OP_PKT_STATE_EMPTY;
                    continue;
                }

                /* Ретрансмиссия при timeout */
                ssize_t sent = sendto(ctx->fd, slot->serialized, slot->serialized_len, 0,
                                      (const struct sockaddr *)&ctx->addr, ctx->addr_len);
                if (sent >= 0) {
                    slot->state = OP_PKT_STATE_RETRANSMIT;
                    slot->retry_count++;
                    slot->sent_at = now;
                    
                    /* Exponential backoff для timeout */
                    ctx->timeout_ms = ctx->rtt.rto_ms * (1U << (slot->retry_count - 1));
                    if (ctx->timeout_ms > 60000) {
                        ctx->timeout_ms = 60000;
                    }
                    
                    /* Congestion control: при timeout уменьшаем окно */
                    ctx->ssthresh = ctx->cwnd / 2;
                    if (ctx->ssthresh < OP_RELIABLE_CWND_MIN) {
                        ctx->ssthresh = OP_RELIABLE_CWND_MIN;
                    }
                    ctx->cwnd = OP_RELIABLE_CWND_INITIAL;  /* Возврат к начальному значению */
                    ctx->in_slow_start = 1;
                    
                    OP_LOG_DEBUG("Timeout retransmit - congestion window reduced: cwnd=%u, ssthresh=%u",
                                ctx->cwnd, ctx->ssthresh);

                    retransmit_count++;
                }
            }
        }
    }

    pthread_mutex_unlock(mutex);
    return retransmit_count;
}

int op_reliable_process_ack(OpReliableCtx *ctx, uint32_t ack_seq)
{
    pthread_mutex_t *mutex;
    uint32_t window_idx;
    OpWindowSlot *slot;
    time_t now;

    if (ctx == NULL) {
        errno = EINVAL;
        return -1;
    }

    mutex = (pthread_mutex_t *)ctx->mutex;
    if (mutex == NULL) {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(mutex);

    /* Проверяем, находится ли ACK в окне */
    if (!is_in_window(ack_seq, ctx->send_base, ctx->window_size)) {
        /* ACK вне окна - игнорируем */
        pthread_mutex_unlock(mutex);
        return 0;
    }

    window_idx = seq_to_window_index(ack_seq, ctx->send_base, ctx->window_size);
    slot = &ctx->send_window[window_idx];

    if (slot->state == OP_PKT_STATE_EMPTY || slot->header == NULL) {
        /* Пакет уже обработан или не существует */
        pthread_mutex_unlock(mutex);
        return 0;
    }

    /* Проверяем на дубликаты ACK (Fast Retransmit) */
    if (ack_seq == ctx->last_ack_seq) {
        /* Дубликат ACK */
        ctx->dup_ack_count++;
        if (ctx->dup_ack_count >= 3) {
            /* Fast Retransmit: ретранслируем пакет без ожидания timeout */
            OP_LOG_DEBUG("Fast retransmit triggered (3 duplicate ACKs)");
            ctx->dup_ack_count = 0;
            
            /* Уменьшаем congestion window */
            ctx->ssthresh = ctx->cwnd / 2;
            if (ctx->ssthresh < OP_RELIABLE_CWND_MIN) {
                ctx->ssthresh = OP_RELIABLE_CWND_MIN;
            }
            ctx->cwnd = ctx->ssthresh + 3;  /* Fast Recovery */
            ctx->in_slow_start = 0;
        }
    } else {
        /* Новый ACK - сбрасываем счётчик дубликатов */
        ctx->dup_ack_count = 0;
        ctx->last_ack_seq = ack_seq;
        
        /* Обновляем congestion window */
        if (ctx->in_slow_start) {
            /* Slow Start: экспоненциальный рост */
            ctx->cwnd++;
            if (ctx->cwnd >= ctx->ssthresh) {
                ctx->in_slow_start = 0;
                OP_LOG_DEBUG("Slow start completed, switching to congestion avoidance");
            }
        } else {
            /* Congestion Avoidance: линейный рост (1/cwnd на ACK) */
            /* Упрощённая версия: увеличиваем на 1 каждый cwnd ACK */
            static uint32_t ack_counter = 0;
            ack_counter++;
            if (ack_counter >= ctx->cwnd) {
                ctx->cwnd++;
                ack_counter = 0;
            }
        }
        
        /* Ограничиваем максимальный размер окна */
        if (ctx->cwnd > OP_RELIABLE_CWND_MAX) {
            ctx->cwnd = OP_RELIABLE_CWND_MAX;
        }
        
        /* Эффективный размер окна уже ограничен выше */
    }

    /* Помечаем пакет как подтверждённый */
    slot->state = OP_PKT_STATE_ACKED;

    /* Обновляем RTT (только для первого ACK, не для ретрансмиссий) */
    if (slot->retry_count == 0) {
        now = time(NULL);
        if (now != (time_t)-1 && slot->sent_at != 0) {
            time_t elapsed = now - slot->sent_at;
            uint32_t rtt_ms = (uint32_t)(elapsed * 1000);
            if (rtt_ms > 0) {
                update_rtt(&ctx->rtt, rtt_ms);
                ctx->timeout_ms = ctx->rtt.rto_ms;
            }
        }
    }

    /* Сдвигаем окно, если возможно */
    while (ctx->send_window[seq_to_window_index(ctx->send_base,
                                                 ctx->send_base,
                                                 ctx->window_size)].state == OP_PKT_STATE_ACKED) {
        window_idx = seq_to_window_index(ctx->send_base, ctx->send_base, ctx->window_size);
        slot = &ctx->send_window[window_idx];
        
        /* Освобождаем ресурсы */
        if (slot->header != NULL) {
            free(slot->header);
            slot->header = NULL;
        }
        if (slot->data != NULL) {
            free(slot->data);
            slot->data = NULL;
        }
        if (slot->serialized != NULL) {
            free(slot->serialized);
            slot->serialized = NULL;
        }
        slot->state = OP_PKT_STATE_EMPTY;
        
        ctx->send_base++;
    }

    pthread_mutex_unlock(mutex);
    return 0;
}

void op_reliable_cleanup(OpReliableCtx *ctx)
{
    pthread_mutex_t *mutex;
    uint32_t i;
    OpWindowSlot *slot;

    if (ctx == NULL) {
        return;
    }

    mutex = (pthread_mutex_t *)ctx->mutex;

    if (mutex != NULL) {
        pthread_mutex_lock(mutex);
    }

    /* Освобождаем все пакеты в окне */
    for (i = 0; i < ctx->window_size; i++) {
        slot = &ctx->send_window[i];
        
        if (slot->header != NULL) {
            free(slot->header);
        }
        if (slot->data != NULL) {
            free(slot->data);
        }
        if (slot->serialized != NULL) {
            free(slot->serialized);
        }
    }

    if (mutex != NULL) {
        pthread_mutex_unlock(mutex);
        pthread_mutex_destroy(mutex);
        free(mutex);
        ctx->mutex = NULL;
    }

    memset(ctx, 0, sizeof(OpReliableCtx));
}


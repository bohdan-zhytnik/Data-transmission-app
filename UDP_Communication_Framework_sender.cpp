#define _WIN32_WINNT 0x0600
#pragma comment(lib, "ws2_32.lib")
#include "stdafx.h"
#include <winsock2.h>
#include "ws2tcpip.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#include "SHA256.h"
#include "CRC32.h"

#define TARGET_IP   "127.0.0.2"
#define LOCAL_IP    "127.0.0.3"
#define BUFFERS_LEN 1024

#define TARGET_PORT 14000
#define LOCAL_PORT  15000

#define MAX_RETRIES 50
#define TIMEOUT_MS  1000  
#define PACKET_HEADER_SIZE 12 // 4 bytes TYPE, 4 bytes SEQ, 4 bytes CRC
#define MAX_DATA_LEN (BUFFERS_LEN - PACKET_HEADER_SIZE)

#define TYPE_NAME "NAME"
#define TYPE_WIND "W_SZ"
#define TYPE_SIZE "SIZE"
#define TYPE_HASH "HASH"
#define TYPE_STAR "STAR"
#define TYPE_DATA "DATA"
#define TYPE_STOP "STOP"

typedef struct {
    uint32_t seq_num;
    unsigned char packet[BUFFERS_LEN];
    int packet_len;
    bool acked;
    int retries;
    DWORD send_time;
} WindowPacket;

void pause_and_exit() {
    system("pause"); // Displays "Press any key to continue . . ."
}

void InitWinsock() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

// Set receive timeout on a socket
int set_socket_timeout(SOCKET s, int timeout_ms) {
    int tv = timeout_ms;
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
}

// Compute file hash (SHA256)
int compute_file_hash(const char *filename, char *hash_str, size_t hash_str_size) {
    try {
        std::string hash = compute_sha256(filename); 
        if (hash.size() < hash_str_size) {
            strncpy(hash_str, hash.c_str(), hash_str_size - 1);
            hash_str[hash_str_size - 1] = '\0';
            return 0;
        } else {
            strncpy(hash_str, hash.c_str(), hash_str_size - 1);
            hash_str[hash_str_size - 1] = '\0';
            return 0;
        }
    } catch (const std::exception &e) {
        fprintf(stderr, "compute_file_hash error: %s\n", e.what());
        return -1;
    }
}
int send_packet_and_wait_ack(SOCKET socketS, struct sockaddr_in *addrDest,
                             const char* packet_type,
                             uint32_t seq_num,
                             const unsigned char* payload, size_t payload_len)
{
    unsigned char buffer[BUFFERS_LEN];

    memcpy(buffer, packet_type, 4);
    uint32_t net_seq = htonl(seq_num);
    memcpy(buffer+4, &net_seq, 4);

    memset(buffer+8, 0, 4);

    if (payload_len > BUFFERS_LEN - 12) {
        printf("Payload too large!\n");
        return -1;
    }
    if (payload_len > 0) {
        memcpy(buffer+12, payload, payload_len);
    }
    uint32_t crc = compute_crc32((const char*)buffer, int(payload_len+12));
    uint32_t net_crc = htonl(crc);
    memcpy(buffer+8, &net_crc, 4);
    int attempt = 0;

    char ack_buffer[BUFFERS_LEN];
    struct sockaddr_in from;
    from.sin_family = AF_INET;
    from.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &from.sin_addr.s_addr);
    int fromlen = sizeof(from);

    while (attempt < MAX_RETRIES) {
        int packet_size = (int)(12 + payload_len);
        sendto(socketS, (const char*)buffer, packet_size, 0, (sockaddr*)addrDest, sizeof(*addrDest));

        int received = recvfrom(socketS, ack_buffer, BUFFERS_LEN, 0, (sockaddr*)&from, &fromlen);
        if (received == SOCKET_ERROR) {
            printf("Timeout waiting for ACK/NACK for seq=%u, attempt=%d\n", seq_num, attempt);
            attempt++;
            continue;
        }

        if (received < BUFFERS_LEN) {
            ack_buffer[received] = '\0';
        } else {
            ack_buffer[BUFFERS_LEN-1] = '\0';
        }

        if (strncmp(ack_buffer, "ACK=", 4) == 0) {
            uint32_t rseq = (uint32_t)atoi(ack_buffer+4);
            if (rseq == seq_num) {
                printf("Received ACK for seq_num=%u\n", seq_num);
                return 0; 
            } else {
                printf("ACK with wrong seq_num=%u (expected=%u)\n", rseq, seq_num);
                attempt++;
            }
        } else if (strncmp(ack_buffer, "NACK=", 5) == 0) {
            uint32_t rseq = (uint32_t)atoi(ack_buffer+5);
            if (rseq == seq_num) {
                printf("NACK for seq_num=%u. Resending...\n", seq_num);
                attempt++;
            } else {
                printf("NACK with wrong seq_num. attempt=%d\n", attempt);
                attempt++;
            }
        } else {
            printf("Unknown response '%s'. Retrying...\n", ack_buffer);
            attempt++;
        }
    }

    printf("Failed to get ACK after %d attempts for seq=%u. Aborting.\n", MAX_RETRIES, seq_num);
    
    return -1;
}

int main() {
    InitWinsock();

    SOCKET socketS = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketS == INVALID_SOCKET) {
        printf("Error creating socket.\n");
        pause_and_exit();
        return 1;
    }

    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_port = htons(LOCAL_PORT);
    InetPton(AF_INET, _T(LOCAL_IP), &local.sin_addr.s_addr);

    if (bind(socketS, (sockaddr*)&local, sizeof(local)) != 0) {
        printf("Binding error!\n");
        closesocket(socketS);
        WSACleanup();
        pause_and_exit();
        return 1;
    }

    set_socket_timeout(socketS, TIMEOUT_MS);

    struct sockaddr_in addrDest;
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &addrDest.sin_addr.s_addr);

    // User input for window size
    int window_size = 0;
    printf("Enter sending window size: ");
    scanf("%d", &window_size);
    if (window_size <= 0) {
        printf("Invalid window size.\n");
        closesocket(socketS);
        WSACleanup();
        pause_and_exit();
        return 1;
    }

    const char* filename = "test.jpg";
    FILE* f = fopen(filename, "rb");
    if (!f) {
        printf("Error opening file: %s\n", filename);
        closesocket(socketS);
        WSACleanup();
        pause_and_exit();
        return 1;
    }

    // Compute file size
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Compute file hash
    char filehash[128] = {0};
    if (compute_file_hash(filename, filehash, sizeof(filehash)) != 0) {
        printf("Error computing file hash.\n");
        fclose(f);
        closesocket(socketS);
        WSACleanup();
        pause_and_exit();
        return 1;
    }

    uint32_t seq_num = 0;

    {
        char payload[512];
        snprintf(payload, sizeof(payload), "%s", filename);
        if (send_packet_and_wait_ack(socketS, &addrDest, TYPE_NAME, seq_num++, (const unsigned char*)payload, strlen(payload)) != 0) {
            // error
            closesocket(socketS);
            WSACleanup();
            pause_and_exit();
            return 1;
        }
    }

        // Send WINDOW SIZE
    {
        char payload[512];
        snprintf(payload, sizeof(payload), "%ld", window_size);
        if (send_packet_and_wait_ack(socketS, &addrDest, TYPE_WIND, seq_num++, (const unsigned char*)payload, strlen(payload)) != 0) {
            // error
            closesocket(socketS);
            WSACleanup();
            pause_and_exit();
            return 1;
        }
    }
    // // Send SIZE
    {
        char payload[512];
        snprintf(payload, sizeof(payload), "%ld", filesize);
        if (send_packet_and_wait_ack(socketS, &addrDest, TYPE_SIZE, seq_num++, (const unsigned char*)payload, strlen(payload)) != 0) {
            // error
            closesocket(socketS);
            WSACleanup();
            pause_and_exit();
            return 1;
        }
    }

    // Send HASH
    {
        char payload[512];
        snprintf(payload, sizeof(payload), "%s", filehash);
        if (send_packet_and_wait_ack(socketS, &addrDest, TYPE_HASH, seq_num++, (const unsigned char*)payload, strlen(payload)) != 0) {
            // error
            closesocket(socketS);
            WSACleanup();
            pause_and_exit();
            return 1;
        }
    }

    // START
    {

        if (send_packet_and_wait_ack(socketS, &addrDest, TYPE_STAR, seq_num++, NULL, 0) != 0) {
            // error
            closesocket(socketS);
            WSACleanup();
            pause_and_exit();
            return 1;
        }
    }

    //DATA
    WindowPacket *window = (WindowPacket*)malloc(sizeof(WindowPacket)*window_size);
    memset(window, 0, sizeof(WindowPacket)*window_size);

    uint32_t base = seq_num;
    uint32_t next_seq = seq_num;
    bool eof_reached = false; // EOF - end of file

    while (1) {
        // Send new packets if window is not full and not EOF
        while (!eof_reached && next_seq < base + window_size) {
            unsigned char data_buffer[MAX_DATA_LEN];
            size_t bytes_read = fread(data_buffer+4, 1, MAX_DATA_LEN-4 /*4 bytes offset*/, f);
            if (bytes_read == 0) {
                // no more data
                eof_reached = true;
                break;
            }
            int packet_len = (int)(12 + 4 + bytes_read);    
            uint32_t offset = next_seq - (seq_num); 
            static uint32_t total_offset = 0;
            uint32_t net_offset = htonl(total_offset);
            total_offset += (uint32_t)bytes_read;
            memcpy(data_buffer, &net_offset, 4);

            unsigned char packet[BUFFERS_LEN];
            memcpy(packet, TYPE_DATA, 4);
            uint32_t net_seq = htonl(next_seq);
            memcpy(packet+4, &net_seq, 4);
            memset(packet+8, 0, 4);
            memcpy(packet+12, data_buffer, bytes_read+4);


            uint32_t crc = compute_crc32((const char*)packet, size_t(packet_len));
            uint32_t net_crc = htonl(crc);
            memcpy(packet+8, &net_crc, 4);
            WindowPacket *wp = &window[next_seq % window_size];
            wp->seq_num = next_seq;
            memcpy(wp->packet, packet, packet_len);
            wp->packet_len = packet_len;
            wp->acked = false;
            wp->retries = 0;
            wp->send_time = GetTickCount();

            sendto(socketS, (const char*)packet, packet_len, 0, (sockaddr*)&addrDest, sizeof(addrDest));
            next_seq++;
        }

        if (eof_reached && base == next_seq) {
            if (send_packet_and_wait_ack(socketS, &addrDest, TYPE_STOP, next_seq, NULL, 0) != 0) {
                // error
                closesocket(socketS);
                WSACleanup();
                pause_and_exit();
                return 1;
            }
            break;
        }

        // Wait for ACKs and handle retransmissions
        {
            char ack_buffer[BUFFERS_LEN];
            struct sockaddr_in from;
            int fromlen = sizeof(from);
            int received = recvfrom(socketS, ack_buffer, BUFFERS_LEN, 0, (sockaddr*)&from, &fromlen);

            DWORD current_time = GetTickCount();

            // Check timeouts
            for (uint32_t i = base; i < next_seq; i++) {
                WindowPacket *wp = &window[i % window_size];
                if (!wp->acked && (current_time - wp->send_time > TIMEOUT_MS)) {
                    if (wp->retries < MAX_RETRIES) {
                        sendto(socketS, (const char*)wp->packet, wp->packet_len, 0, (sockaddr*)&addrDest, sizeof(addrDest));
                        wp->send_time = current_time;
                        wp->retries++;
                        printf("Retransmitting seq=%u (retry %d)\n", wp->seq_num, wp->retries);
                    } else {
                        printf("Max retries reached for seq=%u. Aborting.\n", wp->seq_num);
                        fclose(f);
                        free(window);
                        closesocket(socketS);
                        WSACleanup();
                        pause_and_exit();
                        return 1;
                    }
                }
            }

            if (received != SOCKET_ERROR) {
                if (received < BUFFERS_LEN) {
                    ack_buffer[received] = '\0';
                } else {
                    ack_buffer[BUFFERS_LEN-1] = '\0';
                }

                if (strncmp(ack_buffer, "ACK=",4)==0) {
                    uint32_t net_seq_ack;
                    memcpy(&net_seq_ack, ack_buffer + 4, 4);
                    uint32_t rseq = ntohl(net_seq_ack);

                    uint32_t net_crc;
                    memcpy(&net_crc, ack_buffer + 8, 4);
                    uint32_t r_crc = ntohl(net_crc);
                    uint32_t calc_crc = compute_crc32((const char*)ack_buffer, 8);
                    printf("ACK received for seq=%u, retransmitting.\n", rseq);
                    printf("r_crc=%zu,calc_crc=%zu\n",r_crc, calc_crc);
                    if (rseq < next_seq && calc_crc == r_crc) {
                        // Mark packet as acked
                        WindowPacket *wp = &window[rseq % window_size];
                        if (!wp->acked) {
                            wp->acked = true;
                            // Slide base if needed
                            while (base < next_seq && window[base % window_size].acked) {
                                base++;
                            }
                        }
                    } else {
                        // Could be ACK for STOP or other control packets if they appear again
                    }
                } else if (strncmp(ack_buffer, "NACK=",5)==0) {
                    uint32_t rseq = (uint32_t)atoi(ack_buffer+5);
                    // Retransmit that packet immediately
                    if (rseq >= seq_num && rseq < next_seq) {
                        WindowPacket *wp = &window[rseq % window_size];
                        if (wp->retries < MAX_RETRIES) {
                            sendto(socketS, (const char*)wp->packet, wp->packet_len, 0, (sockaddr*)&addrDest, sizeof(addrDest));
                            wp->send_time = GetTickCount();
                            wp->retries++;
                            printf("NACK received for seq=%u, retransmitting.\n", rseq);
                        } else {
                            printf("Max retries reached for seq=%u. Aborting.\n", rseq);
                            fclose(f);
                            free(window);
                            closesocket(socketS);
                            WSACleanup();
                            pause_and_exit();
                            return 1;
                        }
                    }
                } else {
                    // Unknown response, ignore
                }
            }
        }
    }

    fclose(f);
    free(window);
    closesocket(socketS);
    WSACleanup();
    printf("File transmission completed.\n");
    pause_and_exit();
    return 0;
}

#define _WIN32_WINNT 0x0600
#pragma comment(lib, "ws2_32.lib")
#include "stdafx.h"
#include <winsock2.h>
#include "ws2tcpip.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "CRC32.h"
#include "SHA256.h"

#define TARGET_IP   "127.0.0.3"
#define LOCAL_IP    "127.0.0.2"

#define TARGET_PORT 15001
#define LOCAL_PORT  14001

#define BUFFERS_LEN 1024
#define PACKET_HEADER_SIZE 12 

#define MAX_RECV_WINDOW 256

// Packet types
#define TYPE_NAME "NAME"
#define TYPE_WIND "W_SZ"
#define TYPE_SIZE "SIZE"
#define TYPE_HASH "HASH"
#define TYPE_STAR "STAR"
#define TYPE_DATA "DATA"
#define TYPE_STOP "STOP"

static unsigned char **recv_buffer = NULL;  // Array of pointers to data
static bool *received_flags = NULL;
static uint32_t *seq_nums = NULL;
static size_t *data_lens = NULL;

static int window_size = 0;  // Actual dynamic window size at run time

/**
 * Compute file hash (SHA256)
 */
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

void pause_and_exit() {
    system("pause"); 
}

/**
 * Frees and nullifies any previously allocated arrays for the receiver window.
 */
void free_recv_arrays() {
    if (recv_buffer) {
        for (int i = 0; i < window_size; i++) {
            if (recv_buffer[i]) {
                free(recv_buffer[i]);
                recv_buffer[i] = NULL;
            }
        }
        free(recv_buffer);
        recv_buffer = NULL;
    }
    if (received_flags) {
        free(received_flags);
        received_flags = NULL;
    }
    if (seq_nums) {
        free(seq_nums);
        seq_nums = NULL;
    }
    if (data_lens) {
        free(data_lens);
        data_lens = NULL;
    }
}

/**
 * Allocates and initializes arrays for the specified window size.
 */
bool allocate_recv_arrays(int new_window_size) {
    // First, free any existing arrays
    free_recv_arrays();

    // Allocate arrays
    recv_buffer = (unsigned char**)malloc(sizeof(unsigned char*) * new_window_size);
    received_flags = (bool*)malloc(sizeof(bool) * new_window_size);
    seq_nums = (uint32_t*)malloc(sizeof(uint32_t) * new_window_size);
    data_lens = (size_t*)malloc(sizeof(size_t) * new_window_size);

    if (!recv_buffer || !received_flags || !seq_nums || !data_lens) {
        printf("Error: could not allocate memory for receive arrays.\n");
        // Clean up partially allocated arrays
        free_recv_arrays();
        return false;
    }

    // Initialize arrays
    for (int i = 0; i < new_window_size; i++) {
        recv_buffer[i] = NULL;
        received_flags[i] = false;
        seq_nums[i] = 0;
        data_lens[i] = 0;
    }

    // If everything is OK, update window_size
    window_size = new_window_size;
    return true;
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET socketS = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketS == INVALID_SOCKET) {
        printf("Error creating socket.\n");
        return 1;
    }

    struct sockaddr_in local;
    local.sin_family = AF_INET;
    local.sin_port = htons(LOCAL_PORT);
    InetPton(AF_INET, _T(LOCAL_IP), &local.sin_addr.s_addr);

    if (bind(socketS, (struct sockaddr*)&local, sizeof(local)) != 0) {
        printf("Binding error!\n");
        closesocket(socketS);
        WSACleanup();
        return 1;
    }

    printf("Receiver waiting for datagrams on %s:%d...\n", LOCAL_IP, LOCAL_PORT);

    char filename[256] = {0};
    long expected_size = 0;
    char expected_hash[128] = {0};
    FILE* f = NULL;
    bool started = false;
    bool done = false;
    uint32_t expected_seq_num = 0;
    window_size = 0; 

    recv_buffer = NULL;
    received_flags = NULL;
    seq_nums = NULL;
    data_lens = NULL;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &dest.sin_addr.s_addr);
    int destlen = sizeof(dest);

    struct sockaddr_in from;
    from.sin_family = AF_INET;
    from.sin_port = htons(TARGET_PORT);
    int fromlen = sizeof(from);

    while(!done) {
        char buffer_rx[BUFFERS_LEN];
        int received = recvfrom(socketS, buffer_rx, BUFFERS_LEN, 0, (sockaddr*)&from, &fromlen);
        if (received == SOCKET_ERROR) {
            continue;
        }

        if (received < PACKET_HEADER_SIZE) {
            printf("Packet too short, ignoring.\n");
            continue;
        }

        char type[5];
        memcpy(type, buffer_rx, 4);
        type[4] = '\0';

        uint32_t net_seq;
        memcpy(&net_seq, buffer_rx + 4, 4);
        uint32_t seq_num = ntohl(net_seq);

        uint32_t net_crc;
        memcpy(&net_crc, buffer_rx + 8, 4);
        uint32_t pkt_crc = ntohl(net_crc);

        unsigned char* payload_data = (unsigned char*)(buffer_rx + PACKET_HEADER_SIZE);
        int payload_len = received - PACKET_HEADER_SIZE;

      
        memset(buffer_rx+8, 0, 4);
        uint32_t calc_crc = compute_crc32((const char*)buffer_rx, size_t(received));
        if (calc_crc != pkt_crc) {
            printf("CRC error for seq=%u, type=%s. Sending NACK.\n", seq_num, type);
            char resp_msg[128];
            snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
            continue;
        }
        char resp_msg[128];

        // Process the packet types
        if (strcmp(type, TYPE_NAME) == 0) {
            // Check seq
            if (seq_num > expected_seq_num) {
                printf("Unexpected seq_num for NAME. Got %u, expected %u. NACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            } else if (seq_num < expected_seq_num) {
                printf("Already received seq_num. Got %u, expected %u. ACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            // Payload check
            if (payload_len <= 0 || payload_len >= (int)sizeof(filename)) {
                printf("Invalid NAME payload. NACK.\n");
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            memcpy(filename, payload_data, payload_len);
            filename[payload_len] = '\0';

            if (f) {
                fclose(f);
                f = NULL;
            }
            char newfilename[512];
            snprintf(newfilename, sizeof(newfilename), "Received_%s", filename);
            f = fopen(newfilename, "wb");
            if (!f) {
                printf("Error creating file: %s\n", newfilename);
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }
            printf("Receiving file: %s\n", filename);

            expected_seq_num++;
            snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);

        } else if (strcmp(type, TYPE_WIND) == 0) {
            // This sets the receiving window size
            // Check seq
            if (seq_num > expected_seq_num) {
                printf("Unexpected seq_num for WINDOW SIZE. Got %u, expected %u. NACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            } else if (seq_num < expected_seq_num) {
                printf("Already received seq_num. Got %u, expected %u. ACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            char size_w_sz[256];
            if (payload_len <= 0 || payload_len >= (int)sizeof(size_w_sz)) {
                printf("Invalid WINDOW SIZE payload. NACK.\n");
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }
            memcpy(size_w_sz, payload_data, payload_len);
            size_w_sz[payload_len] = '\0';

            int new_window_size = atoi(size_w_sz);
            if (new_window_size <= 0 || new_window_size > MAX_RECV_WINDOW) {
                printf("Received invalid or out-of-range window size: %d. NACK.\n", new_window_size);
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            printf("Received request to set window size to %d\n", new_window_size);

            // Allocate new arrays
            if (!allocate_recv_arrays(new_window_size)) {
                // If allocation failed, we must NACK
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            expected_seq_num++;
            snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);

        } else if (strcmp(type, TYPE_SIZE) == 0) {
            if (seq_num > expected_seq_num) {
                printf("Unexpected seq_num for SIZE. Got %u, expected %u. NACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            } else if (seq_num < expected_seq_num) {
                printf("Already received seq_num. Got %u, expected %u. ACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            char size_str[256];
            if (payload_len <= 0 || payload_len >= (int)sizeof(size_str)) {
                printf("Invalid SIZE payload. NACK.\n");
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }
            memcpy(size_str, payload_data, payload_len);
            size_str[payload_len] = '\0';
            expected_size = atol(size_str);
            printf("File size: %ld bytes\n", expected_size);

            expected_seq_num++;
            snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);

        } else if (strcmp(type, TYPE_HASH) == 0) {
            if (seq_num > expected_seq_num) {
                printf("Unexpected seq_num for HASH. NACK.\n");
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            } else if (seq_num < expected_seq_num) {
                printf("Already received seq_num. Got %u, expected %u. ACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            if (payload_len <= 0 || payload_len >= (int)sizeof(expected_hash)) {
                printf("Invalid HASH payload. NACK.\n");
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }
            memcpy(expected_hash, payload_data, payload_len);
            expected_hash[payload_len] = '\0';
            printf("Expected file hash: %s\n", expected_hash);

            expected_seq_num++;
            snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);

        } else if (strcmp(type, TYPE_STAR) == 0) {
            // START packet
            if (seq_num > expected_seq_num) {
                printf("Unexpected seq_num for START. NACK.\n");
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            } else if (seq_num < expected_seq_num) {
                printf("Already received seq_num. Got %u, expected %u. ACK.\n", seq_num, expected_seq_num);
                snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }
            started = true;
            printf("Start receiving data...\n");

            expected_seq_num++;
            snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);

        } else if (strcmp(type, TYPE_DATA) == 0) {
            if (!started) {
                // Data before START
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            if (window_size <= 0 || !recv_buffer) {
                printf("DATA received but window_size not set or arrays not allocated!\n");
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            if (payload_len < 4) {
                snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
                sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
                continue;
            }

            // Check if seq_num is in the receiving window
            printf("type=%s,seq_num=%u \n",type,seq_num);
            printf("expected_seq_num=%u,(expected_seq_num + window_size)=%u \n",expected_seq_num,(expected_seq_num + window_size));
            if (seq_num >= expected_seq_num && seq_num < (expected_seq_num + window_size)) {
                int idx = seq_num % window_size;
                if (!received_flags[idx]) {
                    // Store the packet
                    if (recv_buffer[idx]) {
                        free(recv_buffer[idx]);
                        recv_buffer[idx] = NULL;
                    }
                    recv_buffer[idx] = (unsigned char*)malloc(payload_len);
                    memcpy(recv_buffer[idx], payload_data, payload_len);
                    data_lens[idx] = payload_len;
                    seq_nums[idx] = seq_num;
                    received_flags[idx] = true;
                }
                // ACK
                char resp_msg[12];
                memset(resp_msg, 0, sizeof(resp_msg));
                snprintf(resp_msg, sizeof(resp_msg), "ACK=");
                uint32_t net_seq_num = htonl(seq_num);
                memcpy(resp_msg + 4, &net_seq_num, 4);
                
                uint32_t resp_msg_crc = compute_crc32((const char*)resp_msg, 8);
                uint32_t net_resp_msg_crc = htonl(resp_msg_crc);
                memcpy(resp_msg + 8, &net_resp_msg_crc, 4);
                sendto(socketS, resp_msg, 12, 0, (struct sockaddr*)&dest, destlen);

                while (received_flags[expected_seq_num % window_size] &&
                       seq_nums[expected_seq_num % window_size] == expected_seq_num) 
                {
                    int widx = expected_seq_num % window_size;
                    unsigned char* p = recv_buffer[widx];
                    int len = (int)data_lens[widx];

                    if (len > 4 && f) {
                        uint32_t net_offset;
                        memcpy(&net_offset, p, 4);
                        uint32_t offset = ntohl(net_offset);

                        fseek(f, offset, SEEK_SET);
                        fwrite(p + 4, 1, len - 4, f);
                        printf("offset=%u", offset);
                    }
                    else {
                        printf("len=%u,f=%n ", len,f);    
                    }

                    free(recv_buffer[widx]);
                    recv_buffer[widx] = NULL;
                    received_flags[widx] = false;
                    expected_seq_num++;
                }

            } else if (seq_num <= expected_seq_num) {
                char resp_msg[12];
                memset(resp_msg, 0, sizeof(resp_msg));
                snprintf(resp_msg, sizeof(resp_msg), "ACK=");
                uint32_t net_seq_num = htonl(seq_num);
                memcpy(resp_msg + 4, &net_seq_num, 4);
                
                uint32_t resp_msg_crc = compute_crc32((const char*)resp_msg, 8);
                uint32_t net_resp_msg_crc = htonl(resp_msg_crc);
                memcpy(resp_msg + 8, &net_resp_msg_crc, 4);
                sendto(socketS, resp_msg, 12, 0, (struct sockaddr*)&dest, destlen);
            }
            else{
                
                }

        } else if (strcmp(type, TYPE_STOP) == 0) {
            // STOP received
            snprintf(resp_msg, sizeof(resp_msg), "ACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);

            printf("Stop received. Checking file integrity.\n");
            if (f) {
                fclose(f);
                f = NULL;
            }

            // Compute local file hash
            char received_hash[128] = {0};
            {
                char newfilename[512];
                snprintf(newfilename, sizeof(newfilename), "Received_%s", filename);
                if (compute_file_hash(newfilename, received_hash, sizeof(received_hash)) != 0) {
                    printf("Error computing received file hash.\n");
                }
            }

            if (strcmp(expected_hash, received_hash) == 0) {
                printf("File hash matches! File received correctly.\n");
            } else {
                printf("File hash does not match! File corrupted.\n");
            }

            done = true;

        } else {
            // Unknown packet type
            snprintf(resp_msg, sizeof(resp_msg), "NACK=%u", seq_num);
            sendto(socketS, resp_msg, (int)strlen(resp_msg), 0, (struct sockaddr*)&dest, destlen);
        }
    }

    printf("Receiving finished.\n");

    // Cleanup
    free_recv_arrays();
    closesocket(socketS);
    WSACleanup();
    pause_and_exit();
    return 0;
}

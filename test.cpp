#define _WIN32_WINNT 0x0600
#pragma comment(lib, "ws2_32.lib")
#include "stdafx.h"
#include <winsock2.h>
#include "ws2tcpip.h"
#include <stdio.h>
#include <stdint.h> // для uint32_t
#include <string.h>

#define TARGET_IP   "127.0.0.1"
#define BUFFERS_LEN 1024

// Режим - отправитель
#define SENDER
//#define RECEIVER

#ifdef SENDER
#define TARGET_PORT 5555
#define LOCAL_PORT  8888
#endif

#ifdef RECEIVER
#define TARGET_PORT 8888
#define LOCAL_PORT  5555
#endif

void InitWinsock() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

int main() {
    SOCKET socketS;
    InitWinsock();

    struct sockaddr_in local;
    struct sockaddr_in addrDest;

    local.sin_family = AF_INET;
    local.sin_port = htons(LOCAL_PORT);
    local.sin_addr.s_addr = INADDR_ANY;

    socketS = socket(AF_INET, SOCK_DGRAM, 0);
    if (bind(socketS, (sockaddr*)&local, sizeof(local)) != 0) {
        printf("Binding error!\n");
        getchar(); // wait for press Enter
        return 1;
    }

#ifdef SENDER

    // Настраиваем адрес назначения
    addrDest.sin_family = AF_INET;
    addrDest.sin_port = htons(TARGET_PORT);
    InetPton(AF_INET, _T(TARGET_IP), &addrDest.sin_addr.s_addr);

    // Имя файла для отправки
    const char* filename = "test.jpg";
    // Открываем файл для чтения в двоичном режиме
    FILE* f = fopen(filename, "rb");
    if(!f) {
        printf("Error opening file: %s\n", filename);
        closesocket(socketS);
        WSACleanup();
        return 1;
    }

    // Определяем размер файла
    fseek(f, 0, SEEK_END);
    long filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char buffer_tx[BUFFERS_LEN];

    // 1) Отправляем NAME=filename
    {
        snprintf(buffer_tx, BUFFERS_LEN, "NAME=%s", filename);
        sendto(socketS, buffer_tx, (int)strlen(buffer_tx), 0, (sockaddr*)&addrDest, sizeof(addrDest));
    }

    // 2) Отправляем SIZE=filesize
    {
        snprintf(buffer_tx, BUFFERS_LEN, "SIZE=%ld", filesize);
        sendto(socketS, buffer_tx, (int)strlen(buffer_tx), 0, (sockaddr*)&addrDest, sizeof(addrDest));
    }

    // 3) Отправляем START
    {
        snprintf(buffer_tx, BUFFERS_LEN, "START");
        sendto(socketS, buffer_tx, (int)strlen(buffer_tx), 0, (sockaddr*)&addrDest, sizeof(addrDest));
    }

    // 4) Отправляем DATA пакеты
    // Формат пакета:
    // "DATA" + [4 байта смещения в бинарном виде] + [данные файла]
    // Максимум 1024 байта.
    // Из них первые 4 байта после "DATA" - смещение (uint32_t), 
    // остальное - данные файла.
    // Структура пакета:
    // buffer_tx:
    // 0..3 байт: 'D', 'A', 'T', 'A'
    // 4..7 байт: позиция (uint32_t)
    // 8..1023 байт: данные файла

    {
        unsigned char data_packet[BUFFERS_LEN];
        memcpy(data_packet, "DATA", 4); // Запишем префикс "DATA"

        const int header_size = 8; // "DATA"(4байта) + offset(4байта) = 8 байт
        // Максимум данных: 1024 - 8 = 1016 байт файла на пакет
        const int max_data_len = BUFFERS_LEN - header_size;

        uint32_t offset = 0;
        size_t bytes_read = 0;
        do {
            bytes_read = fread(data_packet + header_size, 1, max_data_len, f);
            if (bytes_read > 0) {
                // Записываем offset
                // Преобразуем в сетевой порядок байт если нужно (для совместимости)
                // В данном случае можно и не преобразовывать, но по-хорошему:
                uint32_t net_offset = htonl(offset);
                memcpy(data_packet + 4, &net_offset, 4);

                // Отправляем пакет
                int packet_size = (int)(header_size + bytes_read);
                sendto(socketS, (const char*)data_packet, packet_size, 0, (sockaddr*)&addrDest, sizeof(addrDest));

                offset += (uint32_t)bytes_read;
            }
        } while (bytes_read == max_data_len); 
        // Если мы прочитали меньше max_data_len, значит достигли конца файла.
    }

    // 5) Отправляем STOP
    {
        snprintf(buffer_tx, BUFFERS_LEN, "STOP");
        sendto(socketS, buffer_tx, (int)strlen(buffer_tx), 0, (sockaddr*)&addrDest, sizeof(addrDest));
    }

    fclose(f);
    closesocket(socketS);
    WSACleanup();

#endif // SENDER

    getchar(); // wait for press Enter
    return 0;
}

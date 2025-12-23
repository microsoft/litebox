// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define DEFAULT_PORT 12345
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    int client_fd;
    struct sockaddr_in addr;
    char recv_buf[BUFFER_SIZE];
    const char* ip_addr = "127.0.0.1";
    int port = DEFAULT_PORT;
    
    // Parse command line arguments
    if (argc > 1) {
        ip_addr = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "Invalid port number. Using default: %d\n", DEFAULT_PORT);
            port = DEFAULT_PORT;
        }
    }
    
    printf("===== TCP Client Test =====\n\n");
    
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket failed");
        return 1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    // Convert IP address string to binary form
    if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_addr);
        close(client_fd);
        return 1;
    }
    
    addr.sin_port = htons(port);
    
    printf("Client: Connecting to %s:%d...\n", ip_addr, port);
    if (connect(client_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect failed");
        close(client_fd);
        return 1;
    }
    
    printf("Client: Connected\n");
    
    const char* message = "Hello from TCP client!";
    if (send(client_fd, message, strlen(message), 0) < 0) {
        perror("send failed");
    } else {
        printf("Client: Sent '%s'\n", message);
    }
    
    // Receive response
    memset(recv_buf, 0, sizeof(recv_buf));
    ssize_t n = recv(client_fd, recv_buf, sizeof(recv_buf), 0);
    if (n < 0) {
        perror("recv failed");
    } else {
        printf("Client: Received %zd bytes: '%s'\n", n, recv_buf);
    }
    
    close(client_fd);
    
    printf("\n===== Client Test Complete =====\n");
    
    return 0;
}
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
    int server_fd, conn_fd;
    struct sockaddr_in addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char recv_buf[BUFFER_SIZE];
    int opt = 1;
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
    
    printf("===== TCP Server Test =====\n\n");
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        return 1;
    }
    
    // Allow address reuse
    // if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    //     perror("setsockopt failed");
    //     close(server_fd);
    //     return 1;
    // }
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    
    // Convert IP address string to binary form
    if (inet_pton(AF_INET, ip_addr, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip_addr);
        close(server_fd);
        return 1;
    }
    
    addr.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 1;
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        close(server_fd);
        return 1;
    }
    
    printf("Server: Listening on %s:%d...\n", ip_addr, port);
    
    conn_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (conn_fd < 0) {
        perror("accept failed");
        close(server_fd);
        return 1;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Server: Client connected from %s:%d\n", client_ip, ntohs(client_addr.sin_port));
    
    memset(recv_buf, 0, sizeof(recv_buf));
    ssize_t n = recv(conn_fd, recv_buf, sizeof(recv_buf), 0);
    if (n < 0) {
        perror("recv failed");
    } else {
        printf("Server: Received %zd bytes: '%s'\n", n, recv_buf);
    }
    
    // Send response back
    const char* response = "Hello from TCP server!";
    if (send(conn_fd, response, strlen(response), 0) < 0) {
        perror("send failed");
    } else {
        printf("Server: Sent response\n");
    }

    close(conn_fd);
    close(server_fd);
    
    printf("\n===== Server Test Complete =====\n");
    
    return 0;
}
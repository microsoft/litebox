#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <errno.h>

#define TEST_SOCKET_PATH "/tmp/test_unix_socket.sock"
#define BUFFER_SIZE 1024

// Shared data between threads
struct test_context {
    struct sockaddr_un addr;
    int ready;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

void* server_thread(void* arg) {
    struct test_context* ctx = (struct test_context*)arg;
    int server_fd, conn_fd;
    char recv_buf[BUFFER_SIZE];
    
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("server socket failed");
        return NULL;
    }
    
    if (bind(server_fd, (struct sockaddr*)&ctx->addr, sizeof(ctx->addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        return NULL;
    }
    
    if (listen(server_fd, 5) < 0) {
        perror("listen failed");
        close(server_fd);
        return NULL;
    }
    
    // Signal that server is ready
    pthread_mutex_lock(&ctx->mutex);
    ctx->ready = 1;
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->mutex);
    
    printf("Server: Waiting for connection...\n");
    conn_fd = accept(server_fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("accept failed");
        close(server_fd);
        return NULL;
    }
    
    printf("Server: Client connected\n");
    
    memset(recv_buf, 0, sizeof(recv_buf));
    ssize_t n = recv(conn_fd, recv_buf, sizeof(recv_buf), 0);
    if (n < 0) {
        perror("recv failed");
    } else {
        printf("Server: Received '%s'\n", recv_buf);
    }
    
    // Send response back
    const char* response = "Hello from server!";
    if (send(conn_fd, response, strlen(response), 0) < 0) {
        perror("send failed");
    } else {
        printf("Server: Sent response\n");
    }
    
    close(conn_fd);
    close(server_fd);
    
    return NULL;
}

void* client_thread(void* arg) {
    struct test_context* ctx = (struct test_context*)arg;
    int client_fd;
    char recv_buf[BUFFER_SIZE];
    
    // Wait for server to be ready
    pthread_mutex_lock(&ctx->mutex);
    while (!ctx->ready) {
        pthread_cond_wait(&ctx->cond, &ctx->mutex);
    }
    pthread_mutex_unlock(&ctx->mutex);
    
    // Give server a moment to call accept()
    usleep(100000);
    
    client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("client socket failed");
        return NULL;
    }
    
    printf("Client: Connecting to server...\n");
    if (connect(client_fd, (struct sockaddr*)&ctx->addr, sizeof(ctx->addr)) < 0) {
        perror("connect failed");
        close(client_fd);
        return NULL;
    }
    
    printf("Client: Connected\n");
    
    const char* message = "Hello from client!";
    if (send(client_fd, message, strlen(message), 0) < 0) {
        perror("send failed");
    } else {
        printf("Client: Sent '%s'\n", message);
    }
    
    usleep(500000);  // Wait for server to process and stop

    // Receive response
    memset(recv_buf, 0, sizeof(recv_buf));
    ssize_t n = recv(client_fd, recv_buf, sizeof(recv_buf), 0);
    if (n < 0) {
        perror("recv failed");
    } else {
        printf("Client: Received '%s'\n", recv_buf);
    }

    close(client_fd);

    return NULL;
}

int main() {
    pthread_t server_tid, client_tid;
    struct test_context ctx;
    
    printf("===== Unix Domain Socket Test =====\n\n");
    
    // Clean up any existing socket file
    unlink(TEST_SOCKET_PATH);
    
    // Initialize context
    memset(&ctx, 0, sizeof(ctx));
    ctx.addr.sun_family = AF_UNIX;
    strncpy(ctx.addr.sun_path, TEST_SOCKET_PATH, sizeof(ctx.addr.sun_path) - 1);
    ctx.ready = 0;
    pthread_mutex_init(&ctx.mutex, NULL);
    pthread_cond_init(&ctx.cond, NULL);
    
    // Create server thread
    if (pthread_create(&server_tid, NULL, server_thread, &ctx) != 0) {
        perror("Failed to create server thread");
        return 1;
    }
    
    // Create client thread
    if (pthread_create(&client_tid, NULL, client_thread, &ctx) != 0) {
        perror("Failed to create client thread");
        pthread_join(server_tid, NULL);
        return 1;
    }
    
    // Wait for both threads to complete
    pthread_join(server_tid, NULL);
    pthread_join(client_tid, NULL);
    
    // Cleanup
    pthread_mutex_destroy(&ctx.mutex);
    pthread_cond_destroy(&ctx.cond);
    unlink(TEST_SOCKET_PATH);
    
    printf("\n===== Test Complete =====\n");
    
    return 0;
}
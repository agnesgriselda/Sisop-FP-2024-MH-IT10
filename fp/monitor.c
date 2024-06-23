#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 1024

void handle_monitor_mode(int sock, const char *channel_name, const char *room_name);

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <username> -channel <channel_name> -room <room_name>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *username = argv[1];
    const char *channel_name = argv[3];
    const char *room_name = argv[4];

    int sock;
    struct sockaddr_in server;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);

    // Connect to remote server
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connect failed. Error");
        exit(EXIT_FAILURE);
    }

    // Send initial login message to server
    char login_message[BUFFER_SIZE];
    snprintf(login_message, sizeof(login_message), "LOGIN %s", username);
    if (send(sock, login_message, strlen(login_message), 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    // Send join channel message
    char join_channel_message[BUFFER_SIZE];
    snprintf(join_channel_message, sizeof(join_channel_message), "JOIN %s", channel_name);
    if (send(sock, join_channel_message, strlen(join_channel_message), 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    // Send join room message
    char join_room_message[BUFFER_SIZE];
    snprintf(join_room_message, sizeof(join_room_message), "JOIN %s", room_name);
    if (send(sock, join_room_message, strlen(join_room_message), 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    // Enter monitor mode
    handle_monitor_mode(sock, channel_name, room_name);

    close(sock);
    return 0;
}

void handle_monitor_mode(int sock, const char *channel_name, const char *room_name) {
    char message[BUFFER_SIZE], server_reply[BUFFER_SIZE];

    while (1) {
        if (send(sock, "SEE CHAT", strlen("SEE CHAT"), 0) < 0) {
            perror("Send failed");
            break;
        }

        int recv_size = recv(sock, server_reply, BUFFER_SIZE, 0);
        if (recv_size < 0) {
            perror("Recv failed");
            break;
        }
        server_reply[recv_size] = '\0'; // Null-terminate the received string

        printf("%s\n", server_reply);

        // Check for exit command from the user
        printf("[%s/%s/%s] ", getenv("USER"), channel_name, room_name);
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0; // Remove newline character

        if (strcmp(message, "EXIT") == 0) {
            break;
        }

        sleep(2); // Sleep for a while before checking for new messages
    }
}

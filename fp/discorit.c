#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BUFFER_SIZE 1024
#define USERS_FILE "/home/agnesgriselda/fp/DiscorIT/users.csv"

typedef struct {
    int id_user;
    char name[50];
    char password[256];
    char global_role[10];
} User;

void handle_interactive_mode(int sock, const char *username);
void encrypt_password(const char *password, char *encrypted_password);
int verify_password(const char *password, const char *encrypted_password);
int register_user(const char *username, const char *password);
int login_user(const char *username, const char *password);

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <command> <username> -p <password>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "REGISTER") == 0) {
        if (register_user(argv[2], argv[4])) {
            printf("%s berhasil register\n", argv[2]);
        } else {
            printf("%s sudah terdaftar\n", argv[2]);
        }
        return 0;
    } else if (strcmp(argv[1], "LOGIN") == 0) {
        if (login_user(argv[2], argv[4])) {
            printf("%s berhasil login\n", argv[2]);

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
            snprintf(login_message, sizeof(login_message), "LOGIN %s", argv[2]);
            if (send(sock, login_message, strlen(login_message), 0) < 0) {
                perror("Send failed");
                exit(EXIT_FAILURE);
            }

            // Enter interactive mode
            handle_interactive_mode(sock, argv[2]);

            close(sock);
        } else {
            printf("Username atau password salah\n");
        }
        return 0;
    } else {
        fprintf(stderr, "Invalid command\n");
        exit(EXIT_FAILURE);
    }
}

void handle_interactive_mode(int sock, const char *username) {
    char message[BUFFER_SIZE], server_reply[BUFFER_SIZE];

    while (1) {
        printf("[%s] ", username);
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0; // Remove newline character

        if (strcmp(message, "EXIT") == 0) {
            break;
        }

        if (send(sock, message, strlen(message), 0) < 0) {
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
    }
}

void encrypt_password(const char *password, char *encrypted_password) {
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(hash), hash);

    memcpy(encrypted_password, salt, sizeof(salt));
    memcpy(encrypted_password + sizeof(salt), hash, sizeof(hash));
}

int verify_password(const char *password, const char *encrypted_password) {
    unsigned char salt[16];
    memcpy(salt, encrypted_password, sizeof(salt));

    unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(hash), hash);

    return memcmp(hash, encrypted_password + sizeof(salt), sizeof(hash)) == 0;
}

int register_user(const char *username, const char *password) {
    char line[256];
    char stored_username[50];
    FILE *file = fopen(USERS_FILE, "a+");
    if (file == NULL) {
        perror("Failed to open users file");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%*s,%*s", stored_username);
        if (strcmp(username, stored_username) == 0) {
            fclose(file);
            return 0;
        }
    }

    char encrypted_password[256];
    encrypt_password(password, encrypted_password);

    User new_user;
    new_user.id_user = 1; // This should be incremented based on the existing users
    strcpy(new_user.name, username);
    strcpy(new_user.password, encrypted_password);

    fseek(file, 0, SEEK_END);
    if (ftell(file) == 0) {
        strcpy(new_user.global_role, "ROOT");
    } else {
        strcpy(new_user.global_role, "USER");
    }

    fprintf(file, "%d,%s,%s,%s\n", new_user.id_user, new_user.name, new_user.password, new_user.global_role);
    fclose(file);
    return 1;
}

int login_user(const char *username, const char *password) {
    char line[256];
    char stored_username[50], stored_password[256];
    FILE *file = fopen(USERS_FILE, "r");
    if (file == NULL) {
        perror("Failed to open users file");
        exit(EXIT_FAILURE);
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%[^,],%*s", stored_username, stored_password);
        if (strcmp(username, stored_username) == 0) {
            fclose(file);
            return verify_password(password, stored_password);
        }
    }

    fclose(file);
    return 0;
}

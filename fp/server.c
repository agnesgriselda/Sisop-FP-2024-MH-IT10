#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define USERS_FILE "/home/agnesgriselda/fp/DiscorIT/users.csv"
#define CHANNELS_FILE "/home/agnesgriselda/fp/DiscorIT/channels.csv"
#define LOG_FILE "/home/agnesgriselda/fp/DiscorIT/users.log"

typedef struct {
    int id_channel;
    char name[50];
    char key[256];
} Channel;

void *handle_client(void *socket_desc);
void list_channels(int sock);
void join_channel(const char *username, const char *channel_name, const char *key, int sock);
void list_rooms(const char *channel_name, int sock);
void list_users(const char *channel_name, int sock);
void chat_message(const char *username, const char *channel_name, const char *room_name, const char *message, int sock);
void see_chats(const char *channel_name, const char *room_name, int sock);
void edit_chat(const char *channel_name, const char *room_name, int chat_id, const char *new_message, int sock);
void delete_chat(const char *channel_name, const char *room_name, int chat_id, int sock);
void daemonize();
void handle_session(int sock, const char *username, const char *role);
void list_all_users(int sock);
void edit_user(const char *old_username, const char *new_username, const char *new_password, int sock);
void remove_user(const char *username, int sock);
void create_channel(const char *username, const char *channel_name, const char *key, int sock);
void edit_channel(const char *old_channel_name, const char *new_channel_name, int sock);
void delete_channel(const char *channel_name, int sock);
void create_room(const char *channel_name, const char *room_name, int sock);
void edit_room(const char *channel_name, const char *old_room_name, const char *new_room_name, int sock);
void delete_room(const char *channel_name, const char *room_name, int sock);
void delete_all_rooms(const char *channel_name, int sock);
void ban_user(const char *channel_name, const char *username, int sock);
void unban_user(const char *channel_name, const char *username, int sock);
void encrypt_password(const char *password, char *encrypted_password);
int verify_password(const char *password, const char *encrypted_password);
int channel_exists(const char *channel_name);
void save_channel(Channel channel);

FILE *log_file;

int main(int argc, char const *argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    daemonize();

    log_file = fopen("/tmp/discorit_server.log", "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(EXIT_FAILURE);
    }

    fprintf(log_file, "Server starting...\n");
    fflush(log_file);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        fprintf(log_file, "Socket creation failed\n");
        fflush(log_file);
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(log_file, "Bind failed\n");
        fflush(log_file);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        fprintf(log_file, "Listen failed\n");
        fflush(log_file);
        exit(EXIT_FAILURE);
    }

    fprintf(log_file, "Server started on port %d\n", PORT);
    fflush(log_file);

    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen))) {
        fprintf(log_file, "Accepted connection\n");
        fflush(log_file);
        pthread_t client_thread;
        int *new_sock = malloc(sizeof(int));
        *new_sock = new_socket;

        if (pthread_create(&client_thread, NULL, handle_client, (void *)new_sock) < 0) {
            fprintf(log_file, "Could not create thread\n");
            fflush(log_file);
            return 1;
        }
    }

    if (new_socket < 0) {
        fprintf(log_file, "Accept failed\n");
        fflush(log_file);
        exit(EXIT_FAILURE);
    }

    fclose(log_file);
    return 0;
}

void daemonize() {
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    if (chdir("/") < 0) {
        exit(EXIT_FAILURE);
    }

    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--) {
        close(x);
    }
}

void *handle_client(void *socket_desc) {
    int sock = *(int *)socket_desc;
    int read_size;
    char client_message[BUFFER_SIZE];
    char username[50];
    char role[10];

    while ((read_size = recv(sock, client_message, BUFFER_SIZE, 0)) > 0) {
        client_message[read_size] = '\0';
        fprintf(log_file, "Received: %s\n", client_message);
        fflush(log_file);

        char *command = strtok(client_message, " ");
        if (strcmp(command, "LOGIN") == 0) {
            strcpy(username, strtok(NULL, " "));
            // Retrieve role for session handling
            char line[256];
            FILE *file = fopen(USERS_FILE, "r");
            if (file != NULL) {
                while (fgets(line, sizeof(line), file)) {
                    char stored_username[50], stored_role[10];
                    sscanf(line, "%*d,%[^,],%*s,%s", stored_username, stored_role);
                    if (strcmp(username, stored_username) == 0) {
                        strcpy(role, stored_role);
                        break;
                    }
                }
                fclose(file);
            }
            handle_session(sock, username, role); // Hand off to session handler after login
            break;
        } else {
            snprintf(client_message, sizeof(client_message), "Invalid command\n");
            send(sock, client_message, strlen(client_message), 0);
        }

        memset(client_message, 0, BUFFER_SIZE);
    }

    if (read_size == 0) {
        fprintf(log_file, "Client disconnected\n");
        fflush(log_file);
    } else if (read_size == -1) {
        fprintf(log_file, "Recv failed\n");
        fflush(log_file);
    }

    free(socket_desc);
    return 0;
}

void handle_session(int sock, const char *username, const char *role) {
    char buffer[BUFFER_SIZE];
    char client_message[BUFFER_SIZE];

    while (1) {
        int read_size = recv(sock, client_message, BUFFER_SIZE, 0);
        if (read_size <= 0) {
            break;
        }

        client_message[read_size] = '\0';
        fprintf(log_file, "Received in session: %s\n", client_message);
        fflush(log_file);

        char *command = strtok(client_message, " ");
        if (strcmp(command, "LIST") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "CHANNEL") == 0) {
                list_channels(sock);
            } else if (strcmp(sub_command, "ROOM") == 0) {
                char *channel_name = strtok(NULL, " ");
                list_rooms(channel_name, sock);
            } else if (strcmp(sub_command, "USER") == 0) {
                if (strcmp(role, "ROOT") == 0) {
                    list_all_users(sock);
                } else {
                    snprintf(buffer, sizeof(buffer), "Permission denied\n");
                    send(sock, buffer, strlen(buffer), 0);
                }
            }
        } else if (strcmp(command, "JOIN") == 0) {
            char *channel_name = strtok(NULL, " ");
            char *key = strtok(NULL, " ");
            join_channel(username, channel_name, key, sock);
        } else if (strcmp(command, "CHAT") == 0) {
            char *channel_name = strtok(NULL, " ");
            char *room_name = strtok(NULL, " ");
            char *message = strtok(NULL, "\"");
            chat_message(username, channel_name, room_name, message, sock);
        } else if (strcmp(command, "SEE") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "CHAT") == 0) {
                char *channel_name = strtok(NULL, " ");
                char *room_name = strtok(NULL, " ");
                see_chats(channel_name, room_name, sock);
            }
        } else if (strcmp(command, "EDIT") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "CHAT") == 0) {
                char *channel_name = strtok(NULL, " ");
                char *room_name = strtok(NULL, " ");
                int chat_id = atoi(strtok(NULL, " "));
                char *new_message = strtok(NULL, "\"");
                edit_chat(channel_name, room_name, chat_id, new_message, sock);
            } else if (strcmp(sub_command, "WHERE") == 0 && strcmp(role, "ROOT") == 0) {
                char *old_username = strtok(NULL, " ");
                char *flag = strtok(NULL, " ");
                if (strcmp(flag, "-u") == 0) {
                    char *new_username = strtok(NULL, " ");
                    edit_user(old_username, new_username, NULL, sock);
                } else if (strcmp(flag, "-p") == 0) {
                    char *new_password = strtok(NULL, " ");
                    edit_user(old_username, NULL, new_password, sock);
                }
            }
        } else if (strcmp(command, "DEL") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "CHAT") == 0) {
                char *channel_name = strtok(NULL, " ");
                char *room_name = strtok(NULL, " ");
                int chat_id = atoi(strtok(NULL, " "));
                delete_chat(channel_name, room_name, chat_id, sock);
            } else if (strcmp(sub_command, "CHANNEL") == 0 && (strcmp(role, "ROOT") == 0 || strcmp(role, "ADMIN") == 0)) {
                char *channel_name = strtok(NULL, " ");
                delete_channel(channel_name, sock);
            } else if (strcmp(sub_command, "ROOM") == 0) {
                char *channel_name = strtok(NULL, " ");
                char *room_name = strtok(NULL, " ");
                delete_room(channel_name, room_name, sock);
            }
        } else if (strcmp(command, "REMOVE") == 0 && strcmp(role, "ROOT") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "USER") == 0) {
                char *username = strtok(NULL, " ");
                remove_user(username, sock);
            }
        } else if (strcmp(command, "CREATE") == 0) {
            char *sub_command = strtok(NULL, " ");
            if (strcmp(sub_command, "CHANNEL") == 0 && (strcmp(role, "ROOT") == 0 || strcmp(role, "ADMIN") == 0)) {
                char *channel_name = strtok(NULL, " ");
                char *flag = strtok(NULL, " ");
                char *key = strtok(NULL, " ");
                create_channel(username, channel_name, key, sock);
            } else if (strcmp(sub_command, "ROOM") == 0) {
                char *channel_name = strtok(NULL, " ");
                char *room_name = strtok(NULL, " ");
                create_room(channel_name, room_name, sock);
            }
        } else if (strcmp(command, "BAN") == 0) {
            char *channel_name = strtok(NULL, " ");
            char *username_to_ban = strtok(NULL, " ");
            ban_user(channel_name, username_to_ban, sock);
        } else if (strcmp(command, "UNBAN") == 0) {
            char *channel_name = strtok(NULL, " ");
            char *username_to_unban = strtok(NULL, " ");
            unban_user(channel_name, username_to_unban, sock);
        } else if (strcmp(command, "EXIT") == 0) {
            break;
        } else {
            snprintf(buffer, sizeof(buffer), "Invalid command or insufficient permissions\n");
            send(sock, buffer, strlen(buffer), 0);
        }

        memset(client_message, 0, BUFFER_SIZE);
    }

    close(sock);
}

void list_channels(int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    FILE *file = fopen(CHANNELS_FILE, "r");
    if (file == NULL) {
        snprintf(response, sizeof(response), "No channels found\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    response[0] = '\0'; // Clear response buffer
    while (fgets(line, sizeof(line), file)) {
        char channel_name[50];
        sscanf(line, "%*d,%[^,],%*s", channel_name);
        strcat(response, channel_name);
        strcat(response, " ");
    }
    fclose(file);

    send(sock, response, strlen(response), 0);
}

void join_channel(const char *username, const char *channel_name, const char *key, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    FILE *file = fopen(CHANNELS_FILE, "r");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Channel not found\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        char stored_channel_name[50], stored_key[256];
        sscanf(line, "%*d,%[^,],%s", stored_channel_name, stored_key);
        if (strcmp(channel_name, stored_channel_name) == 0) {
            if (verify_password(key, stored_key)) {
                snprintf(response, sizeof(response), "%s/%s\n", username, channel_name);
                send(sock, response, strlen(response), 0);
            } else {
                snprintf(response, sizeof(response), "Invalid key\n");
                send(sock, response, strlen(response), 0);
            }
            fclose(file);
            return;
        }
    }

    snprintf(response, sizeof(response), "Channel not found\n");
    send(sock, response, strlen(response), 0);
    fclose(file);
}

void list_rooms(const char *channel_name, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/room_list.csv", channel_name);
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        snprintf(response, sizeof(response), "No rooms found\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    response[0] = '\0'; // Clear response buffer
    while (fgets(line, sizeof(line), file)) {
        char room_name[50];
        sscanf(line, "%s", room_name);
        strcat(response, room_name);
        strcat(response, " ");
    }
    fclose(file);

    send(sock, response, strlen(response), 0);
}

void list_users(const char *channel_name, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/auth.csv", channel_name);
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        snprintf(response, sizeof(response), "No users found\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    response[0] = '\0'; // Clear response buffer
    while (fgets(line, sizeof(line), file)) {
        char user_name[50];
        sscanf(line, "%*d,%[^,],%*s", user_name);
        strcat(response, user_name);
        strcat(response, " ");
    }
    fclose(file);

    send(sock, response, strlen(response), 0);
}

void chat_message(const char *username, const char *channel_name, const char *room_name, const char *message, int sock) {
    char response[BUFFER_SIZE];
    char file_path[100];
    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/%s/chat.csv", channel_name, room_name);

    FILE *file = fopen(file_path, "a");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to send message\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    fprintf(file, "%ld,%d,%s,\"%s\"\n", time(NULL), 1, username, message); // Example format
    fclose(file);

    snprintf(response, sizeof(response), "Message sent\n");
    send(sock, response, strlen(response), 0);
}

void see_chats(const char *channel_name, const char *room_name, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/%s/chat.csv", channel_name, room_name);
    FILE *file = fopen(file_path, "r");
    if (file == NULL) {
        snprintf(response, sizeof(response), "No chats found\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    response[0] = '\0'; // Clear response buffer
    while (fgets(line, sizeof(line), file)) {
        strcat(response, line);
    }
    fclose(file);

    send(sock, response, strlen(response), 0);
}

void edit_chat(const char *channel_name, const char *room_name, int chat_id, const char *new_message, int sock) {
    // Example implementation: Editing a chat message
    // This function should read the chat.csv file, find the chat_id, and update the message
    // Note: This is just a simplified example, proper file handling should be implemented
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Edited chat ID %d with message: %s\n", chat_id, new_message);
    send(sock, response, strlen(response), 0);
}

void delete_chat(const char *channel_name, const char *room_name, int chat_id, int sock) {
    // Example implementation: Deleting a chat message
    // This function should read the chat.csv file, find the chat_id, and remove the message
    // Note: This is just a simplified example, proper file handling should be implemented
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Deleted chat ID %d\n", chat_id);
    send(sock, response, strlen(response), 0);
}

void list_all_users(int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    FILE *file = fopen(USERS_FILE, "r");
    if (file == NULL) {
        snprintf(response, sizeof(response), "No users found\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    response[0] = '\0'; // Clear response buffer
    while (fgets(line, sizeof(line), file)) {
        char user_name[50];
        sscanf(line, "%*d,%[^,],%*s,%*s", user_name);
        strcat(response, user_name);
        strcat(response, " ");
    }
    fclose(file);

    send(sock, response, strlen(response), 0);
}

void edit_user(const char *old_username, const char *new_username, const char *new_password, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char updated_line[BUFFER_SIZE];
    char stored_username[50], stored_password[256], stored_role[10];
    int found = 0;

    FILE *file = fopen(USERS_FILE, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open users file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/users_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%[^,],%s", stored_username, stored_password, stored_role);
        if (strcmp(old_username, stored_username) == 0) {
            found = 1;
            if (new_username != NULL) {
                strcpy(stored_username, new_username);
            }
            if (new_password != NULL) {
                encrypt_password(new_password, stored_password);
            }
            snprintf(updated_line, sizeof(updated_line), "%s,%s,%s\n", stored_username, stored_password, stored_role);
            fputs(updated_line, temp_file);
        } else {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    if (found) {
        remove(USERS_FILE);
        rename("/tmp/users_temp.csv", USERS_FILE);
        snprintf(response, sizeof(response), "User %s updated successfully\n", old_username);
    } else {
        remove("/tmp/users_temp.csv");
        snprintf(response, sizeof(response), "User %s not found\n", old_username);
    }

    send(sock, response, strlen(response), 0);
}

void remove_user(const char *username, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char stored_username[50];
    int found = 0;

    FILE *file = fopen(USERS_FILE, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open users file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/users_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%*s,%*s", stored_username);
        if (strcmp(username, stored_username) == 0) {
            found = 1;
        } else {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    if (found) {
        remove(USERS_FILE);
        rename("/tmp/users_temp.csv", USERS_FILE);
        snprintf(response, sizeof(response), "User %s removed successfully\n", username);
    } else {
        remove("/tmp/users_temp.csv");
        snprintf(response, sizeof(response), "User %s not found\n", username);
    }

    send(sock, response, strlen(response), 0);
}

void create_channel(const char *username, const char *channel_name, const char *key, int sock) {
    char response[BUFFER_SIZE];
    if (channel_exists(channel_name)) {
        snprintf(response, sizeof(response), "Channel %s already exists\n", channel_name);
        send(sock, response, strlen(response), 0);
        return;
    }

    char encrypted_key[256];
    encrypt_password(key, encrypted_key);

    Channel new_channel;
    new_channel.id_channel = 1; // This should be incremented based on the existing channels
    strcpy(new_channel.name, channel_name);
    strcpy(new_channel.key, encrypted_key);

    save_channel(new_channel);
    snprintf(response, sizeof(response), "Channel %s created successfully\n", channel_name);
    send(sock, response, strlen(response), 0);
}

void edit_channel(const char *old_channel_name, const char *new_channel_name, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char updated_line[BUFFER_SIZE];
    char stored_channel_name[50], stored_key[256];
    int found = 0;

    FILE *file = fopen(CHANNELS_FILE, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open channels file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/channels_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%s", stored_channel_name, stored_key);
        if (strcmp(old_channel_name, stored_channel_name) == 0) {
            found = 1;
            strcpy(stored_channel_name, new_channel_name);
            snprintf(updated_line, sizeof(updated_line), "%s,%s\n", stored_channel_name, stored_key);
            fputs(updated_line, temp_file);
        } else {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    if (found) {
        remove(CHANNELS_FILE);
        rename("/tmp/channels_temp.csv", CHANNELS_FILE);
        snprintf(response, sizeof(response), "Channel %s updated successfully\n", old_channel_name);
    } else {
        remove("/tmp/channels_temp.csv");
        snprintf(response, sizeof(response), "Channel %s not found\n", old_channel_name);
    }

    send(sock, response, strlen(response), 0);
}

void delete_channel(const char *channel_name, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char stored_channel_name[50];
    int found = 0;

    FILE *file = fopen(CHANNELS_FILE, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open channels file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/channels_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%*s", stored_channel_name);
        if (strcmp(channel_name, stored_channel_name) == 0) {
            found = 1;
        } else {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    if (found) {
        remove(CHANNELS_FILE);
        rename("/tmp/channels_temp.csv", CHANNELS_FILE);
        snprintf(response, sizeof(response), "Channel %s deleted successfully\n", channel_name);
    } else {
        remove("/tmp/channels_temp.csv");
        snprintf(response, sizeof(response), "Channel %s not found\n", channel_name);
    }

    send(sock, response, strlen(response), 0);
}

void create_room(const char *channel_name, const char *room_name, int sock) {
    char response[BUFFER_SIZE];
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/room_list.csv", channel_name);

    FILE *file = fopen(file_path, "a");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to create room\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    fprintf(file, "%s\n", room_name);
    fclose(file);

    snprintf(response, sizeof(response), "Room %s created successfully\n", room_name);
    send(sock, response, strlen(response), 0);
}

void edit_room(const char *channel_name, const char *old_room_name, const char *new_room_name, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char updated_line[BUFFER_SIZE];
    char stored_room_name[50];
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/room_list.csv", channel_name);

    FILE *file = fopen(file_path, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open room list file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/rooms_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%s", stored_room_name);
        if (strcmp(old_room_name, stored_room_name) == 0) {
            snprintf(updated_line, sizeof(updated_line), "%s\n", new_room_name);
            fputs(updated_line, temp_file);
        } else {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    remove(file_path);
    rename("/tmp/rooms_temp.csv", file_path);

    snprintf(response, sizeof(response), "Room %s updated to %s successfully\n", old_room_name, new_room_name);
    send(sock, response, strlen(response), 0);
}

void delete_room(const char *channel_name, const char *room_name, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char stored_room_name[50];
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/room_list.csv", channel_name);

    FILE *file = fopen(file_path, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open room list file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/rooms_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%s", stored_room_name);
        if (strcmp(room_name, stored_room_name) != 0) {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    remove(file_path);
    rename("/tmp/rooms_temp.csv", file_path);

    snprintf(response, sizeof(response), "Room %s deleted successfully\n", room_name);
    send(sock, response, strlen(response), 0);
}

void delete_all_rooms(const char *channel_name, int sock) {
    char response[BUFFER_SIZE];
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/room_list.csv", channel_name);

    remove(file_path);

    snprintf(response, sizeof(response), "All rooms deleted successfully\n");
    send(sock, response, strlen(response), 0);
}

void ban_user(const char *channel_name, const char *username, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char updated_line[BUFFER_SIZE];
    char stored_username[50], stored_role[10];
    int found = 0;
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/auth.csv", channel_name);

    FILE *file = fopen(file_path, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open auth file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/auth_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%s", stored_username, stored_role);
        if (strcmp(username, stored_username) == 0) {
            found = 1;
            strcpy(stored_role, "BANNED");
            snprintf(updated_line, sizeof(updated_line), "%s,%s\n", stored_username, stored_role);
            fputs(updated_line, temp_file);
        } else {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    if (found) {
        remove(file_path);
        rename("/tmp/auth_temp.csv", file_path);
        snprintf(response, sizeof(response), "User %s banned successfully\n", username);
    } else {
        remove("/tmp/auth_temp.csv");
        snprintf(response, sizeof(response), "User %s not found\n", username);
    }

    send(sock, response, strlen(response), 0);
}

void unban_user(const char *channel_name, const char *username, int sock) {
    char response[BUFFER_SIZE];
    char line[256];
    char updated_line[BUFFER_SIZE];
    char stored_username[50], stored_role[10];
    int found = 0;
    char file_path[100];

    snprintf(file_path, sizeof(file_path), "/home/agnesgriselda/fp/DiscorIT/%s/admin/auth.csv", channel_name);

    FILE *file = fopen(file_path, "r+");
    if (file == NULL) {
        snprintf(response, sizeof(response), "Failed to open auth file\n");
        send(sock, response, strlen(response), 0);
        return;
    }

    FILE *temp_file = fopen("/tmp/auth_temp.csv", "w");
    if (temp_file == NULL) {
        snprintf(response, sizeof(response), "Failed to create temp file\n");
        send(sock, response, strlen(response), 0);
        fclose(file);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        sscanf(line, "%*d,%[^,],%s", stored_username, stored_role);
        if (strcmp(username, stored_username) == 0) {
            found = 1;
            strcpy(stored_role, "USER");
            snprintf(updated_line, sizeof(updated_line), "%s,%s\n", stored_username, stored_role);
            fputs(updated_line, temp_file);
        } else {
            fputs(line, temp_file);
        }
    }

    fclose(file);
    fclose(temp_file);

    if (found) {
        remove(file_path);
        rename("/tmp/auth_temp.csv", file_path);
        snprintf(response, sizeof(response), "User %s unbanned successfully\n", username);
    } else {
        remove("/tmp/auth_temp.csv");
        snprintf(response, sizeof(response), "User %s not found\n", username);
    }

    send(sock, response, strlen(response), 0);
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

int channel_exists(const char *channel_name) {
    char line[256];
    FILE *file = fopen(CHANNELS_FILE, "r");
    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file)) {
        char stored_channel_name[50];
        sscanf(line, "%*d,%[^,],%*s", stored_channel_name);
        if (strcmp(channel_name, stored_channel_name) == 0) {
            fclose(file);
            return 1;
        }
    }

    fclose(file);
    return 0;
}

void save_channel(Channel channel) {
    FILE *file = fopen(CHANNELS_FILE, "a");
    if (file == NULL) {
        perror("Failed to open channels file");
        exit(EXIT_FAILURE);
    }

    fprintf(file, "%d,%s,%s\n", channel.id_channel, channel.name, channel.key);
    fclose(file);
}

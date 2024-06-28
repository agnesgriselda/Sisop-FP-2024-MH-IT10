# Final Project Praktikum Sistem Operasi
## DiscorIT

- Agnes Zenobia __Griselda__ Petrina (5027231034)
- Muhammad __Nafi__ Firdaus (5027231045)
- __Rafika__ Az Zahra Kusumastuti (5027231050)

## Penjelasan Kode
# A. Autentifikasi User Registration and Login Program

Program ini adalah implementasi dalam bahasa C yang memungkinkan pengguna untuk mendaftar dan masuk menggunakan enkripsi kata sandi dengan OpenSSL. Program ini juga mendukung mode interaktif setelah berhasil login.

## Prasyarat
- OpenSSL library terinstal pada sistem Anda.

## Penggunaan
Program ini mendukung dua perintah utama: `REGISTER` dan `LOGIN`.

### Mendaftar Pengguna Baru
Untuk mendaftar pengguna baru, gunakan perintah berikut:
```sh
./program REGISTER <username> -p <password>
```
Contoh:
```sh
./program REGISTER alice -p password123
```

### Masuk Sebagai Pengguna
Untuk masuk sebagai pengguna yang sudah terdaftar, gunakan perintah berikut:
```sh
./program LOGIN <username> -p <password>
```
Contoh:
```sh
./program LOGIN alice -p password123
```

Jika login berhasil, program akan masuk ke mode interaktif dimana pengguna dapat berkomunikasi dengan server melalui soket.

## Penjelasan Kode

### Struktur Data User
```c
typedef struct {
    int id_user;
    char name[50];
    char password[256];
    char global_role[10];
} User;
```
Struktur `User` menyimpan informasi tentang pengguna termasuk ID, nama, kata sandi yang dienkripsi, dan peran global.

### Fungsi Utama
1. **main()**
   - Memproses argumen input dari pengguna.
   - Memanggil fungsi `register_user()` atau `login_user()` berdasarkan perintah yang diberikan.
   - Menginisiasi koneksi soket jika login berhasil dan masuk ke mode interaktif.

2. **register_user()**
   - Memeriksa apakah pengguna sudah terdaftar dengan membaca file `users.csv`.
   - Jika belum terdaftar, mengenkripsi kata sandi dan menyimpan data pengguna baru ke file.

3. **login_user()**
   - Memeriksa kredensial pengguna dengan membaca file `users.csv` dan memverifikasi kata sandi yang dienkripsi.

4. **encrypt_password()**
   - Mengenkripsi kata sandi menggunakan fungsi `PKCS5_PBKDF2_HMAC` dari OpenSSL.

5. **verify_password()**
   - Memverifikasi kata sandi dengan membandingkan hash yang dienkripsi.

6. **handle_interactive_mode()**
   - Mengelola mode interaktif setelah pengguna berhasil login dan terhubung ke server.

### Fungsi Utama
```c
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
```
Fungsi ini memproses argumen input dari pengguna, memanggil fungsi `register_user()` atau `login_user()` berdasarkan perintah yang diberikan, dan menginisiasi koneksi soket jika login berhasil dan masuk ke mode interaktif.

### Register User
```c
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
```
Fungsi ini memeriksa apakah pengguna sudah terdaftar dengan membaca file `users.csv`. Jika belum terdaftar, mengenkripsi kata sandi dan menyimpan data pengguna baru ke file.

### Login User
```c
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
```
Fungsi ini memeriksa kredensial pengguna dengan membaca file `users.csv` dan memverifikasi kata sandi yang dienkripsi.

### Enkripsi Kata Sandi
```c
void encrypt_password(const char *password, char *encrypted_password) {
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));

    unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(hash), hash);

    memcpy(encrypted_password, salt, sizeof(salt));
    memcpy(encrypted_password + sizeof(salt), hash, sizeof(hash));
}
```
Fungsi ini mengenkripsi kata sandi dengan menambahkan salt dan menghasilkan hash menggunakan algoritma HMAC-SHA256.

### Verifikasi Kata Sandi
```c
int verify_password(const char *password, const char *encrypted_password) {
    unsigned char salt[16];
    memcpy(salt, encrypted_password, sizeof(salt));

    unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 10000, EVP_sha256(), sizeof(hash), hash);

    return memcmp(hash, encrypted_password + sizeof(salt), sizeof(hash)) == 0;
}
```
Fungsi ini memverifikasi kata sandi dengan membandingkan hash dari kata sandi yang diberikan dengan hash yang tersimpan.

### Handle Interaktif
```c
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
```
Fungsi ini mengelola mode interaktif setelah pengguna berhasil login dan terhubung ke server.

# B. Bagaimana DiscorIT Digunakan

Program ini memiliki perbadaan antara Root, Admin, dan User.
- Root: Memiliki akses penuh untuk mengelola semua channel, room, dan user. Root adalah akun yang pertama kali mendaftar.
- Admin: Memiliki akses untuk mengelola channel dan room yang mereka buat, serta mengelola user dalam channel mereka.
- User: Dapat mengirim pesan chat, melihat channel, dan room. user menjadi admin di channel yang mereka buat.

## 1. List Channel dan Room
Program ini pengguna dapat melihat daftar channel yang tersedia dan dapat melihat list room dan pengguna dalam channel tersebut.

## Prasyarat
- Lakukan login terlebih dahulu.

## Penggunaan
Program ini mendukung dua perintah utama: `LIST CHANNEL` dan `LIST ROOM`.

### Melihat Daftar Channel
Untuk melihat daftar channel, gunakan perintah berikut:
```sh
[user] LIST CHANNEL
channel1 channel2 channel3
```
Contoh:
```sh
[qurbancare] LIST CHANNEL
care bancar qurb
```

### Melihat List Room dan List User
Untuk melihat list room, gunakan perintah berikut:
```sh
[user/channel] LIST ROOM
room1 room2 room3
```
Contoh:
```sh
[qurbancare/care] LIST ROOM
urban banru runab
```

Untuk melihat list user yang ada dalam channel tersebut, gunakan perintah berikut:
```sh
[user/channel] LIST USER
user1 user2 user3
```
Contoh:
```sh
[qurbancare/care] LIST USER
root admin qurbancare
```

Jika login berhasil, program akan masuk ke user rootnya dan pengguna dapat berkomunikasi dengan server.

## Penjelasan Kode

### Struktur Data User
```c
typedef struct {
    int id_channel;
    char name[50];
    char key[256];
} Channel;
```
Struktur `Channel` menyimpan informasi tentang channel termasuk ID, nama, dan kata sandi yang dienkripsi.

### Fungsi Utama
1. **main()**
   - Menginisialisasi dan menjalankan server yang dapat menerima dan menangani koneksi klien secara paralel menggunakan thread.
   - Mencatat semua aktivitas ke dalam file log untuk pemantauan dan debugging.

2. **list_channels()**
   - Mengirimkan daftar semua channel yang ada ke klien melalui soket yang diidentifikasi oleh `sock`.
  
3. **list_rooms()**
   - Mengirimkan daftar semua room yang ada dalam channel tertentu ke klien.

4. **list_users()**
   - Mengirimkan daftar semua pengguna yang ada dalam channel tertentu ke klien.

### Fungsi Utama
```c
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
```
Fungsi ini menginisialisasi dan menjalankan server yang dapat menerima dan menangani koneksi klien secara paralel menggunakan thread dan mencatat semua aktivitas ke dalam file log untuk pemantauan dan debugging.

### List Channel
```c
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
```
Fungsi ini mengirimkan daftar semua channel yang ada ke klien melalui soket yang diidentifikasi oleh `sock`.

### List Room
```c
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
```
Fungsi ini mengirimkan daftar semua room yang ada dalam saluran tertentu ke klien.

### List User
```c
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
```
Fungsi ini mengirimkan daftar semua pengguna yang ada dalam saluran tertentu ke klien.

## 2. Akses Channel dan Room
Program ini user dapat mengakses channel admin dan root dan pengguna dapat masuk ke room setelah bergabung dengan channel.

## Prasyarat
- Lakukan login terlebih dahulu.

## Penggunaan
Program ini mendukung dua perintah utama: `JOIN channel` dan `JOIN room`.

### Mengakses Channel Admin dan Root
Untuk mengakses channel admin dan root, gunakan perintah berikut:
```sh
[user] JOIN channel
Key: key
[user/channel]
```
Contoh:
```sh
[qurbancare] JOIN care
Key: care123
[qurbancare/care] 
```

### Melihat List Room dan List User
Untuk melihat list room, gunakan perintah berikut:
```sh
[user/channel] JOIN room
[user/channel/room] 
```
Contoh:
```sh
[qurbancare/care] JOIN urban
[qurbancare/care/urban]
```

Jika login berhasil, program akan masuk ke user rootnya dan pengguna dapat berkomunikasi dengan server.

## Penjelasan Kode

### Fungsi Utama
1. **join_channels()**
   - Memungkinkan pengguna untuk bergabung dengan channel tertentu menggunakan nama pengguna, nama saluran, dan kunci (jika diperlukan).

### Join Channel
```c
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
```
Fungsi ini memungkinkan pengguna untuk bergabung dengan channel tertentu menggunakan nama pengguna, nama saluran, dan kunci (jika diperlukan).

## 3. Fitur Chat
Program ini user dapat mengirim pesan dalam chat dan pengguna dapat melihat pesan-pesan chat yang ada dalam room. Serta pengguna dapat edit dan delete pesan yang sudah dikirim dengan menggunakan ID pesan.

## Prasyarat
- Lakukan login terlebih dahulu.

## Penggunaan
Program ini mendukung empat perintah utama: `CHAT "text"`, `SEE CHAT`, `EDIT CHAT id “text”`, dan `DEL CHAT id `.

### Mengirim Pesan
Untuk mengirim pesan, gunakan perintah berikut:
```sh
[user/channel/room] CHAT "text"
```
Contoh:
```sh
[qurbancare/care/urban] CHAT “hallo”
```

### Melihat Pesan-Pesan Chat yang Ada Dalam Room
Untuk melihat pesan-pesan chat yang ada dalam room, gunakan perintah berikut:
```sh
[user/channel/room] SEE CHAT
```
Contoh:
```sh
[qurbancare/care/urban] SEE CHAT
```

### Mengedit Pesan yang Sudah Dikirim
Untuk mengedit pesan yang sudah dikirim, gunakan perintah berikut:
```sh
[user/channel/room] EDIT CHAT id “text”
```
Contoh:
```sh
[qurbancare/care/urban] EDIT CHAT 3 “hi”
```

### Menghapus Pesan yang Sudah Dikirim
Untuk menghapus pesan yang sudah dikirim, gunakan perintah berikut:
```sh
[user/channel/room] DEL CHAT id
```
Contoh:
```sh
[qurbancare/care/urban] DEL CHAT 3
```

Jika login berhasil, program akan masuk ke user rootnya dan pengguna dapat berkomunikasi dengan server.

## Penjelasan Kode

### Fungsi Utama
1. **chat_message()**
   - Mengirimkan pesan dari pengguna ke room tertentu dalam channel tertentu.
  
2. **see_chats()**
   - Mengirimkan riwayat percakapan dari room tertentu dalam channel tertentu ke klien.

3. **edit_chat()**
   - Mengubah pesan tertentu dalam room tertentu berdasarkan ID pesan.

4. **delete_chat()**
   - Menghapus pesan tertentu dalam room tertentu berdasarkan ID pesan.

### Chat Message
```c
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
```
Fungsi ini mengirimkan pesan dari pengguna ke room tertentu dalam channel tertentu.

### See Chat
```c
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
```
Fungsi ini mengirimkan riwayat percakapan dari room tertentu dalam channel tertentu ke klien.

### Edit Chat
```c
void edit_chat(const char *channel_name, const char *room_name, int chat_id, const char *new_message, int sock) {
    // Example implementation: Editing a chat message
    // This function should read the chat.csv file, find the chat_id, and update the message
    // Note: This is just a simplified example, proper file handling should be implemented
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Edited chat ID %d with message: %s\n", chat_id, new_message);
    send(sock, response, strlen(response), 0);
}
```
Fungsi ini mengubah pesan tertentu dalam room tertentu berdasarkan ID pesan.

### Delete Chat
```c
void delete_chat(const char *channel_name, const char *room_name, int chat_id, int sock) {
    // Example implementation: Deleting a chat message
    // This function should read the chat.csv file, find the chat_id, and remove the message
    // Note: This is just a simplified example, proper file handling should be implemented
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Deleted chat ID %d\n", chat_id);
    send(sock, response, strlen(response), 0);
}
```
Fungsi ini menghapus pesan tertentu dalam room tertentu berdasarkan ID pesan.

# C. Root

- Akun yang pertama kali mendaftar otomatis mendapatkan peran "root".
- Root dapat masuk ke channel manapun tanpa key dan create, update, dan delete pada channel dan room, mirip dengan admin [D].
- Root memiliki kemampuan khusus untuk mengelola user, seperti: list, edit, dan Remove.

## Penggunaan
Program ini mendukung empat perintah utama: `LIST USER`, `EDIT WHERE user1 -u user01`, `EDIT WHERE user01 -p secretpass`, dan `REMOVE user01`.

### List User
Untuk menlihat list user, gunakan perintah berikut:
```sh
[user] LIST USER
user1 user2 user3
```
Contoh:
```sh
[root] LIST USER
naupan qurbancare bashmi
```

### Mengedit Nama User
Untuk mengedit nama user, gunakan perintah berikut:
```sh
[user] EDIT WHERE user1 -u user01
user1 berhasil diubah menjadi user01
```
Contoh:
```sh
[root] EDIT WHERE naupan -u zika
naupan berhasil diubah menjadi zika
```

### Mengedit Password User
Untuk mengedit password user, gunakan perintah berikut:
```sh
[user] EDIT WHERE user01 -p secretpass
password user01 berhasil diubah
```
Contoh:
```sh
[root] EDIT WHERE zika -p 123zika
password zika berhasil diubah
```

### Menghapus User
Untuk menghapus, gunakan perintah berikut:
```sh
[user] REMOVE user01
user01 berhasil dihapus
```
Contoh:
```sh
[root] REMOVE zika
zika berhasil dihapus
```

## Penjelasan Kode

### Fungsi Utama
1. **list_all_users()**
   - Mengirimkan daftar semua pengguna yang terdaftar ke klien.

2. **edit_user()**
   - Mengubah informasi pengguna, termasuk nama pengguna dan kata sandi.
  
3. **remove_user()**
   - Menghapus pengguna tertentu dari sistem.

### List User
```c
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
```
Fungsi ini mengirimkan daftar semua pengguna yang terdaftar ke klien.

### Edit User
```c
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
```
Fungsi ini mengubah informasi pengguna, termasuk nama pengguna dan kata sandi.

### Remove User
```c
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
```
Fungsi ini menghapus pengguna tertentu dari sistem.

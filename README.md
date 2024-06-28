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

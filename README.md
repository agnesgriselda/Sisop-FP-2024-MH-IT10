# Final Project Praktikum Sistem Operasi
## DiscorIT

- Agnes Zenobia __Griselda__ Petrina (5027231034)
- Muhammad __Nafi__ Firdaus (5027231045)
- __Rafika__ Az Zahra Kusumastuti (5027231050)

## Penjelasan Kode
# User Registration and Login Program

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


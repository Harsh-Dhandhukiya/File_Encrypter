#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <openssl/evp.h>

// --- AES Encryption Functions (Phase 2) ---

// Handles OpenSSL errors by printing them to the console.
void handleErrors(void);

// Performs file encryption or decryption using AES.
// The 'do_encrypt' parameter should be 1 for encryption and 0 for decryption.
bool file_encrypt_decrypt_aes(const std::string& input_file, const std::string& output_file,
                              const unsigned char* key, const unsigned char* iv, int do_encrypt,
                              const EVP_CIPHER *cipher_type);

#endif // ENCRYPTION_H
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <openssl/evp.h>

// --- General & AES Functions (Phase 2) ---

// Handles OpenSSL errors.
void handleErrors(void);

// Performs AES file encryption or decryption.
bool file_encrypt_decrypt_aes(const std::string& input_file, const std::string& output_file,
                              const unsigned char* key, const unsigned char* iv, int do_encrypt,
                              const EVP_CIPHER *cipher_type);

// --- RSA Functions (Phase 3) ---

// Generates an RSA key pair and saves them to the specified files.
bool generate_rsa_keys(const std::string& pub_key_file, const std::string& priv_key_file);

// Encrypts data using an RSA public key.
bool rsa_encrypt(const std::string& pub_key_file, const std::vector<unsigned char>& plain_text, std::vector<unsigned char>& encrypted_text);

// Decrypts data using an RSA private key.
bool rsa_decrypt(const std::string& priv_key_file, const std::vector<unsigned char>& encrypted_text, std::vector<unsigned char>& decrypted_text);


#endif // ENCRYPTION_H
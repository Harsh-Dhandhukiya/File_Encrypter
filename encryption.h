#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <openssl/evp.h>

// --- High-Level Workflow Functions (Phase 4) ---

/**
 * @brief Generates an RSA key pair and saves them to PEM files.
 * @param pub_key_file Path to save the public key.
 * @param priv_key_file Path to save the private key.
 * @return True on success, false on failure.
 */
bool generate_rsa_keys(const std::string& pub_key_file, const std::string& priv_key_file);

/**
 * @brief Encrypts a file using a hybrid AES+RSA scheme.
 * @param input_file The file to encrypt.
 * @param pub_key_file The RSA public key to use for encrypting the session key.
 * @return True on success, false on failure.
 */
bool hybrid_encrypt(const std::string& input_file, const std::string& pub_key_file);

/**
 * @brief Decrypts a file encrypted with the hybrid scheme.
 * @param input_file The encrypted file (e.g., file.txt.enc).
 * @param priv_key_file The RSA private key for decrypting the session key.
 * @return True on success, false on failure.
 */
bool hybrid_decrypt(const std::string& input_file, const std::string& priv_key_file);


// --- Internal Helper Functions ---

// Handles OpenSSL errors.
void handleErrors(void);

#endif // ENCRYPTION_H
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <vector>
#include <openssl/evp.h>

// --- High-Level Workflow Functions ---

/**
 * @brief Generates an RSA key pair and saves them to PEM files.
 */
bool generate_rsa_keys(const std::string& pub_key_file, const std::string& priv_key_file);

/**
 * @brief Encrypts a file using a standard hybrid AES+RSA scheme.
 */
bool hybrid_encrypt(const std::string& input_file, const std::string& pub_key_file);

/**
 * @brief Decrypts a file encrypted with the standard hybrid scheme.
 */
bool hybrid_decrypt(const std::string& input_file, const std::string& priv_key_file);

/**
 * @brief Encrypts a file and disguises the output as a different file type.
 * @param input_file The original file to encrypt.
 * @param pub_key_file The RSA public key to use for encryption.
 * @param disguised_output_file The final output file with a deceptive extension (e.g., image.jpg).
 * @return True on success, false on failure.
 */
bool disguise_file(const std::string& input_file, const std::string& pub_key_file, const std::string& disguised_output_file);

/**
 * @brief Reveals and decrypts a file that was disguised.
 * @param disguised_input_file The file to reveal and decrypt.
 * @param priv_key_file The RSA private key for decryption.
 * @param revealed_output_file The path to save the final decrypted content.
 * @return True on success, false on failure.
 */
bool reveal_file(const std::string& disguised_input_file, const std::string& priv_key_file, const std::string& revealed_output_file);


// --- Internal Helper Functions ---
void handleErrors(void);

#endif // ENCRYPTION_H
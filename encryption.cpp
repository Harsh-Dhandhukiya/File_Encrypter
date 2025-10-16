#include "encryption.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

using namespace std;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// --- AES Implementation (Phase 2) ---
bool file_encrypt_decrypt_aes(const std::string& input_file, const std::string& output_file,
                              const unsigned char* key, const unsigned char* iv, int do_encrypt,
                              const EVP_CIPHER *cipher_type)
{
    ifstream in_file(input_file, ios::binary);
    if (!in_file) {
        cerr << "Error: Cannot open input file: " << input_file << endl;
        return false;
    }

    ofstream out_file(output_file, ios::binary);
    if (!out_file) {
        cerr << "Error: Cannot open output file: " << output_file << endl;
        return false;
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    const int buffer_size = 4096;
    vector<unsigned char> in_buffer(buffer_size);
    vector<unsigned char> out_buffer(buffer_size + EVP_MAX_BLOCK_LENGTH);

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_CipherInit_ex(ctx, cipher_type, NULL, key, iv, do_encrypt)) handleErrors();

    while(in_file.read(reinterpret_cast<char*>(in_buffer.data()), buffer_size)) {
        int bytes_read = in_file.gcount();
        if(1 != EVP_CipherUpdate(ctx, out_buffer.data(), &len, in_buffer.data(), bytes_read)) handleErrors();
        out_file.write(reinterpret_cast<char*>(out_buffer.data()), len);
    }
    
    int bytes_read = in_file.gcount();
    if (bytes_read > 0) {
        if(1 != EVP_CipherUpdate(ctx, out_buffer.data(), &len, in_buffer.data(), bytes_read)) handleErrors();
        out_file.write(reinterpret_cast<char*>(out_buffer.data()), len);
    }

    if(1 != EVP_CipherFinal_ex(ctx, out_buffer.data(), &len)) handleErrors();
    out_file.write(reinterpret_cast<char*>(out_buffer.data()), len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// --- RSA Implementation (Phase 3) ---

bool generate_rsa_keys(const std::string& pub_key_file, const std::string& priv_key_file) {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        handleErrors();
        return false;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        handleErrors();
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        handleErrors();
        return false;
    }
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        handleErrors();
        return false;
    }
    
    // Save public key
    FILE* pub_fp = fopen(pub_key_file.c_str(), "wb");
    if (!pub_fp) {
        cerr << "Error opening public key file for writing." << endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    PEM_write_PUBKEY(pub_fp, pkey);
    fclose(pub_fp);

    // Save private key
    FILE* priv_fp = fopen(priv_key_file.c_str(), "wb");
     if (!priv_fp) {
        cerr << "Error opening private key file for writing." << endl;
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    PEM_write_PrivateKey(priv_fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(priv_fp);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return true;
}

bool rsa_encrypt(const std::string& pub_key_file, const std::vector<unsigned char>& plain_text, std::vector<unsigned char>& encrypted_text) {
    FILE* pub_fp = fopen(pub_key_file.c_str(), "rb");
    if (!pub_fp) {
        cerr << "Error opening public key file." << endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
    fclose(pub_fp);
    if (!pkey) {
        handleErrors();
        return false;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) { handleErrors(); return false; }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) { handleErrors(); return false; }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) { handleErrors(); return false; }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plain_text.data(), plain_text.size()) <= 0) { handleErrors(); return false; }
    encrypted_text.resize(outlen);
    if (EVP_PKEY_encrypt(ctx, encrypted_text.data(), &outlen, plain_text.data(), plain_text.size()) <= 0) { handleErrors(); return false; }
    encrypted_text.resize(outlen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return true;
}

bool rsa_decrypt(const std::string& priv_key_file, const std::vector<unsigned char>& encrypted_text, std::vector<unsigned char>& decrypted_text) {
    FILE* priv_fp = fopen(priv_key_file.c_str(), "rb");
    if (!priv_fp) {
        cerr << "Error opening private key file." << endl;
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
    fclose(priv_fp);
    if (!pkey) {
        handleErrors();
        return false;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) { handleErrors(); return false; }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) { handleErrors(); return false; }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) { handleErrors(); return false; }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_text.data(), encrypted_text.size()) <= 0) { handleErrors(); return false; }
    decrypted_text.resize(outlen);
    if (EVP_PKEY_decrypt(ctx, decrypted_text.data(), &outlen, encrypted_text.data(), encrypted_text.size()) <= 0) { handleErrors(); return false; }
    decrypted_text.resize(outlen);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return true;
}
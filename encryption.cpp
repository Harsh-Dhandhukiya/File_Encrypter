#include "encryption.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

using namespace std;

// --- Internal Helper Functions Declarations ---
namespace internal {
    bool file_encrypt_decrypt_aes(const std::string&, const std::string&, const unsigned char*, const unsigned char*, int, const EVP_CIPHER*);
    bool rsa_encrypt(const std::string&, const std::vector<unsigned char>&, std::vector<unsigned char>&);
    bool rsa_decrypt(const std::string&, const std::vector<unsigned char>&, std::vector<unsigned char>&);
    vector<unsigned char> read_file(const string& filename);
    void write_file(const string& filename, const vector<unsigned char>& data);
}

// --- Error Handling ---
void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

// --- High-Level Workflow Implementations (Phase 4) ---

bool generate_rsa_keys(const std::string& pub_key_file, const std::string& priv_key_file) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) { handleErrors(); return false; }

    if (EVP_PKEY_keygen_init(ctx) <= 0) { handleErrors(); return false; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { handleErrors(); return false; }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) { handleErrors(); return false; }
    EVP_PKEY_CTX_free(ctx);

    FILE* pub_fp = fopen(pub_key_file.c_str(), "wb");
    if (!pub_fp) { cerr << "Error: Unable to open public key file for writing." << endl; return false; }
    PEM_write_PUBKEY(pub_fp, pkey);
    fclose(pub_fp);

    FILE* priv_fp = fopen(priv_key_file.c_str(), "wb");
    if (!priv_fp) { cerr << "Error: Unable to open private key file for writing." << endl; return false; }
    PEM_write_PrivateKey(priv_fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(priv_fp);
    
    EVP_PKEY_free(pkey);
    return true;
}

bool hybrid_encrypt(const std::string& input_file, const std::string& pub_key_file) {
    // 1. Generate one-time AES key and IV
    unsigned char aes_key[32];
    unsigned char iv[16];
    if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv))) {
        cerr << "Error: Failed to generate random AES key/IV." << endl;
        return false;
    }

    // 2. Encrypt AES key+IV using RSA public key
    vector<unsigned char> key_iv_to_encrypt;
    key_iv_to_encrypt.insert(key_iv_to_encrypt.end(), aes_key, aes_key + sizeof(aes_key));
    key_iv_to_encrypt.insert(key_iv_to_encrypt.end(), iv, iv + sizeof(iv));

    vector<unsigned char> encrypted_aes_key;
    if (!internal::rsa_encrypt(pub_key_file, key_iv_to_encrypt, encrypted_aes_key)) {
        cerr << "Error: RSA encryption of AES key failed." << endl;
        return false;
    }
    internal::write_file(input_file + ".key.enc", encrypted_aes_key);
    cout << "Session key encrypted and saved to " << input_file << ".key.enc" << endl;

    // 3. Encrypt the file using AES
    if (internal::file_encrypt_decrypt_aes(input_file, input_file + ".enc", aes_key, iv, 1, EVP_aes_256_cbc())) {
        cout << "File successfully encrypted to " << input_file << ".enc" << endl;
        return true;
    } else {
        cout << "Error: AES file encryption failed." << endl;
        return false;
    }
}

bool hybrid_decrypt(const std::string& input_file, const std::string& priv_key_file) {
    // 1. Determine base filename to find the encrypted key file
    string base_filename = input_file;
    size_t pos = base_filename.rfind(".enc");
    if (pos == string::npos) {
        cerr << "Error: Input file does not have the .enc extension." << endl;
        return false;
    }
    base_filename.erase(pos);
    
    // 2. Decrypt the AES key+IV using RSA private key
    string encrypted_key_file = base_filename + ".key.enc";
    vector<unsigned char> encrypted_aes_key = internal::read_file(encrypted_key_file);
    if (encrypted_aes_key.empty()) return false;

    vector<unsigned char> decrypted_key_iv;
    if (!internal::rsa_decrypt(priv_key_file, encrypted_aes_key, decrypted_key_iv)) {
        cerr << "Error: RSA decryption of AES key failed. Is the private key correct?" << endl;
        return false;
    }
    if (decrypted_key_iv.size() != 48) { // 32 for key + 16 for IV
        cerr << "Error: Decrypted session key is not the correct size." << endl;
        return false;
    }

    // 3. Extract AES key and IV
    unsigned char aes_key[32];
    unsigned char iv[16];
    copy(decrypted_key_iv.begin(), decrypted_key_iv.begin() + 32, aes_key);
    copy(decrypted_key_iv.begin() + 32, decrypted_key_iv.end(), iv);

    // 4. Decrypt the file using AES
    string output_file = input_file + ".dec";
    if (internal::file_encrypt_decrypt_aes(input_file, output_file, aes_key, iv, 0, EVP_aes_256_cbc())) {
        cout << "File successfully decrypted to " << output_file << endl;
        return true;
    } else {
        cout << "Error: AES file decryption failed." << endl;
        return false;
    }
}


// --- Internal Helper Functions Implementations ---
namespace internal {
    vector<unsigned char> read_file(const string& filename) {
        ifstream file(filename, ios::binary);
        if (!file) {
            cerr << "Error: Cannot open file: " << filename << endl;
            return {};
        }
        return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    }

    void write_file(const string& filename, const vector<unsigned char>& data) {
        ofstream file(filename, ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
    }

    bool file_encrypt_decrypt_aes(const std::string& input_file, const std::string& output_file,
                                  const unsigned char* key, const unsigned char* iv, int do_encrypt,
                                  const EVP_CIPHER *cipher_type) {
        ifstream in_file(input_file, ios::binary);
        if (!in_file) { cerr << "Error: Cannot open input file: " << input_file << endl; return false; }
        ofstream out_file(output_file, ios::binary);
        if (!out_file) { cerr << "Error: Cannot open output file: " << output_file << endl; return false; }

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

    bool rsa_encrypt(const std::string& pub_key_file, const std::vector<unsigned char>& plain_text, std::vector<unsigned char>& encrypted_text) {
        FILE* pub_fp = fopen(pub_key_file.c_str(), "rb");
        if (!pub_fp) { cerr << "Error opening public key file." << endl; return false; }
        EVP_PKEY* pkey = PEM_read_PUBKEY(pub_fp, NULL, NULL, NULL);
        fclose(pub_fp);
        if (!pkey) { handleErrors(); return false; }

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
        if (!priv_fp) { cerr << "Error opening private key file." << endl; return false; }
        EVP_PKEY* pkey = PEM_read_PrivateKey(priv_fp, NULL, NULL, NULL);
        fclose(priv_fp);
        if (!pkey) { handleErrors(); return false; }
        
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
}
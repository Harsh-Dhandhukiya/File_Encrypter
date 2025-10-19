#include "encryption.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <cstdint> // For uint32_t
#include <cstdio>  // For remove() and rename()

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

// --- High-Level Workflow Implementations ---

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
    unsigned char aes_key[32];
    unsigned char iv[16];
    if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv))) {
        cerr << "Error: Failed to generate random AES key/IV." << endl;
        return false;
    }
    vector<unsigned char> key_iv_to_encrypt(aes_key, aes_key + sizeof(aes_key));
    key_iv_to_encrypt.insert(key_iv_to_encrypt.end(), iv, iv + sizeof(iv));
    vector<unsigned char> encrypted_aes_key;
    if (!internal::rsa_encrypt(pub_key_file, key_iv_to_encrypt, encrypted_aes_key)) {
        cerr << "Error: RSA encryption of AES key failed." << endl;
        return false;
    }
    internal::write_file(input_file + ".key.enc", encrypted_aes_key);
    cout << "Session key encrypted and saved to " << input_file + ".key.enc" << endl;
    if (internal::file_encrypt_decrypt_aes(input_file, input_file + ".enc", aes_key, iv, 1, EVP_aes_256_cbc())) {
        cout << "File successfully encrypted to " << input_file + ".enc" << endl;
        return true;
    }
    return false;
}

bool hybrid_decrypt(const std::string& input_file, const std::string& priv_key_file) {
    string base_filename = input_file;
    size_t pos = base_filename.rfind(".enc");
    if (pos == string::npos) { cerr << "Error: Input file must have .enc extension." << endl; return false; }
    base_filename.erase(pos);
    string encrypted_key_file = base_filename + ".key.enc";
    vector<unsigned char> encrypted_aes_key = internal::read_file(encrypted_key_file);
    if (encrypted_aes_key.empty()) return false;
    vector<unsigned char> decrypted_key_iv;
    if (!internal::rsa_decrypt(priv_key_file, encrypted_aes_key, decrypted_key_iv) || decrypted_key_iv.size() != 48) {
        cerr << "Error: RSA decryption of AES key failed. Check private key or key file." << endl;
        return false;
    }
    unsigned char aes_key[32];
    unsigned char iv[16];
    copy(decrypted_key_iv.begin(), decrypted_key_iv.begin() + 32, aes_key);
    copy(decrypted_key_iv.begin() + 32, decrypted_key_iv.end(), iv);
    string output_file = input_file + ".dec";
    if (internal::file_encrypt_decrypt_aes(input_file, output_file, aes_key, iv, 0, EVP_aes_256_cbc())) {
        cout << "File successfully decrypted to " << output_file << endl;
        return true;
    }
    return false;
}

bool disguise_file(const std::string& input_file, const std::string& pub_key_file, const std::string& disguised_output_file) {
    // 1. Encrypt the file, creating temporary .enc and .key.enc files
    if (!hybrid_encrypt(input_file, pub_key_file)) {
        cerr << "Error: Failed to perform initial encryption." << endl;
        return false;
    }

    // 2. Read the encrypted components into memory
    vector<unsigned char> encrypted_data = internal::read_file(input_file + ".enc");
    vector<unsigned char> encrypted_key = internal::read_file(input_file + ".key.enc");
    if (encrypted_data.empty() || encrypted_key.empty()) {
        cerr << "Error: Failed to read temporary encrypted files." << endl;
        return false;
    }

    // 3. Create the disguised data packet: [4 bytes key_size][encrypted_key][encrypted_data]
    uint32_t key_size = encrypted_key.size();
    vector<unsigned char> disguised_packet;
    disguised_packet.insert(disguised_packet.end(), reinterpret_cast<unsigned char*>(&key_size), reinterpret_cast<unsigned char*>(&key_size) + sizeof(key_size));
    disguised_packet.insert(disguised_packet.end(), encrypted_key.begin(), encrypted_key.end());
    disguised_packet.insert(disguised_packet.end(), encrypted_data.begin(), encrypted_data.end());

    // 4. Write the packet to the final output file
    internal::write_file(disguised_output_file, disguised_packet);

    // 5. Clean up temporary files
    remove((input_file + ".enc").c_str());
    remove((input_file + ".key.enc").c_str());

    cout << "Successfully encrypted and disguised " << input_file << " as " << disguised_output_file << endl;
    return true;
}

bool reveal_file(const std::string& disguised_input_file, const std::string& priv_key_file, const std::string& revealed_output_file) {
    // 1. Read the entire disguised file
    vector<unsigned char> disguised_packet = internal::read_file(disguised_input_file);
    if (disguised_packet.size() < sizeof(uint32_t)) {
        cerr << "Error: Disguised file is invalid or too small." << endl;
        return false;
    }

    // 2. Extract key size from the start of the packet
    uint32_t key_size;
    memcpy(&key_size, disguised_packet.data(), sizeof(key_size));

    if (disguised_packet.size() < key_size + sizeof(key_size)) {
        cerr << "Error: Disguised file is corrupted or key size is incorrect." << endl;
        return false;
    }

    // 3. Split the packet into its components
    vector<unsigned char> encrypted_key(disguised_packet.begin() + sizeof(key_size), disguised_packet.begin() + sizeof(key_size) + key_size);
    vector<unsigned char> encrypted_data(disguised_packet.begin() + sizeof(key_size) + key_size, disguised_packet.end());

    // 4. Write temporary files for the standard decryption function
    string temp_base = "temp_revealed_file";
    internal::write_file(temp_base + ".enc", encrypted_data);
    internal::write_file(temp_base + ".key.enc", encrypted_key);
    
    // 5. Decrypt using the standard hybrid method
    bool success = hybrid_decrypt(temp_base + ".enc", priv_key_file);
    
    if(success) {
        // Rename the final decrypted file to the user's desired output name
        rename((temp_base + ".enc.dec").c_str(), revealed_output_file.c_str());
        cout << "Successfully revealed and decrypted file to " << revealed_output_file << endl;
    }

    // 6. Clean up temporary files
    remove((temp_base + ".enc").c_str());
    remove((temp_base + ".key.enc").c_str());

    return success;
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
        while(in_file) {
            in_file.read(reinterpret_cast<char*>(in_buffer.data()), buffer_size);
            int bytes_read = in_file.gcount();
            if (bytes_read > 0) {
                if(1 != EVP_CipherUpdate(ctx, out_buffer.data(), &len, in_buffer.data(), bytes_read)) {
                    handleErrors(); EVP_CIPHER_CTX_free(ctx); return false;
                }
                out_file.write(reinterpret_cast<char*>(out_buffer.data()), len);
            }
        }
        if(1 != EVP_CipherFinal_ex(ctx, out_buffer.data(), &len)) {
            handleErrors(); EVP_CIPHER_CTX_free(ctx); return false;
        }
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
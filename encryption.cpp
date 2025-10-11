#include "encryption.h"
#include <fstream>
#include <iostream>
#include <vector>
#include <openssl/err.h>

using namespace std;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

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

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handleErrors();
    }

    // Initialise the encryption/decryption operation.
    if(1 != EVP_CipherInit_ex(ctx, cipher_type, NULL, key, iv, do_encrypt)) {
        handleErrors();
    }

    // Process the file in chunks
    while(in_file.read(reinterpret_cast<char*>(in_buffer.data()), buffer_size)) {
        int bytes_read = in_file.gcount();
        if(1 != EVP_CipherUpdate(ctx, out_buffer.data(), &len, in_buffer.data(), bytes_read)) {
            handleErrors();
        }
        out_file.write(reinterpret_cast<char*>(out_buffer.data()), len);
    }
    
    // Process the final block if the file was not a multiple of the buffer size
    int bytes_read = in_file.gcount();
    if (bytes_read > 0) {
        if(1 != EVP_CipherUpdate(ctx, out_buffer.data(), &len, in_buffer.data(), bytes_read)) {
            handleErrors();
        }
        out_file.write(reinterpret_cast<char*>(out_buffer.data()), len);
    }

    // Finalise the operation.
    if(1 != EVP_CipherFinal_ex(ctx, out_buffer.data(), &len)) {
        handleErrors();
    }
    out_file.write(reinterpret_cast<char*>(out_buffer.data()), len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
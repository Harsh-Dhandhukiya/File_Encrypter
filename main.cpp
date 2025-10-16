#include <iostream>
#include "encryption.h"
#include <string>
#include <vector>
#include <fstream>
#include <openssl/rand.h>

using namespace std;

// Helper function to read an entire file into a vector
vector<unsigned char> read_file(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Error: Cannot open file: " << filename << endl;
        return {};
    }
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

// Helper function to write a vector to a file
void write_file(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void generate_keys_workflow() {
    string pub_key_file, priv_key_file;
    cout << "Enter filename for public key (e.g., public.pem): ";
    cin >> pub_key_file;
    cout << "Enter filename for private key (e.g., private.pem): ";
    cin >> priv_key_file;

    if (generate_rsa_keys(pub_key_file, priv_key_file)) {
        cout << "Successfully generated RSA keys." << endl;
    } else {
        cout << "Error: Failed to generate RSA keys." << endl;
    }
}

void hybrid_encrypt_workflow() {
    string input_file, pub_key_file;
    cout << "Enter the name of the file to encrypt: ";
    getline(cin >> ws, input_file);
    cout << "Enter the public key file to use (e.g., public.pem): ";
    cin >> pub_key_file;
    
    // 1. Generate one-time AES key and IV
    unsigned char aes_key[32];
    unsigned char iv[16];
    if (!RAND_bytes(aes_key, sizeof(aes_key)) || !RAND_bytes(iv, sizeof(iv))) {
        cerr << "Error generating random AES key/IV." << endl;
        return;
    }

    // Combine key and IV for RSA encryption
    vector<unsigned char> key_iv_to_encrypt;
    key_iv_to_encrypt.insert(key_iv_to_encrypt.end(), aes_key, aes_key + sizeof(aes_key));
    key_iv_to_encrypt.insert(key_iv_to_encrypt.end(), iv, iv + sizeof(iv));

    // 2. Encrypt AES key+IV using RSA public key
    vector<unsigned char> encrypted_aes_key;
    if (!rsa_encrypt(pub_key_file, key_iv_to_encrypt, encrypted_aes_key)) {
        cerr << "Error: RSA encryption of AES key failed." << endl;
        return;
    }
    write_file(input_file + ".key.enc", encrypted_aes_key);
    cout << "AES key encrypted and saved to " << input_file << ".key.enc" << endl;

    // 3. Encrypt the file using AES
    if (file_encrypt_decrypt_aes(input_file, input_file + ".enc", aes_key, iv, 1, EVP_aes_256_cbc())) {
        cout << "File successfully encrypted to " << input_file << ".enc" << endl;
    } else {
        cout << "Error: AES file encryption failed." << endl;
    }
}

void hybrid_decrypt_workflow() {
    string input_file, priv_key_file;
    cout << "Enter the name of the file to decrypt (e.g., file.txt.enc): ";
    getline(cin >> ws, input_file);
    cout << "Enter the private key file to use (e.g., private.pem): ";
    cin >> priv_key_file;

    // 1. Decrypt the AES key+IV using RSA private key
    string encrypted_key_file = input_file;
    size_t pos = encrypted_key_file.rfind(".enc");
    if (pos != string::npos) {
        encrypted_key_file.erase(pos);
    }
    encrypted_key_file += ".key.enc";
    
    vector<unsigned char> encrypted_aes_key = read_file(encrypted_key_file);
    if (encrypted_aes_key.empty()) return;

    vector<unsigned char> decrypted_key_iv;
    if (!rsa_decrypt(priv_key_file, encrypted_aes_key, decrypted_key_iv)) {
        cerr << "Error: RSA decryption of AES key failed. (Check private key)" << endl;
        return;
    }
    if (decrypted_key_iv.size() != 48) { // 32 for key + 16 for IV
        cerr << "Error: Decrypted key size is incorrect." << endl;
        return;
    }

    // 2. Extract AES key and IV
    unsigned char aes_key[32];
    unsigned char iv[16];
    copy(decrypted_key_iv.begin(), decrypted_key_iv.begin() + 32, aes_key);
    copy(decrypted_key_iv.begin() + 32, decrypted_key_iv.end(), iv);

    // 3. Decrypt the file using AES
    string output_file = input_file + ".dec";
    if (file_encrypt_decrypt_aes(input_file, output_file, aes_key, iv, 0, EVP_aes_256_cbc())) {
        cout << "File successfully decrypted to " << output_file << endl;
    } else {
        cout << "Error: AES file decryption failed." << endl;
    }
}

int main() {
    int choice;
    cout << "--- File Encrypter: Phase 3 (RSA+AES Hybrid) ---" << endl;
    cout << "1. Generate RSA Key Pair" << endl;
    cout << "2. Encrypt a File (Hybrid)" << endl;
    cout << "3. Decrypt a File (Hybrid)" << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    switch (choice) {
        case 1:
            generate_keys_workflow();
            break;
        case 2:
            hybrid_encrypt_workflow();
            break;
        case 3:
            hybrid_decrypt_workflow();
            break;
        default:
            cout << "Invalid choice." << endl;
            break;
    }

    return 0;
}
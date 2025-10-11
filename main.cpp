#include <iostream>
#include "encryption.h"
#include <string>
#include <openssl/rand.h>
#include <fstream>

using namespace std;

// Helper function to save the binary key/IV to a file
void save_key_iv(const string& filename, const unsigned char* data, size_t len) {
    ofstream file(filename, ios::binary);
    file.write(reinterpret_cast<const char*>(data), len);
}

// Helper function to load the binary key/IV from a file
void load_key_iv(const string& filename, unsigned char* data, size_t len) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "Error: Cannot open key/IV file: " << filename << ". Ensure it exists for decryption." << endl;
        exit(1); // Exit if key file is missing for decryption
    }
    file.read(reinterpret_cast<char*>(data), len);
}

int main()
{
    cout << "--- AES File Encrypter ---" << endl;
    cout << "Encrypt or Decrypt (E/D)?: ";
    char mode;
    cin >> mode;
    
    cout << "Enter the input file name: ";
    string filename;
    getline(cin >> ws, filename);

    cout << "Choose AES mode (E for ECB, C for CBC): ";
    char aes_mode_choice;
    cin >> aes_mode_choice;

    const EVP_CIPHER *cipher_type;
    if (aes_mode_choice == 'E' || aes_mode_choice == 'e') {
        cipher_type = EVP_aes_256_ecb();
    } else if (aes_mode_choice == 'C' || aes_mode_choice == 'c') {
        cipher_type = EVP_aes_256_cbc();
    } else {
        cout << "Invalid AES mode selected." << endl;
        return 1;
    }
    
    unsigned char key[32]; // AES-256 key
    unsigned char iv[16];  // AES block size
    string keyfilename, ivfilename, outfilename;

    if (mode == 'E' || mode == 'e')
    {
        keyfilename = filename + ".key";
        ivfilename = filename + ".iv";
        outfilename = filename + ".enc";

        // Generate a random key and IV for encryption
        if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
            cerr << "Error generating random key/IV." << endl;
            return 1;
        }

        save_key_iv(keyfilename, key, sizeof(key));
        save_key_iv(ivfilename, iv, sizeof(iv));
        cout << "Key and IV saved to " << keyfilename << " and " << ivfilename << endl;

        if(file_encrypt_decrypt_aes(filename, outfilename, key, iv, 1, cipher_type)) {
            cout << "File encrypted successfully to " << outfilename << endl;
        } else {
            cout << "Error: File encryption failed." << endl;
        }
    }
    else if (mode == 'D' || mode == 'd')
    {
        // --- FIX: Logic to find the correct key/iv files ---
        string base_filename = filename;
        size_t pos = base_filename.rfind(".enc");
        if (pos != string::npos) {
            base_filename.erase(pos, 4);
        }
        
        keyfilename = base_filename + ".key";
        ivfilename = base_filename + ".iv";
        // ---------------------------------------------------
        
        outfilename = filename + ".dec";

        // Load the key and IV from files for decryption
        load_key_iv(keyfilename, key, sizeof(key));
        load_key_iv(ivfilename, iv, sizeof(iv));
        
        if(file_encrypt_decrypt_aes(filename, outfilename, key, iv, 0, cipher_type)) {
            cout << "File decrypted successfully to " << outfilename << endl;
        } else {
            cout << "Error: File decryption failed." << endl;
        }
    }
    else
    {
        cout << "Error: Invalid mode selected. Please enter E or D." << endl;
    }

    return 0;
}
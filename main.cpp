#include <iostream>
#include "encryption.h"
#include <string>

using namespace std;

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

void encrypt_workflow() {
    string input_file, pub_key_file;
    cout << "Enter the name of the file to encrypt: ";
    getline(cin >> ws, input_file);
    cout << "Enter the public key file to use (e.g., public.pem): ";
    cin >> pub_key_file;
    
    hybrid_encrypt(input_file, pub_key_file);
}

void decrypt_workflow() {
    string input_file, priv_key_file;
    cout << "Enter the name of the file to decrypt (e.g., file.txt.enc): ";
    getline(cin >> ws, input_file);
    cout << "Enter the private key file to use (e.g., private.pem): ";
    cin >> priv_key_file;

    hybrid_decrypt(input_file, priv_key_file);
}

void disguise_workflow() {
    string input_file, pub_key_file, output_file;
    cout << "Enter the original file to encrypt and disguise: ";
    getline(cin >> ws, input_file);
    cout << "Enter the public key file: ";
    cin >> pub_key_file;
    cout << "Enter the final disguised filename (e.g., fake_image.jpg): ";
    cin >> output_file;

    disguise_file(input_file, pub_key_file, output_file);
}

void reveal_workflow() {
    string disguised_file, priv_key_file, output_file;
    cout << "Enter the disguised file to reveal: ";
    getline(cin >> ws, disguised_file);
    cout << "Enter the private key file: ";
    cin >> priv_key_file;
    cout << "Enter the filename for the revealed content: ";
    cin >> output_file;
    
    reveal_file(disguised_file, priv_key_file, output_file);
}

int main() {
    int choice;
    cout << "--- File Encrypter ---" << endl;
    cout << "1. Generate RSA Key Pair" << endl;
    cout << "2. Encrypt a File (Standard)" << endl;
    cout << "3. Decrypt a File (Standard)" << endl;
    cout << "4. Encrypt & Disguise a File" << endl;
    cout << "5. Reveal & Decrypt a File" << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    switch (choice) {
        case 1:
            generate_keys_workflow();
            break;
        case 2:
            encrypt_workflow();
            break;
        case 3:
            decrypt_workflow();
            break;
        case 4:
            disguise_workflow();
            break;
        case 5:
            reveal_workflow();
            break;
        default:
            cout << "Invalid choice." << endl;
            break;
    }

    return 0;
}
// #include<bits/stdc++.h>

#include <iostream>
#include "encryption.h"
#include <string>

using namespace std;
int main()
{
    string filename;
    char mode; // To define either it's encryption or decryption mode
    cout << "Enter the file name: ";
    // CORRECTED: Removed the redundant 'cin >> filename;' which was causing input errors.
    // 'getline' is now the only line reading the filename, correctly handling names with spaces.
    getline(cin >> ws, filename);

    cout << "Encrypt or Decrypt (E/D)?: ";
    cin >> mode;

    if (mode == 'E' || mode == 'e')
    {
        if(encryptFile(filename, true))
        {
            cout << "File encrypted successfully." << endl;
        }
        else
        {
            cout << "Error: File encryption failed." << endl;
        }
    }

    else if (mode == 'D' || mode == 'd')
    {
        // For decryption, it's better to ask for the encrypted file name (e.g., file.txt.enc)
        if(encryptFile(filename, false))
        {
            cout << "File decrypted successfully." << endl;
        }
        else
        {
            cout << "Error: File decryption failed." << endl;
        }

    }
    else
    {
        cout << "Error: Invalid mode selected. Please enter E or D." << endl;
    }

    return 0;
}
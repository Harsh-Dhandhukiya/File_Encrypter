#include "encryption.h"
#include <fstream>
#include <cctype> // To check the letter is in UPPERCASE or lowercase
#include <iostream>

using namespace std;

bool performCaesarCipher(string& content, bool encrypt)
{
    // This line correctly sets the shift: +3 for encryption, -3 for decryption.
    int shift = encrypt ? 3 : -3;

    for (char& ch : content)
    {
        if (isalpha(ch))
        {
            char base = isupper(ch) ? 'A' : 'a';
            // CORRECTED: The formula was flawed for decryption.
            // The original code had '(encrypt ? shift : -shift)', which resulted in a positive 3 for decryption too (-(-3) = 3).
            // The corrected formula now correctly applies the negative shift for decryption.
            ch = (ch - base + shift + 26) % 26 + base;
        }
    }
    return true;
}

bool encryptFile(const string& filename, bool encrypt)
{
    ifstream inputFile(filename);
    if (!inputFile.is_open())
    {
        // CLEANUP: Removed redundant cout from here. Main function will report the error.
        return false;
    }

    string content((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
    inputFile.close();

    if (performCaesarCipher(content, encrypt))
    {
        // During decryption, creates a new file with .dec extension (e.g., from 'file.txt.enc' to 'file.txt.enc.dec')
        ofstream outputFile(filename + (encrypt ? ".enc" : ".dec"));
        if (!outputFile.is_open())
        {
            return false;
        }
        outputFile << content;
        outputFile.close();
        return true;
    }
    else
    {
        return false;
    }
}
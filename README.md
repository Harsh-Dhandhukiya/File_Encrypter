# File Encrypter: A Hybrid Cryptography & Steganography Utility

**File Encrypter** is a powerful, cross-platform command-line tool built in **C++** for securing sensitive data.  
It employs a **hybrid encryption model** — combining the speed of **AES-256** with the asymmetric security of **RSA-2048** — and features an integrated **steganography module** to disguise encrypted files, offering an additional layer of plausible deniability.

---

## 🚀 Key Features

- **🔒 Hybrid Encryption**
  - Combines **AES-256** (for fast, bulk data encryption) with **RSA-2048** (for secure key exchange).  
  - Achieves both performance and cryptographic strength.

- **🕵️‍♂️ File Disguise (Steganography)**
  - Obfuscates encrypted files by embedding them into a single binary.  
  - Users can apply deceptive extensions (e.g., `.jpg`, `.pdf`) to make files appear harmless.

- **🧩 Secure Key Management**
  - Generates and manages RSA public/private key pairs for end-to-end encryption and decryption workflows.

- **🧱 Cross-Platform Build System**
  - Uses a **Makefile** and the **MSYS2/MinGW** toolchain for seamless builds on Windows and Unix-like environments.

- **⚙️ Modular Architecture**
  - Cryptographic logic is cleanly separated from the UI layer, making the project easy to maintain, test, and extend.

---

## 🧠 Technology Stack

| Component     | Technology               |
|----------------|--------------------------|
| **Language**   | C++                      |
| **Cryptography** | OpenSSL (AES, RSA)     |
| **Build System** | Make, MSYS2 (MinGW)    |

---

## 🧰 Prerequisites

To compile and run the project, you’ll need:

- A **C++ compiler toolchain** (`g++`, `gcc`, `make`).
- **OpenSSL development libraries** properly installed.
- On **Windows**, it is highly recommended to use **MSYS2** with the **MinGW32** toolchain.

### Windows Setup via MSYS2

```bash
# 1. Update package databases
pacman -Syu

# 2. Install 32-bit toolchain, make, and OpenSSL
pacman -S --needed base-devel mingw-w64-i686-toolchain mingw-w64-i686-openssl
````

---

##  Compilation

```bash
# Navigate to the project directory
cd /path/to/FE_v1.0

# Compile the project
make
```

After compilation, an executable named `file_encrypter` (or `file_encrypter.exe` on Windows) will be generated in the project root.

---

## 💡 Usage Guide

The utility provides a **menu-driven interface** for all cryptographic and steganographic operations.


### 🔑 Workflow 1: Generate RSA Key Pair

1. Run the program:

   ```bash
   file_encrypter
   ```
2. Choose **Option 1 – Generate RSA Key Pair**
3. Enter filenames for your keys (e.g., `public.pem` and `private.pem`)

> ⚠️ **Security Note:**
> Share your `public.pem` freely.
> Keep `private.pem` secure — compromise of this key exposes your data.

---

### 🧱 Workflow 2: Standard Encryption & Decryption

#### 🔐 To Encrypt:

1. Choose **Option 2 – Encrypt a File (Standard)**
2. Enter:

   * Path to original file (e.g., `my_document.txt`)
   * Path to your `public.pem`
3. Output:

   * `my_document.txt.enc` — Encrypted file
   * `my_document.txt.key.enc` — Encrypted AES key

#### 🔓 To Decrypt:

1. Choose **Option 3 – Decrypt a File (Standard)**
2. Enter:

   * Path to encrypted file (`my_document.txt.enc`)
   * Path to your `private.pem`
3. Output:

   * `my_document.txt.enc.dec` — Decrypted, original file

---

### 🕵️‍♀️ Workflow 3: Disguise & Reveal Files (Steganography)

#### 🎭 To Disguise:

1. Choose **Option 4 – Encrypt & Disguise a File**
2. Enter:

   * Original file (e.g., `secret_plan.txt`)
   * Path to `public.pem`
   * Deceptive output name (e.g., `innocent_image.jpg`)
3. Output:

   * `innocent_image.jpg` — Appears as an image but contains encrypted data.

#### 🔍 To Reveal:

1. Choose **Option 5 – Reveal & Decrypt a File**
2. Enter:

   * Disguised file (e.g., `innocent_image.jpg`)
   * Path to `private.pem`
   * Output filename (e.g., `revealed_plan.txt`)
3. Output:

   * `revealed_plan.txt` — Fully restored and decrypted file.

---

## 🧬 How It Works

### 🧩 Hybrid Encryption Model

1. A **unique AES-256 session key** is generated for each encryption task.
2. The AES key encrypts the file data (fast, symmetric encryption).
3. The AES key itself is then **encrypted with RSA-2048** using the recipient’s public key (asymmetric encryption).
4. During decryption, the recipient’s private RSA key decrypts the AES key, which is then used to restore the original data.

### 🗃️ File Disguise Format

Internally, disguised files follow this structure:

```
[ 4-byte Key Size | RSA-Encrypted AES Key | AES-Encrypted File Data ]
```

This self-contained format allows easy extraction and decryption without additional `.enc` files.

---

## 🧑‍💻 Development Notes

This project was created as a practical exercise in **applied cryptography**, **C++ systems programming**, and **secure software design**.
It demonstrates principles of **hybrid encryption**, **key management**, and **data obfuscation** through steganography.

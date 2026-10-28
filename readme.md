Use planning mode to build a complete, interactive, single-page educational web application for "PGP & S/MIME Email Message Signing and Verification" using vanilla HTML5, modern CSS (dark-mode cybersecurity dashboard theme), and vanilla JavaScript.

### Project Goal
Create a visual, step-by-step cryptographic simulator that generates a signed email message by:
1. Taking an email message (Sender, Receiver, Subject, Message Body).
2. Generating or accepting RSA Keys (primes p and q, modulus n, totient phi(n), public exponent e, and calculated private key d).
3. Computing the cryptographic hash of the message (show both a readable SHA-256 hex digest AND a mathematical numeric hash H mod n for step-by-step RSA calculation).
4. Encrypting the hash H with the sender's Private Key (d, n) using modular exponentiation: S = (H^d) mod n.
5. Appending the digital signature to the email message in both PGP Cleartext Signed format and S/MIME (multipart/signed) format.
6. Providing an interactive "Receiver Verification & Tamper Test" panel where users can edit the signed message or signature in real time to see if the decrypted hash H' = (S^e) mod n matches the newly computed message hash.

### Key UI Sections & Features to Build
1. **Header**:
   - Title: "PGP / S/MIME Email Message Signing Simulator"
   - Subtitle explaining the core workflow: Message -> Hash(M) -> Encrypt with Private Key (d) -> Append Signature.

2. **Step 1: Sender RSA Key Generator Card**:
   - Inputs for Prime `p`, Prime `q`, and Public Exponent `e`.
   - Include a "Load Preset Primes" dropdown (e.g., p=61, q=53, e=17; p=11, q=17, e=7; p=47, q=71, e=79) and a "Generate Random Primes" button.
   - Real-time validation checking that `p` and `q` are prime and `gcd(e, phi) == 1`.
   - Live display of calculated values: `n = p * q`, `phi(n) = (p-1)*(q-1)`, Public Key `(e, n)`, and Private Key `(d, n)` computed via the Extended Euclidean Algorithm.

3. **Step 2: Email Composer Card**:
   - Input fields for: From (Sender Email), To (Receiver Email), Subject, and Email Body (textarea).
   - A "Load Sample Email" button for quick testing.
   - Primary CTA button: "Compute Hash & Sign Email".

4. **Step 3: Live Cryptographic Pipeline Visualizer**:
   - Visual flow cards showing the live math for the current message:
     - Card A: **Message Hash Computation** (displays SHA-256 Hex Hash + Numeric Hash `H mod n`).
     - Card B: **Private Key Encryption (Signing)** (displays the formula `S = H^d mod n` with actual numbers plugged in and the resulting Signature `S`, plus Base64/Hex encoded signature block).
     - Card C: **Appended Output** (indicates signature attached to payload).

5. **Step 4: Generated Signed Email Output (with Format Toggle)**:
   - Tabs to switch between **PGP Signed Message Format** (`-----BEGIN PGP SIGNED MESSAGE-----` ... `-----BEGIN PGP SIGNATURE-----`) and **S/MIME Format** (`MIME-Version: 1.0`, `Content-Type: multipart/signed`, boundary headers, body, and `application/pkcs7-signature` block).
   - "Copy Signed Email" and "Download .eml / .asc File" buttons.

6. **Step 5: Receiver Verification & Tamper Simulator**:
   - Editable textarea pre-filled with the signed message body and editable signature value `S`.
   - Button/Live check that computes `H_new = Hash(Message)` and decrypts the signature using the Sender's Public Key: `H' = S^e mod n`.
   - Clear visual badge: Green "SIGNATURE VALID — Authentic & Untampered (H == H')" or Red "SIGNATURE INVALID — Message Tampered or Forged (H != H')".

### Technical & Design Requirements
- Use `BigInt` in JavaScript for all modular arithmetic (`powerMod`, `gcd`, `modInverse`) so large primes never overflow.
- Design a sleek, modern dark-themed UI (slate/indigo palette, glowing status badges, monospace font for keys, hashes, and MIME/PGP blocks, responsive grid layout).
- Keep all code clean and modular across `index.html`, `styles.css`, and `script.js`.
- After generating the files, open the preview to verify that clicking "Sign Email" and modifying text in the Tamper Simulator updates the verification badge accurately.
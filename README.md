# PGP & S/MIME Signing Workbench

A single-page, browser-based demonstration of RSA message signing and signature verification. The workbench shows how key parameters, a SHA-256 digest, modular arithmetic, and a tamper check fit together, with illustrative PGP-style and S/MIME-style payload views.

> **Educational use only.** This project is not a secure cryptographic tool and does not implement RFC-compliant OpenPGP or S/MIME. It uses very small RSA keys, textbook RSA without secure padding, and illustrative signature payloads. Do not use it to protect real messages, keys, or data.

## Features

- Configure RSA primes `p`, `q`, and public exponent `e`; calculate `n`, `phi(n)`, and private exponent `d`.
- Validate prime inputs and check that `e` is in range and relatively prime to `phi(n)`.
- Hash the message body with the browser's Web Crypto SHA-256 implementation.
- Inspect the digest, its reduction modulo `n`, and the RSA signature calculation using JavaScript `BigInt`.
- View generated PGP-cleartext-style and S/MIME-multipart-style payloads; copy or export the selected view.
- Recompute a received body's hash and compare it with the public-key operation on the signature.
- Modify the message or signature to observe verification failures, then restore the original.
- Load sample messages and preset RSA parameters.

## Run locally

The project has no package manager dependencies or build step. It requires Node.js to run the included static server.

1. Clone or download this repository.
2. From the project directory, start the server:

   ```sh
   node serve.js
   ```

3. Open [http://localhost:3000](http://localhost:3000) in a browser.

You can also open `index.html` directly in a modern browser. Serving it from localhost is recommended for consistent Web Crypto API behavior. The optional Inter and JetBrains Mono fonts are loaded from Google Fonts; system font fallbacks are defined if those fonts are unavailable.

## Using the workbench

1. Choose a preset or enter `p`, `q`, and `e`. The key panel displays the derived values and reports invalid parameters.
2. Edit the email headers and message body, then select **Compute Hash & Generate Signature**.
3. Inspect the digest and RSA arithmetic in the signing pipeline.
4. Choose a payload view, then copy it or export it as `.ASC` or `.EML`.
5. Edit the received message body or signature, or use the tamper buttons. The verification panel compares the newly calculated hash with the signature operation under the public key.

The preset keys are intentionally small so the arithmetic can be inspected easily:

| Preset | `p` | `q` | `e` |
|---|---:|---:|---:|
| Standard demo | 61 | 53 | 17 |
| 3-digit primes | 101 | 103 | 7 |
| Medium scale | 251 | 257 | 17 |

## How the demonstration works

The implementation hashes only the message body (not the From, To, or Subject headers). It treats the SHA-256 digest as an integer, reduces it modulo `n`, and computes:

```text
H = SHA256(message body) mod n
S = H^d mod n
H' = S^e mod n
```

Verification succeeds when the recomputed `H` equals `H'`. The application uses `BigInt` for RSA arithmetic and Web Crypto for SHA-256.

The payload views are for illustrating familiar message structures only. They are assembled by the app and do **not** contain standards-compliant OpenPGP signatures or valid CMS/PKCS#7 S/MIME signatures. The `.ASC` and `.EML` exports are therefore not suitable for real email signing or verification.

## Project files

- `index.html` — workbench structure and controls.
- `styles.css` — responsive paper-and-ink interface.
- `script.js` — RSA calculations, hashing, payload display, and verification behavior.
- `serve.js` — minimal Node.js static file server on port `3000`.

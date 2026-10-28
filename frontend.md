Build a single-page web application for "PGP & S/MIME Email Message Signing and Verification" using vanilla HTML5, CSS3, and JavaScript.

### STRICT ANTI-AI DESIGN & UI RULES (MUST FOLLOW)
Do NOT use generic AI design tropes. Specifically:
1. NO AI COLORING: Strictly ban purple, indigo, violet, neon cyan, teal, and all linear/radial gradients. Do not use dark-mode slate/navy themes (`#0f172a`).
2. NO AI SHAPING: Ban large border-radius values (`8px+`, pills, or blobs), glassmorphism (`backdrop-filter`), floating cards, hover lift animations (`translateY`), and soft diffuse drop-shadows.
3. NO AI FLUFF: Zero emojis anywhere in the UI (no lock, key, rocket, or checkmark emojis). No marketing hero banner or centered introductory paragraphs.

### TARGET DESIGN SYSTEM: "SWISS ENGINEERING WORKBENCH"
Design the interface like a serious desktop cryptographic utility (similar to CyberChef, Postman, or an IETF RFC inspection tool):
- **Color Palette (Paper & Ink)**:
  - Canvas background: Warm technical off-white (`#F4F4F0`)
  - Panel surface: Crisp white (`#FFFFFF`) and subtle recessed gray (`#EBEBE6`) for read-only outputs
  - Borders: Exposed `1px solid #CCCCCC` hairline grid dividers and `#111111` active borders
  - Primary Text: Deep charcoal/ink (`#111111`)
  - Secondary/Label Text: Muted neutral (`#555555`)
  - Primary Interactive Button: Solid flat charcoal (`#111111`) with white text, or flat international blue (`#0044CC`), turning `#333333` on hover
  - Semantic Status Only: Flat forest green (`#146C2E` on `#E6F4EA` background) for VALID signature; flat brick red (`#B3261E` on `#FCE8E6` background) for INVALID/TAMPERED signature
- **Geometry & Layout**:
  - Exposed grid layout with `1px solid` borders separating panes, `0px` or maximum `2px` border-radius on all inputs, buttons, and panels.
  - High information density: compact padding (`12px` to `16px`), crisp tabular alignment, and split-pane workbench layout that fits on a standard desktop screen without excessive scrolling.
- **Typography**:
  - UI Labels & Headers: Clean grotesque sans-serif (`Inter`, `-apple-system`, `Segoe UI`, `sans-serif`), uppercase micro-labels (`11px`, `letter-spacing: 0.06em`, `font-weight: 600`).
  - All Keys, Math, Hashes, and Email Raw Output: Technical monospace (`JetBrains Mono`, `IBM Plex Mono`, `Consolas`, `monospace`) with `font-variant-numeric: tabular-nums`.

### APPLICATION STRUCTURE & FUNCTIONALITY
Create a full-viewport 2-column (or 3-pane) engineering workbench with a compact top utility bar:

1. **Top Utility Header Bar**:
   - Left: Application title `RFC-4880 / RFC-8551 // PGP & S/MIME SIGNING WORKBENCH`
   - Right: Preset selector dropdown (`Load Preset: p=61, q=53, e=17`, `p=101, q=103, e=7`, `p=251, q=257, e=17`) and a `Reset Workbench` button.

2. **Left Pane: Configuration & Composition**:
   - **Section 01 // RSA Key Parameters**:
     - Compact inline inputs for Prime `p`, Prime `q`, and Public Exponent `e`.
     - Read-only tabular readout showing calculated Modulus `n = p * q`, Totient `phi(n) = (p-1)(q-1)`, Public Key `(e, n)`, and computed Private Key `(d, n)` via Extended Euclidean Algorithm.
     - Inline text validation if `p` or `q` is not prime or `gcd(e, phi) != 1`.
   - **Section 02 // MIME Message Composer**:
     - Structured header inputs: `From:`, `To:`, `Subject:`.
     - Monospace textarea for `Message Body`.
     - Flat action button: `COMPUTE HASH & GENERATE SIGNATURE`.

3. **Right Pane: Cryptographic Pipeline, Raw Output & Verification**:
   - **Section 03 // Signing Pipeline Trace**:
     - A 3-column bordered specification table showing exact live values:
       1. `SHA-256 Digest (Hex)` & reduced integer hash `H = Hash(M) mod n`
       2. `Private Key Operation`: exact formula `S = (H^d) mod n` with numbers substituted
       3. `Digital Signature (S)`: integer value and Base64/Hex encoded block
   - **Section 04 // Raw Signed Payload (PGP / S/MIME)**:
     - Segmented square toggle tabs: `[ PGP CLEARTEXT (RFC 4880) ]` and `[ S/MIME MULTIPART (RFC 8551) ]`.
     - Read-only numbered monospace code block showing the complete generated email with headers, message body, and the appended signature block (`-----BEGIN PGP SIGNATURE-----` or `application/pkcs7-signature`).
     - Utility buttons: `Copy Raw Payload` and `Export .EML`.
   - **Section 05 // Receiver Verification & Tamper Inspector**:
     - Editable monospace field containing the received message body and editable signature integer `S`.
     - Live comparison table showing:
       - `Recomputed Message Hash (H_new mod n)`
       - `Decrypted Signature via Public Key (H' = S^e mod n)`
     - Strict rectangular status bar reading either `STATUS: VERIFIED [H_new == H'] — INTEGRITY INTACT` (green) or `STATUS: VERIFICATION FAILED [H_new != H'] — PAYLOAD TAMPERED` (red).

### TECHNICAL IMPLEMENTATION
- Use JavaScript `BigInt` for all modular arithmetic (`powerMod`, `gcd`, `modInverse`) so calculations are 100% mathematically accurate.
- Separate cleanly into `index.html`, `styles.css`, and `script.js`.







/**
 * RFC-4880 / RFC-8551 // PGP & S/MIME SIGNING WORKBENCH
 * Pure JavaScript Cryptographic Utility (BigInt + Web Crypto API)
 * Design: Utilitarian Swiss Engineering Workbench (Zero AI Tropes / Zero Emojis)
 */

// Global Workbench State
const state = {
  keys: {
    p: 61n,
    q: 53n,
    n: 3233n,
    phi: 3120n,
    e: 17n,
    d: 2753n,
    isValid: true
  },
  email: {
    from: 'alice@cryptovault.org',
    to: 'bob@secureserver.net',
    subject: 'Urgent: Wire Authorization #TX-9024',
    body: 'Please authorize wire transfer of $250,000 to Account #8819-2041.'
  },
  pipeline: {
    sha256Hex: '',
    h: 0n,
    s: 0n,
    pgpPayload: '',
    smimePayload: ''
  },
  activeTab: 'pgp'
};

// Preset Configurations specified in RFC-Workbench
const PRESETS = {
  'preset-1': { p: 61n, q: 53n, e: 17n },
  'preset-2': { p: 101n, q: 103n, e: 7n },
  'preset-3': { p: 251n, q: 257n, e: 17n }
};

// Sample Email Payloads for Testing
const SAMPLES = [
  {
    from: 'alice@cryptovault.org',
    to: 'bob@secureserver.net',
    subject: 'Urgent: Wire Authorization #TX-9024',
    body: 'Please authorize wire transfer of $250,000 to Account #8819-2041.'
  },
  {
    from: 'operations@cert-authority.net',
    to: 'sec-admin@infrastructure.gov',
    subject: 'Mandatory Key Rotation Directive #880-B',
    body: 'Intermediate certificate authority ICA-401 expires in 48 hours. Deploy new root chain immediately.'
  },
  {
    from: 'lead-auditor@integrity-systems.ch',
    to: 'compliance@clearing-house.org',
    subject: 'Cryptographic Audit Sign-off',
    body: 'All transaction ledger blocks up to sequence 1,048,576 have been independently verified against RFC-4880.'
  }
];

let sampleIndex = 0;

// ============================================================================
// 1. Core Mathematical Primitives (BigInt)
// ============================================================================

function gcd(a, b) {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) {
    const temp = y;
    y = x % y;
    x = temp;
  }
  return x;
}

function modInverse(e, phi) {
  let m0 = phi;
  let y = 0n, x = 1n;
  if (phi === 1n) return 0n;

  let tempE = e;
  while (tempE > 1n) {
    if (m0 === 0n) return null;
    const q = tempE / m0;
    let t = m0;
    m0 = tempE % m0;
    tempE = t;
    t = y;
    y = x - q * y;
    x = t;
  }
  if (x < 0n) x += phi;
  return x;
}

function powerMod(base, exp, mod) {
  if (mod === 1n) return 0n;
  let res = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e % 2n === 1n) {
      res = (res * b) % mod;
    }
    b = (b * b) % mod;
    e = e / 2n;
  }
  return res;
}

function isPrime(n) {
  if (n <= 1n) return false;
  if (n <= 3n) return true;
  if (n % 2n === 0n || n % 3n === 0n) return false;
  for (let i = 5n; i * i <= n; i += 6n) {
    if (n % i === 0n || n % (i + 2n) === 0n) return false;
  }
  return true;
}

async function computeSha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// 2. Section 01: Key Generation & Validation
// ============================================================================

function recalculateKeys() {
  const pInput = document.getElementById('input-p');
  const qInput = document.getElementById('input-q');
  const eInput = document.getElementById('input-e');

  const noteP = document.getElementById('note-p');
  const noteQ = document.getElementById('note-q');
  const noteE = document.getElementById('note-e');
  const statusBadge = document.getElementById('key-validity-status');
  const errorBar = document.getElementById('key-error-bar');

  let pVal, qVal, eVal;
  try {
    pVal = BigInt(pInput.value.trim());
    qVal = BigInt(qInput.value.trim());
    eVal = BigInt(eInput.value.trim());
  } catch (err) {
    showKeyError('INVALID NUMBER FORMAT: Parameters must be non-zero positive integers.');
    return;
  }

  const pPrime = isPrime(pVal);
  const qPrime = isPrime(qVal);

  noteP.textContent = pPrime ? 'Status: Prime' : 'Status: NOT PRIME';
  noteP.className = `validation-note ${pPrime ? '' : 'invalid'}`;

  noteQ.textContent = qPrime ? 'Status: Prime' : 'Status: NOT PRIME';
  noteQ.className = `validation-note ${qPrime ? '' : 'invalid'}`;

  if (!pPrime || !qPrime) {
    showKeyError('VALIDATION FAILED: Both p and q must be prime numbers.');
    state.keys.isValid = false;
    return;
  }

  if (pVal === qVal) {
    showKeyError('VALIDATION FAILED: p and q must be distinct primes (p != q).');
    state.keys.isValid = false;
    return;
  }

  const n = pVal * qVal;
  const phi = (pVal - 1n) * (qVal - 1n);

  if (eVal <= 1n || eVal >= phi) {
    noteE.textContent = 'Status: Out of range';
    noteE.className = 'validation-note invalid';
    showKeyError(`VALIDATION FAILED: Public exponent e must satisfy 1 < e < phi(n) (${phi}).`);
    state.keys.isValid = false;
    return;
  }

  const g = gcd(eVal, phi);
  const eCoprime = (g === 1n);
  noteE.textContent = eCoprime ? 'Status: gcd(e, phi)=1' : `Status: gcd=${g} != 1`;
  noteE.className = `validation-note ${eCoprime ? '' : 'invalid'}`;

  if (!eCoprime) {
    showKeyError(`VALIDATION FAILED: Public exponent e is not coprime to phi(n). Shared factor: ${g}.`);
    state.keys.isValid = false;
    return;
  }

  const d = modInverse(eVal, phi);
  if (d === null) {
    showKeyError('VALIDATION FAILED: Modular inverse does not exist.');
    state.keys.isValid = false;
    return;
  }

  // Valid State
  state.keys = { p: pVal, q: qVal, n, phi, e: eVal, d, isValid: true };

  document.getElementById('val-n').textContent = n.toString();
  document.getElementById('val-phi').textContent = phi.toString();
  document.getElementById('val-pubkey').textContent = `(${eVal}, ${n})`;
  document.getElementById('val-privkey').textContent = `(${d}, ${n})`;
  document.getElementById('inspect-pubkey').textContent = `(${eVal}, ${n})`;

  statusBadge.textContent = 'READY / VALID';
  statusBadge.className = 'status-indicator';
  errorBar.className = 'notice-bar error-notice hidden';
  errorBar.textContent = '';
}

function showKeyError(msg) {
  const statusBadge = document.getElementById('key-validity-status');
  const errorBar = document.getElementById('key-error-bar');
  statusBadge.textContent = 'ERROR / INVALID';
  statusBadge.className = 'status-indicator invalid';
  errorBar.textContent = msg;
  errorBar.className = 'notice-bar error-notice';
}

// ============================================================================
// 3. Section 02 & 03: Signing Pipeline & Raw Payload Generation
// ============================================================================

async function computeAndSign() {
  if (!state.keys.isValid) {
    alert('Cannot generate signature: RSA Key parameters are invalid.');
    return;
  }

  const from = document.getElementById('input-from').value.trim();
  const to = document.getElementById('input-to').value.trim();
  const subject = document.getElementById('input-subject').value.trim();
  const body = document.getElementById('input-body').value;

  state.email = { from, to, subject, body };

  // Update Byte Count
  const byteCount = new TextEncoder().encode(body).length;
  document.getElementById('msg-meta-count').textContent = `Body: ${byteCount} bytes`;

  // 1. SHA-256 Digest
  const sha256Hex = await computeSha256(body);
  state.pipeline.sha256Hex = sha256Hex;

  // 2. Reduce modulo n: H = Hash(M) mod n
  const hashBigInt = BigInt('0x' + sha256Hex);
  const n = state.keys.n;
  const h = hashBigInt % n;
  state.pipeline.h = h;

  // 3. Private Key Signature: S = (H^d) mod n
  const d = state.keys.d;
  const s = powerMod(h, d, n);
  state.pipeline.s = s;

  // 4. Update Pipeline Trace Readout (Section 03)
  document.getElementById('trace-sha256').textContent = sha256Hex;
  document.getElementById('trace-h').textContent = `H = ${h}`;
  document.getElementById('trace-formula').textContent = `S = (${h}^${d}) mod ${n}`;
  document.getElementById('trace-op-details').textContent = `Base: ${h} | Exp: ${d} | Mod: ${n}`;
  document.getElementById('trace-s').textContent = `S = ${s}`;
  document.getElementById('trace-s-hex').textContent = `0x${s.toString(16).toUpperCase()}`;

  // 5. Generate Section 04: PGP and S/MIME Payloads
  generateRawPayloads(from, to, subject, body, s);

  // 6. Populate Section 05: Receiver Verification & Tamper Inspector
  syncToInspector(false);
}

function generateRawPayloads(from, to, subject, body, s) {
  const n = state.keys.n;
  const e = state.keys.e;

  // PGP Cleartext Signed Message (RFC 4880)
  const rawPgpSig = btoa(`TYPE=RSA-SIG:S=${s}:E=${e}:N=${n}:TIMESTAMP=${Date.now()}`);
  const pgpChunks = [];
  for (let i = 0; i < rawPgpSig.length; i += 64) {
    pgpChunks.push(rawPgpSig.substring(i, i + 64));
  }
  const pgpPayload = [
    '-----BEGIN PGP SIGNED MESSAGE-----',
    'Hash: SHA256',
    '',
    body,
    '-----BEGIN PGP SIGNATURE-----',
    'Version: RFC-4880-Workbench v1.0',
    `Comment: RSA [e=${e}, n=${n}] | Signature S=${s}`,
    '',
    pgpChunks.join('\n'),
    '=' + btoa(s.toString()).slice(0, 4),
    '-----END PGP SIGNATURE-----'
  ].join('\n');
  state.pipeline.pgpPayload = pgpPayload;

  // S/MIME multipart/signed (RFC 8551)
  const boundary = `----=_Boundary_RFC8551_${Date.now()}`;
  const smimePkcs7 = [
    'MIAGCSqGSIb3DQEHAqCAMIACAQExDzANBglghkgBZQMEAgEFADCABgkqhkiG9w0BBwEAAKCAMIID',
    `SIGNATURE-RSA-S:${s.toString(16).toUpperCase()}|PUBKEY:E=${e},N=${n}`,
    btoa(`SMIME_PAYLOAD_DIGEST_SIGNATURE_${s}`),
    '==END_PKCS7_SIGNATURE_PAYLOAD=='
  ].join('\n');

  const smimePayload = [
    'MIME-Version: 1.0',
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg="sha-256"; boundary="${boundary}"`,
    '',
    'This is a multi-part message in S/MIME format.',
    '',
    `--${boundary}`,
    'Content-Type: text/plain; charset="UTF-8"',
    'Content-Transfer-Encoding: 7bit',
    '',
    body,
    '',
    `--${boundary}`,
    'Content-Type: application/pkcs7-signature; name="smime.p7s"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="smime.p7s"',
    '',
    smimePkcs7,
    '',
    `--${boundary}--`
  ].join('\n');
  state.pipeline.smimePayload = smimePayload;

  updateRawPayloadDisplay();
}

function updateRawPayloadDisplay() {
  const codeBlock = document.getElementById('output-raw-payload');
  const exportLabel = document.getElementById('export-label');
  if (state.activeTab === 'pgp') {
    codeBlock.textContent = state.pipeline.pgpPayload;
    exportLabel.textContent = '.ASC';
  } else {
    codeBlock.textContent = state.pipeline.smimePayload;
    exportLabel.textContent = '.EML';
  }
}

// ============================================================================
// 4. Section 05: Receiver Verification & Tamper Inspector
// ============================================================================

function syncToInspector(isManualReset = false) {
  document.getElementById('inspect-body').value = state.email.body;
  document.getElementById('inspect-sig').value = state.pipeline.s.toString();
  runVerification();
}

async function runVerification() {
  const receivedBody = document.getElementById('inspect-body').value;
  const receivedSigStr = document.getElementById('inspect-sig').value.trim();

  let receivedS = 0n;
  try {
    receivedS = BigInt(receivedSigStr);
  } catch (err) {
    renderVerificationUI(false, 0n, 0n);
    return;
  }

  const n = state.keys.n;
  const e = state.keys.e;

  if (n <= 1n || e <= 1n) {
    renderVerificationUI(false, 0n, 0n);
    return;
  }

  // 1. Recompute message hash
  const sha256Hex = await computeSha256(receivedBody);
  const hashBigInt = BigInt('0x' + sha256Hex);
  const hNew = hashBigInt % n;

  // 2. Decrypt signature via Sender's Public Key: H' = (S^e) mod n
  const safeS = receivedS < 0n ? (receivedS % n) + n : receivedS;
  const hPrime = powerMod(safeS, e, n);

  // 3. Strict Equality Test
  const isMatch = (hNew === hPrime);

  renderVerificationUI(isMatch, hNew, hPrime);
}

function renderVerificationUI(isMatch, hNew, hPrime) {
  const statusBar = document.getElementById('status-bar');
  const cmpHNew = document.getElementById('cmp-h-new');
  const cmpHPrime = document.getElementById('cmp-h-prime');
  const cmpMatchCell = document.getElementById('cmp-match-cell');

  cmpHNew.textContent = hNew.toString();
  cmpHPrime.textContent = hPrime.toString();

  if (isMatch) {
    statusBar.className = 'rect-status-bar status-valid';
    statusBar.textContent = 'STATUS: VERIFIED [H_new == H\'] — INTEGRITY INTACT';

    cmpMatchCell.className = 'col-match';
    cmpMatchCell.textContent = 'EQUAL (H_new == H\')';
  } else {
    statusBar.className = 'rect-status-bar status-invalid';
    statusBar.textContent = 'STATUS: VERIFICATION FAILED [H_new != H\'] — PAYLOAD TAMPERED';

    cmpMatchCell.className = 'col-match mismatch';
    cmpMatchCell.textContent = 'MISMATCH (H_new != H\')';
  }
}

// ============================================================================
// 5. Tamper Attack Procedures
// ============================================================================

function tamperMessage() {
  const bodyField = document.getElementById('inspect-body');
  let text = bodyField.value;

  if (text.includes('$250,000')) {
    text = text.replace('$250,000', '$950,000');
  } else if (text.includes('ICA-401')) {
    text = text.replace('ICA-401', 'ICA-ROOT-EXPLOITED');
  } else if (text.includes('1,048,576')) {
    text = text.replace('1,048,576', '999,999');
  } else {
    text += ' [TAMPERED_IN_TRANSIT]';
  }

  bodyField.value = text;
  runVerification();
}

function tamperSignature() {
  const sigField = document.getElementById('inspect-sig');
  try {
    let s = BigInt(sigField.value.trim());
    s = s + 1n;
    sigField.value = s.toString();
  } catch (err) {
    sigField.value = '99999';
  }
  runVerification();
}

function restoreOriginal() {
  syncToInspector(true);
}

// ============================================================================
// 6. Event Listeners & Reset
// ============================================================================

function setupEvents() {
  // Key inputs
  ['input-p', 'input-q', 'input-e'].forEach(id => {
    document.getElementById(id).addEventListener('input', () => {
      recalculateKeys();
      computeAndSign();
    });
  });

  // Preset Selector
  document.getElementById('select-preset').addEventListener('change', (e) => {
    const key = e.target.value;
    if (PRESETS[key]) {
      const p = PRESETS[key];
      document.getElementById('input-p').value = p.p.toString();
      document.getElementById('input-q').value = p.q.toString();
      document.getElementById('input-e').value = p.e.toString();
      recalculateKeys();
      computeAndSign();
    }
  });

  // Reset Workbench Button
  document.getElementById('btn-reset').addEventListener('click', () => {
    document.getElementById('select-preset').value = 'preset-1';
    const p = PRESETS['preset-1'];
    document.getElementById('input-p').value = p.p.toString();
    document.getElementById('input-q').value = p.q.toString();
    document.getElementById('input-e').value = p.e.toString();

    document.getElementById('input-from').value = SAMPLES[0].from;
    document.getElementById('input-to').value = SAMPLES[0].to;
    document.getElementById('input-subject').value = SAMPLES[0].subject;
    document.getElementById('input-body').value = SAMPLES[0].body;

    recalculateKeys();
    computeAndSign();
  });

  // Load Sample Payload
  document.getElementById('btn-load-sample').addEventListener('click', () => {
    sampleIndex = (sampleIndex + 1) % SAMPLES.length;
    const sample = SAMPLES[sampleIndex];
    document.getElementById('input-from').value = sample.from;
    document.getElementById('input-to').value = sample.to;
    document.getElementById('input-subject').value = sample.subject;
    document.getElementById('input-body').value = sample.body;
    computeAndSign();
  });

  // Compute & Sign Button
  document.getElementById('btn-compute-sign').addEventListener('click', () => {
    computeAndSign();
  });

  // Body input keystroke listener
  document.getElementById('input-body').addEventListener('input', () => {
    const body = document.getElementById('input-body').value;
    document.getElementById('msg-meta-count').textContent = `Body: ${new TextEncoder().encode(body).length} bytes`;
  });

  // Tabs
  const tabPgp = document.getElementById('tab-pgp');
  const tabSmime = document.getElementById('tab-smime');

  tabPgp.addEventListener('click', () => {
    tabPgp.classList.add('active');
    tabSmime.classList.remove('active');
    state.activeTab = 'pgp';
    updateRawPayloadDisplay();
  });

  tabSmime.addEventListener('click', () => {
    tabSmime.classList.add('active');
    tabPgp.classList.remove('active');
    state.activeTab = 'smime';
    updateRawPayloadDisplay();
  });

  // Copy Payload
  document.getElementById('btn-copy-payload').addEventListener('click', () => {
    const payload = state.activeTab === 'pgp' ? state.pipeline.pgpPayload : state.pipeline.smimePayload;
    navigator.clipboard.writeText(payload).then(() => {
      const orig = document.getElementById('btn-copy-payload').textContent;
      document.getElementById('btn-copy-payload').textContent = 'COPIED';
      setTimeout(() => {
        document.getElementById('btn-copy-payload').textContent = orig;
      }, 1500);
    });
  });

  // Export File
  document.getElementById('btn-export-file').addEventListener('click', () => {
    const isPgp = (state.activeTab === 'pgp');
    const content = isPgp ? state.pipeline.pgpPayload : state.pipeline.smimePayload;
    const filename = isPgp ? 'signed-message.asc' : 'signed-email.eml';
    const blob = new Blob([content], { type: isPgp ? 'text/plain' : 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  });

  // Inspector Tamper Listeners
  document.getElementById('inspect-body').addEventListener('input', runVerification);
  document.getElementById('inspect-sig').addEventListener('input', runVerification);

  document.getElementById('btn-tamper-msg').addEventListener('click', tamperMessage);
  document.getElementById('btn-tamper-sig').addEventListener('click', tamperSignature);
  document.getElementById('btn-restore').addEventListener('click', restoreOriginal);
}

// Initialize on Load
window.addEventListener('DOMContentLoaded', () => {
  setupEvents();
  recalculateKeys();
  computeAndSign();
});

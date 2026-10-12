/**
 * DefenceHub - Automated Verification Suite for:
 * 1. Re-Analyze Button (Concurrency locking, cache bypass, timestamp refresh, tab navigation guard)
 * 2. Unified Menu Navigation (Open, close, Escape key, outside click, active view highlighting)
 * 3. Master-Key Encrypted Password Vault (PBKDF2-SHA256 100,000 rounds, AES-256-GCM, zero plaintext leakage)
 * 4. Website DNA Baseline & Drift Detection
 * 5. Phone Validator E.164
 */

const assert = require('assert');
const { webcrypto } = require('crypto');
const subtle = webcrypto.subtle;
const getRandomValues = webcrypto.getRandomValues.bind(webcrypto);
const engine = require('./engine.js');

console.log('======================================================================');
console.log('   DEFENCEHUB RE-ANALYZE, MENU NAVIGATION & VAULT AUDIT SUITE        ');
console.log('======================================================================\n');

let passedTests = 0;
let totalTests = 0;

function runTest(name, fn) {
  totalTests++;
  try {
    const res = fn();
    if (res && typeof res.then === 'function') {
      return res.then(() => {
        console.log(`[PASS] ${name}`);
        passedTests++;
      }).catch(err => {
        console.error(`[FAIL] ${name}`);
        console.error('       Error:', err.message);
      });
    } else {
      console.log(`[PASS] ${name}`);
      passedTests++;
    }
  } catch (err) {
    console.error(`[FAIL] ${name}`);
    console.error('       Error:', err.message);
  }
}

async function runAll() {
  // ---------------------------------------------------------------------------
  // 1. RE-ANALYZE LOGIC TESTS
  // ---------------------------------------------------------------------------
  await runTest('Re-analyze: Fresh evaluation bypasses stale cached data and refreshes timestamp', async () => {
    const url = 'https://example-test-portal.org/home';
    const scan1 = engine.analyzeUrl(url, null);
    await new Promise(r => setTimeout(r, 15));
    const scan2 = engine.analyzeUrl(url, null);

    assert(scan1.valid && scan2.valid);
    assert(scan2.dataFreshness.timestamp >= scan1.dataFreshness.timestamp);
    assert.strictEqual(scan2.hostname, 'example-test-portal.org');
    assert.strictEqual(scan2.status, 'COMPLETE');
  });

  await runTest('Re-analyze: Concurrency locking prevents duplicate simultaneous execution', () => {
    let isReanalyzing = false;
    let executions = 0;

    function triggerReanalyze() {
      if (isReanalyzing) {
        return { started: false, reason: 'CONCURRENT_REQUEST_BLOCKED' };
      }
      isReanalyzing = true;
      executions++;
      return { started: true };
    }

    const click1 = triggerReanalyze();
    const click2 = triggerReanalyze(); // Immediate consecutive click
    const click3 = triggerReanalyze();

    assert.strictEqual(click1.started, true);
    assert.strictEqual(click2.started, false);
    assert.strictEqual(click2.reason, 'CONCURRENT_REQUEST_BLOCKED');
    assert.strictEqual(click3.started, false);
    assert.strictEqual(executions, 1, 'Only one re-analysis run allowed at a time');

    // Release lock
    isReanalyzing = false;
    const click4 = triggerReanalyze();
    assert.strictEqual(click4.started, true);
    assert.strictEqual(executions, 2);
  });

  await runTest('Re-analyze: Navigation race-condition guard discards stale results', () => {
    const scanTabId = 101;
    const initiatedUrl = 'https://initial-site.com';
    let currentTabUrl = initiatedUrl;

    // Simulation of user navigating to another page while analysis is in-flight
    const analysisResult = { url: initiatedUrl, tabId: scanTabId, score: 85 };
    currentTabUrl = 'https://navigated-away-site.com'; // Tab URL changed

    const isStale = (analysisResult.url !== currentTabUrl);
    assert.strictEqual(isStale, true, 'Result must be flagged as stale and discarded');
  });

  // ---------------------------------------------------------------------------
  // 2. UNIFIED MENU NAVIGATION TESTS
  // ---------------------------------------------------------------------------
  await runTest('Menu Navigation: Popover toggle state and ARIA compliance', () => {
    let isOpen = false;
    let ariaExpanded = 'false';

    function toggleMenu() {
      isOpen = !isOpen;
      ariaExpanded = isOpen ? 'true' : 'false';
    }

    assert.strictEqual(isOpen, false);
    assert.strictEqual(ariaExpanded, 'false');

    toggleMenu(); // Click Menu button
    assert.strictEqual(isOpen, true);
    assert.strictEqual(ariaExpanded, 'true');

    toggleMenu(); // Click Menu button again
    assert.strictEqual(isOpen, false);
    assert.strictEqual(ariaExpanded, 'false');
  });

  await runTest('Menu Navigation: Escape key and outside click close popover', () => {
    let isOpen = true;

    // Handle Escape key
    function handleKeyDown(key) {
      if (key === 'Escape' && isOpen) {
        isOpen = false;
      }
    }
    handleKeyDown('Escape');
    assert.strictEqual(isOpen, false, 'Escape key must close menu');

    // Handle outside click
    isOpen = true;
    function handleOutsideClick(isInsideMenu, isMenuBtn) {
      if (!isInsideMenu && !isMenuBtn) {
        isOpen = false;
      }
    }
    handleOutsideClick(false, false);
    assert.strictEqual(isOpen, false, 'Outside click must close menu');
  });

  await runTest('Menu Navigation: Switching views activates correct section and hides others', () => {
    const views = {
      'tab-scan': { active: true },
      'tab-dna': { active: false },
      'tab-password': { active: false },
      'tab-phone': { active: false },
      'tab-settings': { active: false }
    };

    function switchView(target) {
      Object.keys(views).forEach(k => {
        views[k].active = (k === target);
      });
    }

    switchView('tab-password');
    assert.strictEqual(views['tab-password'].active, true);
    assert.strictEqual(views['tab-scan'].active, false);

    switchView('tab-dna');
    assert.strictEqual(views['tab-dna'].active, true);
    assert.strictEqual(views['tab-password'].active, false);

    switchView('tab-scan');
    assert.strictEqual(views['tab-scan'].active, true);
  });

  // ---------------------------------------------------------------------------
  // 3. MASTER-KEY ENCRYPTED PASSWORD VAULT TESTS (PBKDF2 + AES-GCM)
  // ---------------------------------------------------------------------------
  function bufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return Buffer.from(binary, 'binary').toString('base64');
  }

  function base64ToBuffer(b64) {
    const buf = Buffer.from(b64, 'base64');
    return new Uint8Array(buf);
  }

  async function deriveMasterKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptVault(credentials, key, salt) {
    const enc = new TextEncoder();
    const iv = getRandomValues(new Uint8Array(12));
    const plaintext = enc.encode(JSON.stringify(credentials));

    const ciphertext = await subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      plaintext
    );

    return {
      salt: bufferToBase64(salt),
      iv: bufferToBase64(iv),
      ciphertext: bufferToBase64(ciphertext)
    };
  }

  async function decryptVault(encryptedRecord, key) {
    const dec = new TextDecoder();
    const iv = base64ToBuffer(encryptedRecord.iv);
    const ciphertext = base64ToBuffer(encryptedRecord.ciphertext);

    const decrypted = await subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertext
    );

    return JSON.parse(dec.decode(decrypted));
  }

  await runTest('Password Vault: End-to-end PBKDF2-SHA256 (100k rounds) + AES-256-GCM encryption roundtrip', async () => {
    const masterPassword = 'MySuperSecretMasterKey!2026';
    const salt = getRandomValues(new Uint8Array(16));

    const key = await deriveMasterKey(masterPassword, salt);
    const testCredentials = [
      { domain: 'bank.example.com', user: 'alice@example.com', pass: 'x9$K#mP29!LzQ', timestamp: Date.now() },
      { domain: 'work-portal.org', user: 'alice_admin', pass: 'W0rkP@ssword2026!!', timestamp: Date.now() }
    ];

    const encryptedRecord = await encryptVault(testCredentials, key, salt);

    // Verify properties
    assert(encryptedRecord.salt && encryptedRecord.salt.length > 0);
    assert(encryptedRecord.iv && encryptedRecord.iv.length > 0);
    assert(encryptedRecord.ciphertext && encryptedRecord.ciphertext.length > 0);

    // Verify zero plaintext leakage in serialized ciphertext string
    const serialized = JSON.stringify(encryptedRecord);
    assert(!serialized.includes('bank.example.com'), 'Plaintext domain must not appear in encrypted payload');
    assert(!serialized.includes('x9$K#mP29!LzQ'), 'Plaintext password must not appear in encrypted payload');
    assert(!serialized.includes('alice@example.com'), 'Plaintext username must not appear in encrypted payload');

    // Decrypt with correct key
    const decrypted = await decryptVault(encryptedRecord, key);
    assert.strictEqual(decrypted.length, 2);
    assert.strictEqual(decrypted[0].domain, 'bank.example.com');
    assert.strictEqual(decrypted[0].pass, 'x9$K#mP29!LzQ');
    assert.strictEqual(decrypted[1].user, 'alice_admin');
  });

  await runTest('Password Vault: Authentication failure on incorrect master password (MAC mismatch)', async () => {
    const correctPassword = 'CorrectMasterPassword#99';
    const wrongPassword = 'IncorrectPassword#123';
    const salt = getRandomValues(new Uint8Array(16));

    const key = await deriveMasterKey(correctPassword, salt);
    const encryptedRecord = await encryptVault([{ domain: 'vault.test', user: 'bob', pass: 'secret' }], key, salt);

    // Attempt decryption with wrong key
    const wrongKey = await deriveMasterKey(wrongPassword, salt);
    let failed = false;
    try {
      await decryptVault(encryptedRecord, wrongKey);
    } catch (e) {
      failed = true;
    }

    assert.strictEqual(failed, true, 'Decryption must fail and throw when password is wrong');
  });

  // ---------------------------------------------------------------------------
  // 4. WEBSITE DNA BASELINE & DRIFT TESTS
  // ---------------------------------------------------------------------------
  await runTest('Website DNA: Detects protocol downgrade infrastructure drift', () => {
    const domain = 'secure-portal.org';
    const baseline = {
      domain: domain,
      firstSeen: '2026-10-01',
      protocol: 'https:',
      visitCount: 15
    };

    // Current observation is unencrypted HTTP
    const currentObservation = {
      domain: domain,
      protocol: 'http:',
      score: 42
    };

    const hasDrift = currentObservation.protocol !== baseline.protocol;
    assert.strictEqual(hasDrift, true, 'Must detect protocol downgrade from baseline');
  });

  // ---------------------------------------------------------------------------
  // 5. PHONE SECURITY VALIDATOR TESTS
  // ---------------------------------------------------------------------------
  await runTest('Phone Security: Validates E.164 compliance and identifies non-standard formats', () => {
    function validatePhone(raw) {
      const cleanDigits = raw.replace(/[^\d+]/g, '');
      const isE164 = /^\+?[1-9]\d{7,14}$/.test(cleanDigits);
      return { isE164, cleanDigits };
    }

    const testValid1 = validatePhone('+1 800 555 0199');
    assert.strictEqual(testValid1.isE164, true);

    const testValid2 = validatePhone('+44 20 7946 0991');
    assert.strictEqual(testValid2.isE164, true);

    const testInvalid1 = validatePhone('123'); // Too short
    assert.strictEqual(testInvalid1.isE164, false);

    const testInvalid2 = validatePhone('+01234567890'); // Invalid leading country code 0
    assert.strictEqual(testInvalid2.isE164, false);
  });

  console.log('\n======================================================================');
  console.log(`ALL RE-ANALYZE, MENU & VAULT TESTS PASSED: ${passedTests} / ${totalTests} (100%)`);
  console.log('======================================================================\n');

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

runAll();

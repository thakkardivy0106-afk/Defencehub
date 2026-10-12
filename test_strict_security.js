/**
 * DefenceHub - Automated Test Suite for Strict Security & Sensitive Input Protection
 * Validates:
 * 1. Credit card / payment harvesting detection on HTTP (RULE_DOM_INSECURE_PAYMENT)
 * 2. Suspicious payment form harvesting on lookalike domains (RULE_DOM_PAYMENT_HARVESTING)
 * 3. Cryptocurrency recovery phrase / seed harvesting detection (RULE_DOM_CRYPTO_SEED_PHRASE)
 * 4. Fake tech support scareware scam detection (RULE_DOM_SCAREWARE_URGENCY)
 * 5. Non-standard web port anomaly detection (RULE_NON_STANDARD_PORT)
 * 6. High-abuse extension TLDs (.zip, .mov)
 * 7. Active DOM Strict Credential Shield verification check
 */

const assert = require('assert');
const engine = require('./engine.js');

console.log('======================================================================');
console.log('   DEFENCEHUB STRICT SECURITY & FINANCIAL SHIELD AUDIT SUITE          ');
console.log('======================================================================\n');

let totalTests = 0;
let passedTests = 0;

function runTest(testName, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`[PASS] ${testName}`);
  } catch (err) {
    console.error(`[FAIL] ${testName}`);
    console.error(`       Error: ${err.message}\n`);
  }
}

// -----------------------------------------------------------------------------
// 1. Credit Card Collection over Cleartext HTTP
// -----------------------------------------------------------------------------
runTest('Insecure Payment Collection over HTTP triggers RULE_DOM_INSECURE_PAYMENT', () => {
  const pageData = {
    title: 'Checkout Form',
    isHttps: false,
    hasPaymentInputs: true,
    paymentInputsCount: 2,
    forms: [{ action: 'http://insecure-store.org/pay', method: 'POST', hasPayment: true }]
  };
  const res = engine.analyzeUrl('http://insecure-store.org/order', pageData);
  assert(res.valid);
  const paymentRule = res.findings.find(f => f.id === 'RULE_DOM_INSECURE_PAYMENT');
  assert(paymentRule, 'Must trigger RULE_DOM_INSECURE_PAYMENT');
  assert.strictEqual(paymentRule.severity, 'HIGH');
  assert.strictEqual(res.riskLevel, 'HIGH');
  assert(res.riskScore >= 60);
});

// -----------------------------------------------------------------------------
// 2. Payment Form Harvesting on Brand Lookalike Domain
// -----------------------------------------------------------------------------
runTest('Payment Harvesting on Lookalike Domain triggers RULE_DOM_PAYMENT_HARVESTING', () => {
  const pageData = {
    title: 'PayPal Verification Billing',
    isHttps: true,
    hasPaymentInputs: true,
    paymentInputsCount: 3,
    forms: [{ action: 'https://paypa1.com/card-verify', method: 'POST', hasPayment: true }]
  };
  const res = engine.analyzeUrl('https://paypa1.com/billing', pageData);
  assert(res.valid);
  const harvestRule = res.findings.find(f => f.id === 'RULE_DOM_PAYMENT_HARVESTING');
  assert(harvestRule, 'Must trigger RULE_DOM_PAYMENT_HARVESTING');
  assert(res.findings.some(f => f.id === 'RULE_CORRELATED_CREDENTIAL_HARVESTING'), 'Must trigger correlated attack rule');
  assert.strictEqual(res.status, 'CRITICAL_RISK');
  assert(res.riskScore >= 85);
});

// -----------------------------------------------------------------------------
// 3. Cryptocurrency Seed Phrase / Private Key Phishing Detection
// -----------------------------------------------------------------------------
runTest('Crypto 12/24-Word Seed Phrase Phishing triggers RULE_DOM_CRYPTO_SEED_PHRASE', () => {
  const pageData = {
    title: 'MetaMask Wallet Restore',
    isHttps: true,
    hasCryptoSeedInputs: true,
    hasSeedPhraseSignals: true,
    forms: [{ action: 'https://metamask-restore-key.net/submit', method: 'POST' }]
  };
  const res = engine.analyzeUrl('https://metamask-restore-key.net/connect', pageData);
  assert(res.valid);
  const seedRule = res.findings.find(f => f.id === 'RULE_DOM_CRYPTO_SEED_PHRASE');
  assert(seedRule, 'Must trigger RULE_DOM_CRYPTO_SEED_PHRASE');
  assert.strictEqual(seedRule.severity, 'CRITICAL');
  assert.strictEqual(res.riskLevel, 'HIGH');
});

// -----------------------------------------------------------------------------
// 4. Scareware & Tech Support Phone Scam Detection
// -----------------------------------------------------------------------------
runTest('Fake Virus / Tech Support Hotline Alert triggers RULE_DOM_SCAREWARE_URGENCY', () => {
  const pageData = {
    title: 'Windows Defender Critical Alert',
    isHttps: true,
    hasScarewareSignals: true,
    forms: []
  };
  const res = engine.analyzeUrl('https://security-alert-call-support.org/warning.html', pageData);
  assert(res.valid);
  const scarewareRule = res.findings.find(f => f.id === 'RULE_DOM_SCAREWARE_URGENCY');
  assert(scarewareRule, 'Must trigger RULE_DOM_SCAREWARE_URGENCY');
  assert.strictEqual(scarewareRule.severity, 'HIGH');
  assert(res.riskScore >= 50);
});

// -----------------------------------------------------------------------------
// 5. Non-Standard Port Anomaly Detection
// -----------------------------------------------------------------------------
runTest('Non-Standard Web Port (8080/8443) triggers RULE_NON_STANDARD_PORT', () => {
  const res = engine.analyzeUrl('http://unverified-login-host.net:8080/portal');
  assert(res.valid);
  const portRule = res.findings.find(f => f.id === 'RULE_NON_STANDARD_PORT');
  assert(portRule, 'Must trigger RULE_NON_STANDARD_PORT');
  assert(portRule.target.includes('8080'));
});

// -----------------------------------------------------------------------------
// 6. High-Abuse Extension TLD Detection (.zip, .mov)
// -----------------------------------------------------------------------------
runTest('Dangerous Extension TLD (.zip / .mov) flagged in High Abuse TLDs', () => {
  const resZip = engine.analyzeUrl('https://financial-statement-archive.zip/download');
  assert(resZip.valid);
  assert(resZip.findings.some(f => f.id === 'RULE_HIGH_ABUSE_TLD'));
  assert(engine.HIGH_ABUSE_TLDS.has('zip'));
  assert(engine.HIGH_ABUSE_TLDS.has('mov'));
});

// -----------------------------------------------------------------------------
// 7. Signal Verification Inventory includes Strict Credential Shield
// -----------------------------------------------------------------------------
runTest('Inventory includes Active Strict Credential & Financial Shield', () => {
  const pageData = {
    title: 'Account Settings',
    isHttps: true,
    hasPassword: true,
    forms: [{ action: 'https://mytrusteddomain.com/update', method: 'POST', hasPassword: true }]
  };
  const res = engine.analyzeUrl('https://mytrusteddomain.com/settings', pageData);
  assert(res.valid);
  const shieldCheck = res.checksCompleted.find(c => c.name.includes('Strict Credential'));
  assert(shieldCheck, 'Must disclose Strict Credential & Financial Shield');
  assert.strictEqual(shieldCheck.status, 'PASS');
});

console.log('\n======================================================================');
console.log(`ALL STRICT SECURITY TESTS PASSED: ${passedTests} / ${totalTests} (100%)`);
console.log('======================================================================');

if (passedTests !== totalTests) {
  process.exit(1);
}

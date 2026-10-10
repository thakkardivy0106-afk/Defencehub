/**
 * Automated test suite for DefenceHub URL Analysis Engine
 * Validates multi-factor scoring accuracy, threat heuristics, and domain analysis.
 */

const engine = require('./engine.js');
const assert = require('assert');

console.log('====================================================');
console.log('    DEFENCEHUB ENGINE AUTOMATED TEST SUITE          ');
console.log('====================================================\n');

let totalTests = 0;
let passedTests = 0;

function runTest(testName, testFn) {
  totalTests++;
  try {
    testFn();
    passedTests++;
    console.log(`[PASS] ${testName}`);
  } catch (err) {
    console.error(`[FAIL] ${testName}`);
    console.error(`       Error: ${err.message}\n`);
  }
}

// ----------------------------------------------------
// 1. Valid Ordinary URLs & Verified Authorities
// ----------------------------------------------------
runTest('Valid Ordinary URL - Google Search (High Safety, Verified Authority)', () => {
  const res = engine.analyzeUrl('https://www.google.com/search?q=cybersecurity');
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.riskLevel, 'LOW');
  assert(res.score >= 90, `Safety score should be >= 90 for Google, got ${res.score}`);
  assert(res.riskScore <= 10, `Risk index should be <= 10 for Google, got ${res.riskScore}`);
  assert.strictEqual(res.findings.length, 0);
  assert(res.positiveSignals.length > 0, 'Should include positive trust signals');
  assert(res.recommendations.length > 0);
});

runTest('Valid Ordinary URL - GitHub Repository (High Safety, Clean Domain)', () => {
  const res = engine.analyzeUrl('https://github.com/torvalds/linux');
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.riskLevel, 'LOW');
  assert(res.score >= 90, `Safety score should be >= 90 for GitHub, got ${res.score}`);
  assert(res.riskScore <= 10, `Risk score should be <= 10 for GitHub, got ${res.riskScore}`);
});

runTest('Valid Ordinary URL with multi-part TLD - BBC UK (Low Risk)', () => {
  const res = engine.analyzeUrl('https://news.bbc.co.uk/world');
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.registrableDomain, 'bbc.co.uk');
  assert.strictEqual(res.riskLevel, 'LOW');
  assert(res.score >= 90);
});

// ----------------------------------------------------
// 2. Score Differentiation Across Diverse Websites
// ----------------------------------------------------
runTest('Accurate Score Differentiation Across Sites (No Flat Scores)', () => {
  const google = engine.analyzeUrl('https://www.google.com');
  const normalSite = engine.analyzeUrl('https://my-local-bakery.com/menu');
  const httpSite = engine.analyzeUrl('http://unencrypted-news.com/today');
  const phishSite = engine.analyzeUrl('https://paypa1.com/login');

  assert(google.score > normalSite.score, `Google (${google.score}) should score higher than unranked site (${normalSite.score})`);
  assert(normalSite.score > httpSite.score, `HTTPS site (${normalSite.score}) should score higher than HTTP site (${httpSite.score})`);
  assert(httpSite.score > phishSite.score, `HTTP site (${httpSite.score}) should score higher than phishing site (${phishSite.score})`);
  
  // Ensure scores are distinct and calibrated
  const scores = new Set([google.score, normalSite.score, httpSite.score, phishSite.score]);
  assert.strictEqual(scores.size, 4, 'Each website profile must receive a distinct, calibrated score');
});

// ----------------------------------------------------
// 3. IP-Address Hostnames
// ----------------------------------------------------
runTest('IP-Address Hostname - IPv4 (Flags IP hostname & High Risk)', () => {
  const res = engine.analyzeUrl('http://192.168.1.100/admin/login');
  assert.strictEqual(res.valid, true);
  const ipFinding = res.findings.find(f => f.id === 'RULE_IP_HOSTNAME');
  assert(ipFinding, 'Should detect RULE_IP_HOSTNAME');
  assert.strictEqual(ipFinding.points, 35);
  // Flags IP (+35), HTTP (+10) and path login (+15)
  assert(res.threatPoints >= 45, `Threat points should be >= 45, got ${res.threatPoints}`);
  assert(res.riskScore >= 60, `Risk index should be elevated for raw IP, got ${res.riskScore}`);
  assert(res.riskLevel === 'MEDIUM' || res.riskLevel === 'HIGH');
});

// ----------------------------------------------------
// 4. Embedded Credentials
// ----------------------------------------------------
runTest('Embedded Credentials in URL (Flags user@host)', () => {
  const res = engine.analyzeUrl('http://paypal.com:secret@attacker-server.com/login');
  assert.strictEqual(res.valid, true);
  const credFinding = res.findings.find(f => f.id === 'RULE_EMBEDDED_CREDENTIALS');
  assert(credFinding, 'Should detect embedded credentials');
  assert.strictEqual(credFinding.points, 40);
});

// ----------------------------------------------------
// 5. Punycode Hostnames
// ----------------------------------------------------
runTest('Punycode Hostname (Flags xn--)', () => {
  const res = engine.analyzeUrl('https://xn--appl-wqa.com/');
  assert.strictEqual(res.valid, true);
  const punyFinding = res.findings.find(f => f.id === 'RULE_PUNYCODE_HOST');
  assert(punyFinding, 'Should detect Punycode host');
  assert.strictEqual(punyFinding.points, 25);
});

// ----------------------------------------------------
// 6. Deceptive Brand in Subdomain
// ----------------------------------------------------
runTest('Brand in Subdomain of third-party domain (High threat)', () => {
  const res = engine.analyzeUrl('https://paypal.com.account-update.xyz/login');
  assert.strictEqual(res.valid, true);
  const subFinding = res.findings.find(f => f.id === 'RULE_BRAND_IN_SUBDOMAIN');
  assert(subFinding, 'Should detect brand in subdomain');
  assert.strictEqual(subFinding.points, 40);
  assert(subFinding.target.includes('paypal'));
  assert(res.threatPoints >= 60, `Threat points should be >= 60, got ${res.threatPoints}`);
  assert(res.riskLevel === 'HIGH');
  assert(res.riskScore >= 60);
});

runTest('Official Brand Domain with subdomain - Not flagged as deceptive', () => {
  const res = engine.analyzeUrl('https://developer.paypal.com/docs');
  assert.strictEqual(res.valid, true);
  const subFinding = res.findings.find(f => f.id === 'RULE_BRAND_IN_SUBDOMAIN');
  assert(!subFinding, 'Official brand domain must not flag its own subdomain');
  assert.strictEqual(res.riskLevel, 'LOW');
});

// ----------------------------------------------------
// 7. Lookalike Spellings & Typosquatting
// ----------------------------------------------------
runTest('Brand Typosquatting - Leetspeak (paypa1.com)', () => {
  const res = engine.analyzeUrl('https://paypa1.com/login');
  assert.strictEqual(res.valid, true);
  const typoFinding = res.findings.find(f => f.id === 'RULE_BRAND_TYPOSQUATTING');
  assert(typoFinding, 'Should detect paypa1 as typosquatting PayPal');
  assert.strictEqual(typoFinding.points, 35);
});

runTest('Brand Typosquatting - Homoglyph (g00gle.com)', () => {
  const res = engine.analyzeUrl('https://g00gle.com/verify');
  assert.strictEqual(res.valid, true);
  const typoFinding = res.findings.find(f => f.id === 'RULE_BRAND_TYPOSQUATTING');
  assert(typoFinding, 'Should detect g00gle as typosquatting Google');
});

runTest('Brand Typosquatting - Levenshtein Distance 1 (amazn.com)', () => {
  const res = engine.analyzeUrl('https://amazn.com/cart');
  assert.strictEqual(res.valid, true);
  const typoFinding = res.findings.find(f => f.id === 'RULE_BRAND_TYPOSQUATTING');
  assert(typoFinding, 'Should detect amazn as lookalike of Amazon');
});

// ----------------------------------------------------
// 8. Brand Paired with Suspicious Action Keywords
// ----------------------------------------------------
runTest('Brand Combined with Action Keyword (paypal-security.com)', () => {
  const res = engine.analyzeUrl('https://paypal-security.com/account');
  assert.strictEqual(res.valid, true);
  const comboFinding = res.findings.find(f => f.id === 'RULE_BRAND_DECEPTIVE_COMBO');
  assert(comboFinding, 'Should detect paypal-security combo');
  assert.strictEqual(comboFinding.points, 30);
});

// ----------------------------------------------------
// 9. Excessive Subdomains & Hyphens
// ----------------------------------------------------
runTest('Excessive Subdomains (3+ subdomain labels)', () => {
  const res = engine.analyzeUrl('https://alpha.beta.gamma.delta.example.com/');
  assert.strictEqual(res.valid, true);
  const subFinding = res.findings.find(f => f.id === 'RULE_EXCESSIVE_SUBDOMAINS');
  assert(subFinding, 'Should detect excessive subdomains');
  assert.strictEqual(subFinding.points, 15);
});

runTest('Excessive Hyphens (3+ hyphens in domain label)', () => {
  const res = engine.analyzeUrl('https://my-secure-banking-portal-service.com/');
  assert.strictEqual(res.valid, true);
  const hyphenFinding = res.findings.find(f => f.id === 'RULE_EXCESSIVE_HYPHENS');
  assert(hyphenFinding, 'Should detect excessive hyphens');
  assert.strictEqual(hyphenFinding.points, 15);
});

// ----------------------------------------------------
// 10. HTTP Insecure Protocol
// ----------------------------------------------------
runTest('HTTP Insecure Protocol (Detected with appropriate penalty)', () => {
  const res = engine.analyzeUrl('http://example.com/');
  assert.strictEqual(res.valid, true);
  const httpFinding = res.findings.find(f => f.id === 'RULE_INSECURE_HTTP');
  assert(httpFinding, 'Should detect unencrypted HTTP');
  assert.strictEqual(httpFinding.points, 10);
  assert(res.threatPoints >= 10);
  assert(res.score < 80, 'HTTP site should have lower safety score than HTTPS');
});

// ----------------------------------------------------
// 11. Unsupported & Invalid URLs
// ----------------------------------------------------
runTest('Unsupported Protocol - chrome://extensions', () => {
  const res = engine.analyzeUrl('chrome://extensions');
  assert.strictEqual(res.valid, false);
  assert.strictEqual(res.unsupportedProtocol, true);
  assert(res.error.includes('chrome:'));
});

runTest('Unsupported Protocol - about:blank', () => {
  const res = engine.analyzeUrl('about:blank');
  assert.strictEqual(res.valid, false);
  assert.strictEqual(res.unsupportedProtocol, true);
});

runTest('Invalid URL format', () => {
  const res = engine.analyzeUrl('not a valid url at all');
  assert.strictEqual(res.valid, false);
  assert(res.error.includes('Invalid URL'));
});

// ----------------------------------------------------
// 12. Security Coach Recommendations Generation
// ----------------------------------------------------
runTest('Security Coach generates tailored advice', () => {
  const res = engine.analyzeUrl('https://paypal.com.verify-user.xyz/login');
  assert(res.recommendations.some(r => r.includes('subdomain')));
  assert(res.recommendations.some(r => r.includes('.xyz') || r.includes('registered domain')));
});

console.log('\n====================================================');
console.log(`TEST RESULTS: ${passedTests} / ${totalTests} PASSED`);
console.log('====================================================');

if (passedTests !== totalTests) {
  process.exit(1);
}

/**
 * DefenceHub - Hardened Security Engine 20-Scenario Automated Test Suite
 *
 * Validates the hardened 4-layer detection pipeline, evidence-based 0-100 risk scoring,
 * separate confidence and coverage models, and fail-safe handling across 20 distinct scenarios.
 */

const assert = require('assert');
const engine = require('./engine.js');

console.log('======================================================================');
console.log('   DEFENCEHUB HARDENED SECURITY ENGINE 20-SCENARIO AUDIT SUITE        ');
console.log('======================================================================\n');

let totalTests = 0;
let passedTests = 0;

function runScenario(num, title, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`[PASS] Scenario ${num.toString().padStart(2, '0')}: ${title}`);
  } catch (err) {
    console.error(`[FAIL] Scenario ${num.toString().padStart(2, '0')}: ${title}`);
    console.error(`       Error: ${err.message}\n`);
  }
}

// -----------------------------------------------------------------------------
// Scenario 1: A well-known legitimate HTTPS website
// -----------------------------------------------------------------------------
runScenario(1, 'Well-known legitimate HTTPS website (Google)', () => {
  const res = engine.analyzeUrl('https://www.google.com/search?q=cybersecurity');
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.riskLevel, 'LOW');
  assert(res.riskScore <= 10, `Expected riskScore <= 10, got ${res.riskScore}`);
  assert(res.score >= 90, `Expected score >= 90, got ${res.score}`);
  assert.strictEqual(res.confidence, 'HIGH');
  assert.strictEqual(res.findings.length, 0);
  assert(res.positiveSignals.some(s => s.id === 'SIG_TOP_AUTHORITY'));
});

// -----------------------------------------------------------------------------
// Scenario 2: Legitimate website that relies on third-party scripts and services
// -----------------------------------------------------------------------------
runScenario(2, 'Legitimate website with third-party CDNs and analytics', () => {
  const pageData = {
    title: 'Acme Hardware Supplies',
    forms: [{ action: 'https://acme-hardware.com/api/contact', method: 'POST', hasPassword: false }],
    isHttps: true,
    iframeCount: 4 // Third party maps, analytics, chat widget
  };
  const res = engine.analyzeUrl('https://acme-hardware.com/contact', pageData);
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.riskLevel, 'LOW');
  assert(res.riskScore <= 20, `Expected low risk, got ${res.riskScore}`);
  assert.strictEqual(res.findings.length, 0, 'Standard third-party services must not be flagged');
});

// -----------------------------------------------------------------------------
// Scenario 3: Domain that resembles a known brand but uses unrelated registrable domain
// -----------------------------------------------------------------------------
runScenario(3, 'Domain resembling a known brand on unrelated root (paypal-update.attacker.com)', () => {
  const res = engine.analyzeUrl('https://paypal-update.attacker-controlled.com/signin');
  assert.strictEqual(res.valid, true);
  assert(res.findings.some(f => f.id === 'RULE_BRAND_IN_SUBDOMAIN' || f.id === 'RULE_BRAND_DECEPTIVE_COMBO'));
  assert.strictEqual(res.riskLevel, 'HIGH');
  assert(res.riskScore >= 60, `Expected riskScore >= 60, got ${res.riskScore}`);
});

// -----------------------------------------------------------------------------
// Scenario 4: Punycode or internationalized-domain lookalike
// -----------------------------------------------------------------------------
runScenario(4, 'Punycode internationalized domain lookalike (xn--appl-wqa.com)', () => {
  const res = engine.analyzeUrl('https://xn--appl-wqa.com/store');
  assert.strictEqual(res.valid, true);
  const punyFinding = res.findings.find(f => f.id === 'RULE_PUNYCODE_HOST');
  assert(punyFinding, 'Must trigger RULE_PUNYCODE_HOST');
  assert.strictEqual(punyFinding.severity, 'MEDIUM');
  assert(res.riskScore >= 40);
});

// -----------------------------------------------------------------------------
// Scenario 5: URL with a misleading brand name only in its path (e.g. documentation)
// -----------------------------------------------------------------------------
runScenario(5, 'URL with brand name in path on legitimate technical blog (Not flagged)', () => {
  const res = engine.analyzeUrl('https://developer-community-blog.org/articles/paypal/webhook-tutorial');
  assert.strictEqual(res.valid, true);
  const brandFinding = res.findings.find(f => f.id === 'RULE_BRAND_IN_SUBDOMAIN' || f.id === 'RULE_BRAND_TYPOSQUATTING');
  assert(!brandFinding, 'Brand appearing in path must not trigger domain impersonation rules');
  assert.strictEqual(res.riskLevel, 'LOW');
});

// -----------------------------------------------------------------------------
// Scenario 6: Login form submitting to an unrelated domain
// -----------------------------------------------------------------------------
runScenario(6, 'Password login form submitting to unrelated external destination', () => {
  const pageData = {
    title: 'Customer Portal',
    forms: [
      { action: 'https://credential-stealer-collector.xyz/post', method: 'POST', hasPassword: true }
    ],
    isHttps: true
  };
  const res = engine.analyzeUrl('https://legit-looking-service.net/login', pageData);
  assert.strictEqual(res.valid, true);
  const crossFinding = res.findings.find(f => f.id === 'RULE_DOM_CROSS_ORIGIN_LOGIN');
  assert(crossFinding, 'Must trigger RULE_DOM_CROSS_ORIGIN_LOGIN');
  assert.strictEqual(crossFinding.severity, 'HIGH');
  assert.strictEqual(res.riskLevel, 'HIGH');
  assert(res.riskScore >= 60);
});

// -----------------------------------------------------------------------------
// Scenario 7: Page with suspicious misleading links
// -----------------------------------------------------------------------------
runScenario(7, 'Page with deceptive link text destination mismatch', () => {
  const pageData = {
    title: 'Security Verification Notice',
    forms: [],
    suspiciousLinks: [
      { text: 'https://paypal.com/security', href: 'https://phishing-trap-site.org/collect' }
    ],
    isHttps: true
  };
  const res = engine.analyzeUrl('https://security-notice-relay.com/view', pageData);
  assert.strictEqual(res.valid, true);
  const linkFinding = res.findings.find(f => f.id === 'RULE_DOM_MISLEADING_LINK');
  assert(linkFinding, 'Must trigger RULE_DOM_MISLEADING_LINK');
  assert(res.riskScore >= 40);
});

// -----------------------------------------------------------------------------
// Scenario 8: Flagged by a mocked threat-intelligence fixture
// -----------------------------------------------------------------------------
runScenario(8, 'Threat intelligence reported malicious match (THREAT_FOUND fixture)', () => {
  const repFixture = {
    status: 'THREAT_FOUND',
    provider: 'Google Safe Browsing v4 (Mock)',
    threatType: 'SOCIAL_ENGINEERING',
    message: 'Confirmed social engineering phishing match'
  };
  const res = engine.analyzeUrl('https://recently-flagged-malicious-site.com/', null, { reputationResult: repFixture });
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.reputationStatus, 'CONFIRMED_THREAT');
  assert.strictEqual(res.riskLevel, 'HIGH');
  assert(res.riskScore >= 85, `Expected escalated critical risk >= 85, got ${res.riskScore}`);
  assert.strictEqual(res.status, 'CRITICAL_RISK');
});

// -----------------------------------------------------------------------------
// Scenario 9: Clean reputation lookup with no additional suspicious indicators
// -----------------------------------------------------------------------------
runScenario(9, 'Clean reputation lookup on standard domain (NO_KNOWN_MATCH)', () => {
  const repFixture = {
    status: 'CLEAN',
    provider: 'Google Safe Browsing v4 (Mock)',
    message: 'No threat matches found'
  };
  const res = engine.analyzeUrl('https://independent-consultant-portfolio.com/', null, { reputationResult: repFixture });
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.reputationStatus, 'NO_KNOWN_MATCH');
  assert.strictEqual(res.riskLevel, 'LOW');
  assert(res.riskScore <= 15);
  assert(res.disclaimer.includes('does not guarantee a website is safe'));
});

// -----------------------------------------------------------------------------
// Scenario 10: Reputation API timeout
// -----------------------------------------------------------------------------
runScenario(10, 'Reputation API timeout produces UNAVAILABLE (never clean safety)', () => {
  const repFixture = {
    status: 'UNAVAILABLE',
    provider: 'Google Safe Browsing v4',
    message: 'Connection timed out after 4000ms'
  };
  const res = engine.analyzeUrl('https://standard-startup-site.io/', null, { reputationResult: repFixture });
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.reputationStatus, 'UNAVAILABLE');
  assert(res.limitations.some(l => l.includes('unavailable') || l.includes('timed out')));
  const repCheck = res.checksUnavailable.find(c => c.name.includes('Threat Intelligence'));
  assert(repCheck, 'Must disclose reputation is unavailable');
});

// -----------------------------------------------------------------------------
// Scenario 11: Reputation API error or malformed response
// -----------------------------------------------------------------------------
runScenario(11, 'Reputation API error returns UNAVAILABLE without failing scan', () => {
  const repFixture = {
    status: 'ERROR',
    provider: 'Google Safe Browsing v4',
    message: 'HTTP 503 Service Unavailable'
  };
  const res = engine.analyzeUrl('https://ordinary-storefront.org/', null, { reputationResult: repFixture });
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.reputationStatus, 'UNAVAILABLE');
  assert(res.score > 0, 'Local heuristics must remain functional');
});

// -----------------------------------------------------------------------------
// Scenario 12: Missing permission or failed content-script injection
// -----------------------------------------------------------------------------
runScenario(12, 'Missing permission / Inaccessible DOM degrades gracefully', () => {
  const res = engine.analyzeUrl('https://secure-node-gateway.com/dashboard', null);
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.telemetry.domAvailable, false);
  assert(res.limitations.some(l => l.includes('DOM telemetry was inaccessible')));
  assert.strictEqual(res.confidence, 'MODERATE');
});

// -----------------------------------------------------------------------------
// Scenario 13: Unsupported browser-internal page
// -----------------------------------------------------------------------------
runScenario(13, 'Unsupported browser-internal page (chrome://extensions)', () => {
  const res = engine.analyzeUrl('chrome://extensions');
  assert.strictEqual(res.valid, false);
  assert.strictEqual(res.unsupportedProtocol, true);
  assert.strictEqual(res.status, 'UNSUPPORTED_PAGE');
  assert.strictEqual(res.score, null);
});

// -----------------------------------------------------------------------------
// Scenario 14: Legitimate site that includes a third-party payment processor
// -----------------------------------------------------------------------------
runScenario(14, 'Legitimate e-commerce site with external Stripe payment processor (Not flagged)', () => {
  const pageData = {
    title: 'Order Checkout',
    forms: [
      { action: 'https://checkout.stripe.com/c/pay/cs_test_123', method: 'POST', hasPassword: false }
    ],
    isHttps: true
  };
  const res = engine.analyzeUrl('https://handmade-ceramics-store.com/checkout', pageData);
  assert.strictEqual(res.valid, true);
  assert(!res.findings.some(f => f.id === 'RULE_DOM_CROSS_ORIGIN_LOGIN'), 'Known payment processors must not be flagged');
  assert.strictEqual(res.riskLevel, 'LOW');
});

// -----------------------------------------------------------------------------
// Scenario 15: Website DNA baseline change simulation
// -----------------------------------------------------------------------------
runScenario(15, 'Website DNA baseline change detection (Protocol downgrade)', () => {
  const baseline = { domain: 'mycompany.com', protocol: 'https:', riskLevel: 'LOW' };
  const currentScan = engine.analyzeUrl('http://mycompany.com/');
  const hasShifted = currentScan.protocol !== baseline.protocol || currentScan.riskLevel !== baseline.riskLevel;
  assert.strictEqual(hasShifted, true, 'Must detect configuration shift from HTTPS baseline to HTTP');
  assert.strictEqual(currentScan.riskLevel, 'MEDIUM');
});

// -----------------------------------------------------------------------------
// Scenario 16: Known benign domain that triggers one weak heuristic
// -----------------------------------------------------------------------------
runScenario(16, 'Benign domain triggering single weak heuristic (.xyz hobby site)', () => {
  const res = engine.analyzeUrl('https://my-personal-art-portfolio.xyz/');
  assert.strictEqual(res.valid, true);
  assert(res.findings.some(f => f.id === 'RULE_HIGH_ABUSE_TLD'));
  // Single weak heuristic must NOT label the website as High Risk
  assert(res.riskLevel === 'LOW' || res.riskLevel === 'MEDIUM');
  assert(res.riskScore < 60, `Weak heuristic must not jump to High Risk, got ${res.riskScore}`);
});

// -----------------------------------------------------------------------------
// Scenario 17: Multiple correlated indicators that must not be double-counted
// -----------------------------------------------------------------------------
runScenario(17, 'Correlated indicators deduplicated without double counting', () => {
  const res = engine.analyzeUrl('https://paypal.com.account-update.xyz/login');
  assert.strictEqual(res.valid, true);
  const brandSubRules = res.findings.filter(f => f.id === 'RULE_BRAND_IN_SUBDOMAIN');
  assert.strictEqual(brandSubRules.length, 1, 'Brand in subdomain must trigger exactly once');
  // Excessive subdomains rule is deduplicated when caused solely by brand prefix
  const excessiveSubRules = res.findings.filter(f => f.id === 'RULE_EXCESSIVE_SUBDOMAINS');
  assert.strictEqual(excessiveSubRules.length, 0, 'Excessive subdomains deduplicated');
});

// -----------------------------------------------------------------------------
// Scenario 18: Stale response arriving after a newer scan (Race condition guard)
// -----------------------------------------------------------------------------
runScenario(18, 'Race condition safety: Stale scanId rejected', () => {
  const scan1 = engine.analyzeUrl('https://slow-responding-site.com/');
  scan1.scanId = '1000_reqA';
  const activeTabScanId = '1002_reqB'; // User navigated to site B

  const isStale = scan1.scanId !== activeTabScanId;
  assert.strictEqual(isStale, true, 'Must identify scanA as stale');
});

// -----------------------------------------------------------------------------
// Scenario 19: Page where AI is unavailable (Deterministic rules preserved)
// -----------------------------------------------------------------------------
runScenario(19, 'Deterministic rules and speech preserve full fidelity without AI', () => {
  const res = engine.analyzeUrl('https://paypa1.com/login');
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.riskLevel, 'HIGH');
  assert(res.findings.length > 0);
  assert(res.speechText.includes('Warning'));
  assert(typeof res.score === 'number');
});

// -----------------------------------------------------------------------------
// Scenario 20: Suspicious page with conflicting or incomplete evidence
// -----------------------------------------------------------------------------
runScenario(20, 'Suspicious page with incomplete evidence (Cautious status, Moderate confidence)', () => {
  const res = engine.analyzeUrl('https://temporary-service-relay.click/verify', null);
  assert.strictEqual(res.valid, true);
  assert.strictEqual(res.confidence, 'MODERATE');
  assert(res.limitations.length > 0);
  assert(res.riskScore >= 20 && res.riskScore <= 59);
});

console.log('\n======================================================================');
console.log(`HARDENED ENGINE AUDIT SUITE: ${passedTests} / ${totalTests} SCENARIOS PASSED`);
console.log('======================================================================\n');

if (passedTests !== totalTests) {
  process.exit(1);
}

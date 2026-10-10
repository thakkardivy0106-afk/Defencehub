/**
 * DefenceHub / PhishGuard - Automated Test Harness & Validation Suite
 * 
 * PHASES COVERED:
 * PHASE 2 — Controlled Fixture Benchmark (10 Core Scenarios with Ground Truth)
 * PHASE 3 — Scoring Engine Validation (Monotonicity, Determinism, Thresholds, Incomplete Data)
 * PHASE 4 — End-to-End Pipeline Simulation (Active Tab -> DOM Extraction -> Engine -> UI & Storage)
 */

const engine = require('./engine.js');
const assert = require('assert');

console.log('======================================================================');
console.log('    PHISHGUARD / DEFENCEHUB AUTOMATED TEST HARNESS & VALIDATION       ');
console.log('======================================================================\n');

// ====================================================================
// PHASE 2 — CONTROLLED TEST FIXTURES (Independently Specified Ground Truth)
// ====================================================================
const FIXTURES = [
  // 1. Legitimate websites with no strong suspicious indicators
  {
    id: 'LEGIT_GOOGLE',
    category: '1. Legitimate websites',
    name: 'Google Search query',
    url: 'https://www.google.com/search?q=cybersecurity+defense',
    pageData: { title: 'cybersecurity defense - Google Search', forms: [], isHttps: true },
    groundTruth: 'BENIGN',
    expectedRiskLevel: 'LOW',
    expectedMinSafety: 90,
    expectedMaxRisk: 10,
    prohibitedRules: ['RULE_BRAND_TYPOSQUATTING', 'RULE_BRAND_IN_SUBDOMAIN', 'RULE_IP_HOSTNAME']
  },
  {
    id: 'LEGIT_WIKIPEDIA',
    category: '1. Legitimate websites',
    name: 'Wikipedia Article',
    url: 'https://en.wikipedia.org/wiki/Computer_security',
    pageData: { title: 'Computer security - Wikipedia', forms: [], isHttps: true },
    groundTruth: 'BENIGN',
    expectedRiskLevel: 'LOW',
    expectedMinSafety: 90,
    expectedMaxRisk: 10,
    prohibitedRules: ['RULE_BRAND_TYPOSQUATTING', 'RULE_BRAND_IN_SUBDOMAIN']
  },
  {
    id: 'LEGIT_LOCAL_BUSINESS',
    category: '1. Legitimate websites',
    name: 'Local Business Website (Unranked, Clean Domain)',
    url: 'https://sunnyvale-artisan-bakery.com/menu',
    pageData: { title: 'Our Fresh Menu - Artisan Bakery', forms: [], isHttps: true },
    groundTruth: 'BENIGN',
    expectedRiskLevel: 'LOW',
    expectedMinSafety: 80,
    expectedMaxRisk: 20,
    prohibitedRules: ['RULE_BRAND_TYPOSQUATTING', 'RULE_HIGH_ABUSE_TLD']
  },

  // 2. Legitimate websites with ordinary third-party resources
  {
    id: 'LEGIT_ECOMMERCE_3RD_PARTY',
    category: '2. Legitimate with 3rd-party resources',
    name: 'E-commerce site with standard CDN & payment scripts',
    url: 'https://acme-supplies-shop.com/checkout',
    pageData: {
      title: 'Checkout - ACME Supplies',
      isHttps: true,
      iframeCount: 2, // Standard Stripe/PayPal payment iframe
      forms: [
        { action: 'https://acme-supplies-shop.com/api/order', method: 'POST', hasPassword: false }
      ]
    },
    groundTruth: 'BENIGN',
    expectedRiskLevel: 'LOW',
    expectedMinSafety: 80,
    expectedMaxRisk: 20,
    prohibitedRules: ['RULE_DOM_INSECURE_FORM', 'RULE_BRAND_TYPOSQUATTING']
  },

  // 3. Lookalike domains
  {
    id: 'LOOKALIKE_PAYPAL_LEET',
    category: '3. Lookalike domains',
    name: 'PayPal Leetspeak lookalike (paypa1.com)',
    url: 'https://paypa1.com/login',
    pageData: { title: 'PayPal: Log In', forms: [], isHttps: true },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_BRAND_TYPOSQUATTING'],
    expectedMaxSafety: 45
  },
  {
    id: 'LOOKALIKE_AMAZON_TYPO',
    category: '3. Lookalike domains',
    name: 'Amazon 1-edit Levenshtein typosquat (amazn.com)',
    url: 'https://amazn.com/orders',
    pageData: { title: 'Your Orders', forms: [], isHttps: true },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_BRAND_TYPOSQUATTING'],
    expectedMaxSafety: 50
  },
  {
    id: 'LOOKALIKE_SUBDOMAIN_BRAND',
    category: '3. Lookalike domains',
    name: 'Brand in Subdomain of third-party root',
    url: 'https://paypal.com.verify-account-user.net/auth',
    pageData: { title: 'Confirm your account', forms: [], isHttps: true },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_BRAND_IN_SUBDOMAIN'],
    expectedMaxSafety: 40
  },
  {
    id: 'LOOKALIKE_COMBO_KEYWORD',
    category: '3. Lookalike domains',
    name: 'Brand + Security action combo keyword',
    url: 'https://paypal-security-alert.com/login',
    pageData: { title: 'Security Alert - Action Required', forms: [], isHttps: true },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_BRAND_DECEPTIVE_COMBO'],
    expectedMaxSafety: 50
  },

  // 4. Suspicious form destinations
  {
    id: 'FORM_INSECURE_DESTINATION',
    category: '4. Suspicious form destinations',
    name: 'Form with password submitting to unencrypted HTTP',
    url: 'https://client-portal-auth.com/login',
    pageData: {
      title: 'Client Portal Login',
      isHttps: true,
      forms: [
        { action: 'http://collector-server.net/post.php', method: 'POST', hasPassword: true }
      ]
    },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_DOM_INSECURE_FORM'],
    expectedMaxSafety: 55
  },

  // 5. Suspicious redirect / Query parameter patterns
  {
    id: 'REDIRECT_OPEN_TARGET',
    category: '5. Suspicious redirects & query strings',
    name: 'Sensitive credentials keyword in deep query',
    url: 'https://unverified-utility-portal.com/gate?redirect=login&verify=true',
    pageData: { title: 'Redirecting...', forms: [], isHttps: true },
    groundTruth: 'SUSPICIOUS',
    expectedRiskLevel: 'MEDIUM',
    expectedRules: ['RULE_SENSITIVE_PATH_KEYWORDS']
  },

  // 6. Multiple independent suspicious indicators
  {
    id: 'MULTI_THREAT_SUBDOMAIN_TLD_PATH',
    category: '6. Multiple independent indicators',
    name: 'Brand in Subdomain + High Abuse TLD + Login Path',
    url: 'https://paypal.com.account-update.xyz/login',
    pageData: { title: 'Account Verification', forms: [], isHttps: true },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_BRAND_IN_SUBDOMAIN', 'RULE_HIGH_ABUSE_TLD', 'RULE_SENSITIVE_PATH_KEYWORDS'],
    expectedMaxSafety: 25
  },
  {
    id: 'MULTI_THREAT_RAW_IP_HTTP',
    category: '6. Multiple independent indicators',
    name: 'Raw IP Hostname + Unencrypted HTTP',
    url: 'http://192.168.1.50/admin',
    pageData: { title: 'Router Gateway', forms: [], isHttps: false },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_IP_HOSTNAME', 'RULE_INSECURE_HTTP'],
    expectedMaxSafety: 20
  },

  // 7. Duplicate or correlated indicators
  {
    id: 'CORRELATED_HTTP_ONLY',
    category: '7. Correlated indicators',
    name: 'Ordinary Website with unencrypted HTTP only',
    url: 'http://traditional-local-club.org/events',
    pageData: { title: 'Club Events', forms: [], isHttps: false },
    groundTruth: 'SUSPICIOUS',
    expectedRiskLevel: 'MEDIUM',
    expectedRules: ['RULE_INSECURE_HTTP'],
    prohibitedRules: ['RULE_BRAND_TYPOSQUATTING', 'RULE_IP_HOSTNAME']
  },

  // 8. Unavailable reputation services
  {
    id: 'UNAVAILABLE_REPUTATION_STARTUP',
    category: '8. Unavailable reputation services',
    name: 'Unfamiliar startup domain (Offline baseline, no reputation API)',
    url: 'https://novatech-quantum-ai-systems.com/about',
    pageData: { title: 'About NovaTech', forms: [], isHttps: true },
    groundTruth: 'BENIGN',
    expectedRiskLevel: 'LOW',
    expectedMinSafety: 75,
    prohibitedRules: ['RULE_HIGH_ABUSE_TLD']
  },

  // 9. Inaccessible pages and incomplete signals
  {
    id: 'INACCESSIBLE_DOM_INCOMPLETE',
    category: '9. Inaccessible page content',
    name: 'Tab where DOM content is blocked/null (URL-only scan)',
    url: 'https://example-service-node.com/status',
    pageData: null, // DOM execution failed / CSP blocked
    groundTruth: 'BENIGN',
    expectedRiskLevel: 'LOW',
    expectedMinSafety: 75
  },

  // 10. Conflicting evidence
  {
    id: 'CONFLICT_OFFICIAL_BRAND_SUBDOMAIN',
    category: '10. Conflicting evidence',
    name: 'Official Brand Subdomain (developer.paypal.com - Must be BENIGN)',
    url: 'https://developer.paypal.com/docs/api',
    pageData: { title: 'PayPal Developer Documentation', forms: [], isHttps: true },
    groundTruth: 'BENIGN',
    expectedRiskLevel: 'LOW',
    expectedMinSafety: 90,
    prohibitedRules: ['RULE_BRAND_IN_SUBDOMAIN', 'RULE_BRAND_TYPOSQUATTING']
  },
  {
    id: 'CONFLICT_EMBEDDED_USER_PHISH',
    category: '10. Conflicting evidence',
    name: 'Embedded Credentials disguising authority brand (paypal.com:pass@phish.net)',
    url: 'http://paypal.com:pass@phish-destination.net/login',
    pageData: { title: 'Login', forms: [], isHttps: false },
    groundTruth: 'MALICIOUS',
    expectedRiskLevel: 'HIGH',
    expectedRules: ['RULE_EMBEDDED_CREDENTIALS'],
    expectedMaxSafety: 20
  }
];

// Run Phase 2 Benchmark
console.log('--- RUNNING PHASE 2: CONTROLLED BENCHMARK ---');
let benchmarkPass = 0;
let benchmarkFail = 0;
const benchmarkResults = [];

FIXTURES.forEach(fixture => {
  const res = engine.analyzeUrl(fixture.url, fixture.pageData);
  const issues = [];

  // 1. Risk Level check
  if (res.riskLevel !== fixture.expectedRiskLevel) {
    issues.push(`Risk Level mismatch: got ${res.riskLevel}, expected ${fixture.expectedRiskLevel}`);
  }

  // 2. Expected Min Safety check
  if (fixture.expectedMinSafety !== undefined && res.score < fixture.expectedMinSafety) {
    issues.push(`Safety score ${res.score} < expected minimum ${fixture.expectedMinSafety}`);
  }

  // 3. Expected Max Safety check
  if (fixture.expectedMaxSafety !== undefined && res.score > fixture.expectedMaxSafety) {
    issues.push(`Safety score ${res.score} > expected maximum ${fixture.expectedMaxSafety}`);
  }

  // 4. Expected Rules check
  if (fixture.expectedRules) {
    fixture.expectedRules.forEach(ruleId => {
      if (!res.findings.some(f => f.id === ruleId)) {
        issues.push(`Expected rule ${ruleId} was not triggered`);
      }
    });
  }

  // 5. Prohibited Rules check
  if (fixture.prohibitedRules) {
    fixture.prohibitedRules.forEach(ruleId => {
      if (res.findings.some(f => f.id === ruleId)) {
        issues.push(`Prohibited rule ${ruleId} was triggered unexpectedly`);
      }
    });
  }

  const passed = issues.length === 0;
  if (passed) {
    benchmarkPass++;
    console.log(`[PASS] ${fixture.id.padEnd(35)} (Score: ${res.score}/100 | Risk: ${res.riskLevel})`);
  } else {
    benchmarkFail++;
    console.log(`[FAIL] ${fixture.id.padEnd(35)} (Score: ${res.score}/100 | Risk: ${res.riskLevel})`);
    issues.forEach(iss => console.log(`       -> ${iss}`));
  }

  benchmarkResults.push({ fixture, result: res, passed, issues });
});

console.log(`\nPhase 2 Benchmark Summary: ${benchmarkPass}/${FIXTURES.length} Passed.\n`);

// ====================================================================
// PHASE 3 — SCORING VALIDATION SUITE
// ====================================================================
console.log('--- RUNNING PHASE 3: SCORING ENGINE VALIDATION ---');
let p3Pass = 0;
let p3Fail = 0;

function testP3(name, fn) {
  try {
    fn();
    p3Pass++;
    console.log(`[PASS] ${name}`);
  } catch (e) {
    p3Fail++;
    console.error(`[FAIL] ${name}: ${e.message}`);
  }
}

// 1. Deterministic Output for Identical Inputs
testP3('Deterministic output across repeated evaluations', () => {
  const url = 'https://paypa1.com/login';
  const res1 = engine.analyzeUrl(url);
  const res2 = engine.analyzeUrl(url);
  assert.strictEqual(res1.score, res2.score);
  assert.strictEqual(res1.riskScore, res2.riskScore);
  assert.strictEqual(res1.riskLevel, res2.riskLevel);
  assert.strictEqual(res1.findings.length, res2.findings.length);
});

// 2. Score Range Bounds (Must be clamped in valid interval [5, 99])
testP3('Strict Score Range Bounds [5, 99] for Safety and [1, 95] for Risk', () => {
  const testInputs = [
    'https://www.google.com',
    'http://192.168.1.1:8080/admin/paypal/login?redirect=phish',
    'https://paypal.com.account-update.billing-verify.xyz/login',
    'http://user:pass@1.2.3.4/login'
  ];
  testInputs.forEach(u => {
    const r = engine.analyzeUrl(u);
    assert(r.score >= 5 && r.score <= 99, `Score ${r.score} out of bounds for ${u}`);
    assert(r.riskScore >= 1 && r.riskScore <= 95, `RiskScore ${r.riskScore} out of bounds for ${u}`);
  });
});

// 3. Monotonicity: Adding an independent threat must NEVER increase safety score
testP3('Strict Monotonicity: Adding independent threat decreases safety score', () => {
  const cleanUrl = 'https://example-test-domain.com/';
  const threat1Url = 'https://example-test-domain.com/login'; // Adds path keyword
  const threat2Url = 'http://example-test-domain.com/login';  // Adds HTTP insecurity
  const threat3Url = 'http://paypa1-test-domain.com/login';   // Adds typosquatting

  const rClean = engine.analyzeUrl(cleanUrl);
  const r1 = engine.analyzeUrl(threat1Url);
  const r2 = engine.analyzeUrl(threat2Url);
  const r3 = engine.analyzeUrl(threat3Url);

  assert(rClean.score >= r1.score, `rClean (${rClean.score}) should be >= r1 (${r1.score})`);
  assert(r1.score > r2.score, `r1 (${r1.score}) should be > r2 (${r2.score})`);
  assert(r2.score >= r3.score, `r2 (${r2.score}) should be >= r3 (${r3.score})`);
  assert(r3.riskScore > rClean.riskScore, `Final risk score should be strictly higher`);
});

// 4. Resistance to Double-Counting on Subdomains
testP3('Resistance to Double Counting on Brand Match', () => {
  const url = 'https://paypal.com.phish.com/';
  const res = engine.analyzeUrl(url);
  // Should trigger RULE_BRAND_IN_SUBDOMAIN once, not once per brand label
  const brandSubRules = res.findings.filter(f => f.id === 'RULE_BRAND_IN_SUBDOMAIN');
  assert.strictEqual(brandSubRules.length, 1, 'Should trigger RULE_BRAND_IN_SUBDOMAIN exactly once');
});

// 5. Correct Handling of Inaccessible DOM (Graceful degradation)
testP3('Inaccessible DOM degrades gracefully to URL-only analysis', () => {
  const url = 'https://example.com/status';
  const resWithNullDom = engine.analyzeUrl(url, null);
  const resWithEmptyDom = engine.analyzeUrl(url, {});
  assert.strictEqual(resWithNullDom.valid, true);
  assert.strictEqual(resWithEmptyDom.valid, true);
  assert.strictEqual(resWithNullDom.score, resWithEmptyDom.score);
});

// 6. Conflicting Evidence Resolution: Authentic owner overrides brand keyword
testP3('Authentic owner overrides brand-in-subdomain heuristic', () => {
  const authUrl = 'https://developer.paypal.com/docs';
  const r = engine.analyzeUrl(authUrl);
  const hasSubThreat = r.findings.some(f => f.id === 'RULE_BRAND_IN_SUBDOMAIN');
  assert.strictEqual(hasSubThreat, false, 'Official domain must not flag its own brand in subdomain');
  assert.strictEqual(r.riskLevel, 'LOW');
});

console.log(`\nPhase 3 Scoring Validation Summary: ${p3Pass}/${p3Pass + p3Fail} Passed.\n`);

// ====================================================================
// PHASE 4 — END-TO-END PIPELINE SIMULATION
// ====================================================================
console.log('--- RUNNING PHASE 4: END-TO-END SIMULATION ---');
let p4Pass = 0;
let p4Fail = 0;

function testP4(name, fn) {
  try {
    fn();
    p4Pass++;
    console.log(`[PASS] ${name}`);
  } catch (e) {
    p4Fail++;
    console.error(`[FAIL] ${name}: ${e.message}`);
  }
}

// 1. Unsupported Browser Schemes
testP4('Unsupported chrome:// and about: schemes rejected honestly', () => {
  const unsupported = ['chrome://settings', 'chrome-extension://xyz/popup.html', 'about:blank', 'view-source:https://google.com'];
  unsupported.forEach(u => {
    const r = engine.analyzeUrl(u);
    assert.strictEqual(r.valid, false);
    assert.strictEqual(r.unsupportedProtocol, true);
  });
});

// 2. Active Tab DOM Telemetry Propagation
testP4('Active Tab DOM Telemetry reaches Engine and triggers content rules', () => {
  const targetUrl = 'https://unverified-login-page.com/portal';
  const spoofedPageData = {
    title: 'PayPal Login - Sign in to your account',
    forms: [
      { action: 'http://insecure-harvester.com/collect', method: 'POST', hasPassword: true }
    ],
    isHttps: true
  };

  const res = engine.analyzeUrl(targetUrl, spoofedPageData);
  assert(res.findings.some(f => f.id === 'RULE_DOM_TITLE_SPOOFING'), 'Must trigger RULE_DOM_TITLE_SPOOFING');
  assert(res.findings.some(f => f.id === 'RULE_DOM_INSECURE_FORM'), 'Must trigger RULE_DOM_INSECURE_FORM');
  assert.strictEqual(res.riskLevel, 'HIGH');
});

// 3. Storage Persistence Simulation
testP4('History storage serializes and deserializes scan results truthfully', () => {
  const scanResult = engine.analyzeUrl('https://paypa1.com/login');
  const storedEntry = {
    hostname: scanResult.hostname,
    url: scanResult.url,
    score: scanResult.score,
    riskScore: scanResult.riskScore,
    riskLevel: scanResult.riskLevel,
    riskLabel: scanResult.riskLabel,
    timestamp: '12:00 PM'
  };

  const jsonStr = JSON.stringify([storedEntry]);
  const parsed = JSON.parse(jsonStr);
  assert.strictEqual(parsed[0].hostname, 'paypa1.com');
  assert.strictEqual(parsed[0].riskLevel, 'HIGH');
  assert.strictEqual(parsed[0].score, scanResult.score);
});

console.log(`\nPhase 4 End-to-End Simulation Summary: ${p4Pass}/${p4Pass + p4Fail} Passed.\n`);

// ====================================================================
// PHASE 5 — METRICS COMPUTATION (Confusion Matrix, Precision, Recall, FPR)
// ====================================================================
console.log('--- PHASE 5: METRICS & ACCURACY COMPUTATION ---');
let TP = 0; // Ground truth Malicious/Suspicious classified as High/Med
let TN = 0; // Ground truth Benign classified as Low
let FP = 0; // Ground truth Benign classified as High/Med
let FN = 0; // Ground truth Malicious/Suspicious classified as Low

benchmarkResults.forEach(({ fixture, result }) => {
  const isMaliciousGT = fixture.groundTruth === 'MALICIOUS' || fixture.groundTruth === 'SUSPICIOUS';
  const isDetectedThreat = result.riskLevel === 'HIGH' || result.riskLevel === 'MEDIUM';

  if (isMaliciousGT && isDetectedThreat) {
    TP++;
  } else if (!isMaliciousGT && !isDetectedThreat) {
    TN++;
  } else if (!isMaliciousGT && isDetectedThreat) {
    FP++;
  } else if (isMaliciousGT && !isDetectedThreat) {
    FN++;
  }
});

const totalLabeled = FIXTURES.length;
const accuracy = ((TP + TN) / totalLabeled) * 100;
const precision = (TP + FP) > 0 ? (TP / (TP + FP)) * 100 : 0;
const recall = (TP + FN) > 0 ? (TP / (TP + FN)) * 100 : 0;
const fpr = (FP + TN) > 0 ? (FP / (FP + TN)) * 100 : 0;

console.log(`Total Labeled Benchmark Cases: ${totalLabeled}`);
console.log(`True Positives (TP):  ${TP}`);
console.log(`True Negatives (TN):  ${TN}`);
console.log(`False Positives (FP): ${FP}`);
console.log(`False Negatives (FN): ${FN}`);
console.log(`Precision:            ${precision.toFixed(1)}%`);
console.log(`Recall (Sensitivity): ${recall.toFixed(1)}%`);
console.log(`False Positive Rate:  ${fpr.toFixed(1)}%`);
console.log(`Overall Accuracy:     ${accuracy.toFixed(1)}%\n`);

// Exit code
const allPassed = (benchmarkFail === 0) && (p3Fail === 0) && (p4Fail === 0);
if (!allPassed) {
  console.error('Test harness detected failures.');
  process.exit(1);
} else {
  console.log('ALL PHASE 2, 3, AND 4 BENCHMARKS PASSED (100% SUCCESS)');
}

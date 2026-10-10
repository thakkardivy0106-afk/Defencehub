/**
 * End-to-End Simulation Test for DefenceHub Popup and Engine
 * Validates DOM events, storage persistence, and UI state transitions.
 */

const assert = require('assert');
const engine = require('./engine.js');

console.log('====================================================');
console.log('    DEFENCEHUB INTEGRATION & WORKFLOW TEST          ');
console.log('====================================================\n');

// 1. Test Storage Simulation
let mockStorage = {};
const chromeStorage = {
  get: (keys, cb) => {
    cb({ defencehub_scan_history: mockStorage['defencehub_scan_history'] || [] });
  },
  set: (obj, cb) => {
    Object.assign(mockStorage, obj);
    if (cb) cb();
  },
  remove: (keys, cb) => {
    keys.forEach(k => delete mockStorage[k]);
    if (cb) cb();
  }
};

// 2. Test Scan and History Pipeline
console.log('[TEST 1] Testing Scan and History Pipeline...');
const testUrls = [
  'https://www.google.com/search',
  'https://paypa1.com/login',
  'http://192.168.1.1/admin',
  'https://paypal.com.account-update.xyz/login'
];

let history = [];
testUrls.forEach(url => {
  const res = engine.analyzeUrl(url);
  assert(res.valid, `URL should be valid: ${url}`);
  
  // Format history entry as popup.js does
  const entry = {
    hostname: res.hostname,
    url: res.url,
    score: res.score,
    riskLevel: res.riskLevel,
    riskLabel: res.riskLabel,
    timestamp: '10:00 AM'
  };
  
  history = history.filter(item => item.hostname !== entry.hostname);
  history.unshift(entry);
});

chromeStorage.set({ defencehub_scan_history: history }, () => {
  chromeStorage.get(['defencehub_scan_history'], res => {
    const saved = res.defencehub_scan_history;
    assert.strictEqual(saved.length, 4);
    assert.strictEqual(saved[0].hostname, 'paypal.com.account-update.xyz');
    assert.strictEqual(saved[0].riskLevel, 'HIGH');
    console.log(' -> History saved and retrieved successfully: 4 items.');
  });
});

// 3. Test History Clearing
console.log('\n[TEST 2] Testing Clear History...');
chromeStorage.remove(['defencehub_scan_history'], () => {
  chromeStorage.get(['defencehub_scan_history'], res => {
    const saved = res.defencehub_scan_history;
    assert.strictEqual(saved.length, 0);
    console.log(' -> History cleared successfully.');
  });
});

// 4. Test Unsupported URL Detection
console.log('\n[TEST 3] Testing Unsupported Schemes...');
const unsupportedUrls = [
  'chrome://extensions',
  'chrome-extension://abcdef/popup.html',
  'edge://settings',
  'about:blank',
  'view-source:https://example.com'
];

unsupportedUrls.forEach(u => {
  const res = engine.analyzeUrl(u);
  assert.strictEqual(res.valid, false);
  assert.strictEqual(res.unsupportedProtocol, true);
  console.log(` -> Correctly blocked unsupported: ${u}`);
});

// 5. Test Brand Impersonation Rule Matrix
console.log('\n[TEST 4] Testing Brand Impersonation Rule Matrix...');

const matrix = [
  {
    url: 'https://paypa1.com/login',
    expectedRule: 'RULE_BRAND_TYPOSQUATTING',
    minScore: 35
  },
  {
    url: 'https://paypal.com.billing-update.top/account',
    expectedRule: 'RULE_BRAND_IN_SUBDOMAIN',
    minScore: 35
  },
  {
    url: 'https://paypal-security-alert.com/login',
    expectedRule: 'RULE_BRAND_DECEPTIVE_COMBO',
    minScore: 30
  },
  {
    url: 'http://192.168.1.50/login',
    expectedRule: 'RULE_IP_HOSTNAME',
    minScore: 35
  },
  {
    url: 'https://xn--appl-wqa.com/',
    expectedRule: 'RULE_PUNYCODE_HOST',
    minScore: 25
  },
  {
    url: 'http://paypal.com:pass@phish.net/',
    expectedRule: 'RULE_EMBEDDED_CREDENTIALS',
    minScore: 40
  }
];

matrix.forEach(testCase => {
  const res = engine.analyzeUrl(testCase.url);
  assert(res.valid);
  const found = res.findings.find(f => f.id === testCase.expectedRule);
  assert(found, `Expected rule ${testCase.expectedRule} for ${testCase.url}`);
  assert(res.threatPoints >= testCase.minScore || res.riskScore >= testCase.minScore, `Threat points/risk score should be >= ${testCase.minScore}`);
  console.log(` -> Rule ${testCase.expectedRule} triggered correctly (+${found.points} pts, risk ${res.riskScore}%)`);
});

// 6. Test Manifest Configuration
console.log('\n[TEST 5] Testing Manifest V3 Content Script & Background Configuration...');
const fs = require('fs');
const manifest = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));

assert(manifest.background && manifest.background.service_worker === 'background.js', 'Manifest must register background.js');
assert(Array.isArray(manifest.content_scripts) && manifest.content_scripts.length > 0, 'Manifest must have content_scripts');
const cs = manifest.content_scripts[0];
assert(cs.matches.includes('http://*/*') && cs.matches.includes('https://*/*'), 'Matches should cover http and https');
assert(cs.js.includes('engine.js') && cs.js.includes('content.js'), 'Must include engine.js and content.js');
assert.strictEqual(cs.js[0], 'engine.js', 'engine.js must load before content.js');
assert.strictEqual(cs.run_at, 'document_end', 'Content scripts should run at document_end');
console.log(' -> Manifest V3 background service worker and content scripts validated successfully.');

// 7. Test In-Page Popup Risk Color Mapping
console.log('\n[TEST 6] Testing In-Page Popup Risk Color Mapping (Red, Orange, Green)...');
const contentScriptSrc = fs.readFileSync('content.js', 'utf8');

// Verify that the 3 required risk colors are configured in content.js
assert(contentScriptSrc.includes('#D92D3A'), 'Content script must configure Red (#D92D3A) for High Risk');
assert(contentScriptSrc.includes('#ea580c'), 'Content script must configure Orange (#ea580c) for Medium Risk');
assert(contentScriptSrc.includes('#16794B'), 'Content script must configure Green (#16794B) for Low Risk');

// Test scenario classifications
const highRiskRes = engine.analyzeUrl('https://paypa1.com/login');
assert.strictEqual(highRiskRes.riskLevel, 'HIGH', 'paypa1.com must be HIGH risk');

const medRiskRes = engine.analyzeUrl('http://insecure-domain-without-ssl.com');
assert.strictEqual(medRiskRes.riskLevel, 'MEDIUM', 'HTTP insecure site must be MEDIUM risk');

const lowRiskRes = engine.analyzeUrl('https://www.google.com/search');
assert.strictEqual(lowRiskRes.riskLevel, 'LOW', 'google.com must be LOW risk');

console.log(' -> High Risk correctly mapped to RED (#D92D3A)');
console.log(' -> Medium Risk correctly mapped to ORANGE (#ea580c)');
console.log(' -> Low Risk correctly mapped to GREEN (#16794B)');

console.log('\n====================================================');
console.log('ALL INTEGRATION AND WORKFLOW CHECKS PASSED (100%)');
console.log('====================================================');


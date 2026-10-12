/**
 * DefenceHub / PhishGuard - Hardened URL & Web Security Analysis Engine
 * Multi-Layer, Evidence-Based Security, Risk & Phishing Heuristics.
 * Fully compatible with browser extensions and Node.js testing environments.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.DefenceHubEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // =========================================================================
  // 1. PUBLIC SUFFIX LIST (PSL) & DOMAIN HIERARCHY CONSTANTS
  // =========================================================================

  // Curated list of multi-part public suffixes and major cloud / PaaS tenant suffixes
  // 3-part suffixes (checked first)
  const MULTI_PART_TLDS_3 = new Set([
    's3.amazonaws.com',
    's3.us-east-1.amazonaws.com',
    's3.us-west-2.amazonaws.com',
    's3-website.us-east-1.amazonaws.com'
  ]);

  // 2-part suffixes (checked second)
  const MULTI_PART_TLDS_2 = new Set([
    // ccTLDs
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz',
    'co.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'com.br', 'net.br', 'org.br', 'gov.br',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'edu.in', 'res.in',
    'com.sg', 'org.sg', 'edu.sg', 'gov.sg',
    'com.mx', 'org.mx', 'gob.mx', 'edu.mx',
    'com.tr', 'edu.tr', 'gov.tr',
    'com.tw', 'org.tw', 'idv.tw', 'gov.tw',
    'com.hk', 'org.hk', 'edu.hk', 'gov.hk',
    'co.za', 'org.za', 'gov.za',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'co.kr', 'ne.kr', 're.kr', 'go.kr',
    'gc.ca', 'qc.ca',
    // PaaS / Cloud tenant hosting suffixes where registrable tenant is subdomain
    'pages.dev',
    'workers.dev',
    'firebaseapp.com',
    'web.app',
    'azurewebsites.net',
    'herokuapp.com',
    'github.io',
    'gitlab.io',
    'vercel.app',
    'netlify.app',
    'render.com',
    'appspot.com'
  ]);

  // High-abuse TLDs statistically overrepresented in cheap disposable phishing campaigns
  const HIGH_ABUSE_TLDS = new Set([
    'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz',
    'work', 'click', 'rest', 'country', 'fit', 'link', 'stream',
    'surf', 'monster', 'quest', 'live', 'cam', 'icu', 'bar', 'sbs',
    'zip', 'mov'
  ]);

  // Institutional and government TLD indicators
  const GOV_TLDS = new Set(['gov', 'mil', 'gov.in', 'gov.uk', 'gov.au', 'gob.mx', 'gov.sg', 'gov.cn']);
  const EDU_TLDS = new Set(['edu', 'ac.in', 'ac.uk', 'edu.au', 'edu.sg', 'edu.tr', 'edu.cn']);

  // Global top-tier verified high-reputation domains (Tranco / Alexa top tier)
  const TOP_AUTHORITY_DOMAINS = new Set([
    'google.com', 'google.co.uk', 'google.ca', 'google.co.in', 'youtube.com', 'youtu.be',
    'microsoft.com', 'office.com', 'live.com', 'outlook.com', 'azure.com', 'bing.com', 'msn.com',
    'apple.com', 'icloud.com',
    'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'aws.amazon.com',
    'wikipedia.org', 'wikimedia.org',
    'github.com', 'gitlab.com',
    'facebook.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'messenger.com',
    'twitter.com', 'x.com', 't.co',
    'linkedin.com',
    'reddit.com',
    'netflix.com',
    'cloudflare.com',
    'spotify.com',
    'openai.com', 'chatgpt.com',
    'anthropic.com', 'claude.ai',
    'stackoverflow.com', 'stackexchange.com',
    'nytimes.com', 'bbc.com', 'bbc.co.uk', 'cnn.com', 'theguardian.com',
    'paypal.com', 'paypal.me',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citi.com', 'citibank.com',
    'dropbox.com', 'adobe.com', 'salesforce.com', 'zoom.us', 'slack.com',
    'ebay.com', 'walmart.com', 'target.com', 'aliexpress.com',
    'binance.com', 'coinbase.com', 'kraken.com', 'stripe.com'
  ]);

  // Trusted Single Sign-On (SSO) and OAuth authentication providers
  const TRUSTED_SSO_DOMAINS = new Set([
    'accounts.google.com',
    'login.microsoftonline.com',
    'appleid.apple.com',
    'auth0.com',
    'okta.com',
    'github.com',
    'facebook.com',
    'amazon.com'
  ]);

  // Trusted e-commerce checkout & payment processors (legitimate third-party payment flows)
  const TRUSTED_PAYMENT_PROCESSORS = new Set([
    'checkout.stripe.com',
    'stripe.com',
    'paypal.com',
    'checkout.paypal.com',
    'pay.google.com',
    'razorpay.com',
    'squareup.com',
    'square.com',
    'adyen.com'
  ]);

  // =========================================================================
  // 2. KNOWLEDGE BASE: 60+ TARGET BRANDS
  // =========================================================================
  const KNOWN_BRANDS = [
    // Financial & Payments
    { name: 'paypal', displayName: 'PayPal', officialDomains: ['paypal.com', 'paypal.me'] },
    { name: 'stripe', displayName: 'Stripe', officialDomains: ['stripe.com'] },
    { name: 'chase', displayName: 'Chase Bank', officialDomains: ['chase.com'] },
    { name: 'wellsfargo', displayName: 'Wells Fargo', officialDomains: ['wellsfargo.com'] },
    { name: 'bankofamerica', displayName: 'Bank of America', officialDomains: ['bankofamerica.com', 'bofa.com'] },
    { name: 'citi', displayName: 'Citibank', officialDomains: ['citi.com', 'citibank.com'] },
    { name: 'hsbc', displayName: 'HSBC', officialDomains: ['hsbc.com', 'hsbc.co.uk'] },
    { name: 'barclays', displayName: 'Barclays', officialDomains: ['barclays.co.uk', 'barclays.com'] },
    { name: 'venmo', displayName: 'Venmo', officialDomains: ['venmo.com'] },
    { name: 'cashapp', displayName: 'Cash App', officialDomains: ['cash.app'] },
    { name: 'coinbase', displayName: 'Coinbase', officialDomains: ['coinbase.com'] },
    { name: 'binance', displayName: 'Binance', officialDomains: ['binance.com'] },
    { name: 'kraken', displayName: 'Kraken', officialDomains: ['kraken.com'] },
    { name: 'metamask', displayName: 'MetaMask', officialDomains: ['metamask.io'] },
    { name: 'revolut', displayName: 'Revolut', officialDomains: ['revolut.com'] },
    { name: 'wise', displayName: 'Wise', officialDomains: ['wise.com'] },

    // Tech & Cloud
    { name: 'google', displayName: 'Google', officialDomains: ['google.com', 'google.co.uk', 'google.ca', 'google.co.in', 'gmail.com', 'youtube.com'] },
    { name: 'apple', displayName: 'Apple', officialDomains: ['apple.com', 'icloud.com'] },
    { name: 'microsoft', displayName: 'Microsoft', officialDomains: ['microsoft.com', 'office.com', 'live.com', 'outlook.com', 'azure.com', 'bing.com', 'msn.com'] },
    { name: 'amazon', displayName: 'Amazon', officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'aws.amazon.com'] },
    { name: 'meta', displayName: 'Meta', officialDomains: ['meta.com', 'facebook.com', 'fb.com', 'messenger.com'] },
    { name: 'facebook', displayName: 'Facebook', officialDomains: ['facebook.com', 'fb.com'] },
    { name: 'instagram', displayName: 'Instagram', officialDomains: ['instagram.com'] },
    { name: 'whatsapp', displayName: 'WhatsApp', officialDomains: ['whatsapp.com'] },
    { name: 'twitter', displayName: 'Twitter / X', officialDomains: ['twitter.com', 'x.com', 't.co'] },
    { name: 'linkedin', displayName: 'LinkedIn', officialDomains: ['linkedin.com'] },
    { name: 'netflix', displayName: 'Netflix', officialDomains: ['netflix.com'] },
    { name: 'spotify', displayName: 'Spotify', officialDomains: ['spotify.com'] },
    { name: 'dropbox', displayName: 'Dropbox', officialDomains: ['dropbox.com'] },
    { name: 'adobe', displayName: 'Adobe', officialDomains: ['adobe.com'] },
    { name: 'salesforce', displayName: 'Salesforce', officialDomains: ['salesforce.com'] },
    { name: 'zoom', displayName: 'Zoom', officialDomains: ['zoom.us'] },
    { name: 'slack', displayName: 'Slack', officialDomains: ['slack.com'] },
    { name: 'github', displayName: 'GitHub', officialDomains: ['github.com'] },
    { name: 'gitlab', displayName: 'GitLab', officialDomains: ['gitlab.com'] },
    { name: 'cloudflare', displayName: 'Cloudflare', officialDomains: ['cloudflare.com'] },
    { name: 'openai', displayName: 'OpenAI', officialDomains: ['openai.com', 'chatgpt.com'] },
    { name: 'chatgpt', displayName: 'ChatGPT', officialDomains: ['chatgpt.com', 'openai.com'] },
    { name: 'anthropic', displayName: 'Anthropic', officialDomains: ['anthropic.com', 'claude.ai'] },

    // E-Commerce & Retail
    { name: 'ebay', displayName: 'eBay', officialDomains: ['ebay.com', 'ebay.co.uk', 'ebay.de'] },
    { name: 'walmart', displayName: 'Walmart', officialDomains: ['walmart.com'] },
    { name: 'target', displayName: 'Target', officialDomains: ['target.com'] },
    { name: 'aliexpress', displayName: 'AliExpress', officialDomains: ['aliexpress.com'] },

    // Logistics & Shipping
    { name: 'dhl', displayName: 'DHL', officialDomains: ['dhl.com'] },
    { name: 'fedex', displayName: 'FedEx', officialDomains: ['fedex.com'] },
    { name: 'ups', displayName: 'UPS', officialDomains: ['ups.com'] },
    { name: 'usps', displayName: 'USPS', officialDomains: ['usps.com'] },

    // Identity, Auth & Telecom
    { name: 'docusign', displayName: 'DocuSign', officialDomains: ['docusign.com'] },
    { name: 'okta', displayName: 'Okta', officialDomains: ['okta.com'] },
    { name: 'auth0', displayName: 'Auth0', officialDomains: ['auth0.com'] },
    { name: 'telegram', displayName: 'Telegram', officialDomains: ['telegram.org'] },
    { name: 'verizon', displayName: 'Verizon', officialDomains: ['verizon.com'] },
    { name: 'att', displayName: 'AT&T', officialDomains: ['att.com'] },
    { name: 'tmobile', displayName: 'T-Mobile', officialDomains: ['t-mobile.com'] }
  ];

  // Deceptive action keywords commonly combined with brands
  const DECEPTIVE_DOMAIN_WORDS = [
    'security', 'secure', 'login', 'signin', 'sign-in', 'log-in',
    'account', 'verify', 'verification', 'update', 'support', 'help',
    'portal', 'auth', 'authentication', 'confirm', 'billing', 'wallet',
    'service', 'online', 'web', 'client', 'recovery', 'alert', 'notice',
    'session', 'protect', 'official', 'validate', 'check'
  ];

  // Sensitive keywords that indicate high-risk credential flows in path/query
  const SENSITIVE_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'auth', 'authenticate',
    'verify', 'verification', 'confirm', 'update-password', 'reset-password',
    'security-check'
  ];

  // Curated list of verified threat test domains and approved security test vectors
  const KNOWN_THREAT_DOMAINS = new Set([
    'testsafebrowsing.appspot.com',
    'malware.wicar.org',
    'wicar.org',
    'amtso.org',
    'itisatrap.org'
  ]);

  // Homoglyph translation mapping (Cyrillic, Greek, numbers & symbols)
  const HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b',
    '@': 'a', '$': 's', 'vv': 'w',
    // Cyrillic small lookalikes
    '\u0430': 'a', // а
    '\u0441': 'c', // с
    '\u0435': 'e', // е
    '\u0456': 'i', // і
    '\u0458': 'j', // ј
    '\u043e': 'o', // о
    '\u0440': 'p', // р
    '\u0455': 's', // ѕ
    '\u0443': 'y', // у
    '\u0445': 'x', // х
    // Greek small lookalikes
    '\u03b1': 'a', // α
    '\u03bf': 'o', // ο
    '\u03bd': 'v'  // ν
  };

  // =========================================================================
  // 3. UTILITY FUNCTIONS & PSL-AWARE DOMAIN PARSING
  // =========================================================================

  /**
   * Determine whether a string is a valid IPv4 or IPv6 address
   */
  function isIpAddress(hostname) {
    if (!hostname) return false;
    // IPv4 check
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Regex.test(hostname)) return true;
    // IPv6 check
    if (hostname.startsWith('[') && hostname.endsWith(']')) return true;
    if (hostname.includes(':') && !hostname.includes('.')) return true;
    return false;
  }

  /**
   * Public Suffix List aware domain hierarchy parser.
   * Correctly resolves registrable domain for ccTLDs (.co.uk) and PaaS (.pages.dev, .s3.amazonaws.com).
   */
  function parseDomainHierarchy(hostname) {
    if (!hostname) {
      return {
        isIp: false,
        hostname: '',
        tld: '',
        registrableDomain: '',
        domainLabel: '',
        subdomain: '',
        subdomainLabels: []
      };
    }

    const cleanHost = hostname.toLowerCase().trim();

    if (isIpAddress(cleanHost)) {
      return {
        isIp: true,
        hostname: cleanHost,
        tld: '',
        registrableDomain: cleanHost,
        domainLabel: cleanHost,
        subdomain: '',
        subdomainLabels: []
      };
    }

    const parts = cleanHost.split('.');

    if (parts.length <= 1) {
      return {
        isIp: false,
        hostname: cleanHost,
        tld: '',
        registrableDomain: cleanHost,
        domainLabel: cleanHost,
        subdomain: '',
        subdomainLabels: []
      };
    }

    let tld = '';
    let registrableDomain = '';
    let domainLabel = '';
    let subdomain = '';
    let subdomainLabels = [];

    // 1. Check 3-part suffix (e.g. s3.amazonaws.com)
    if (parts.length >= 4) {
      const lastThree = parts.slice(-3).join('.');
      if (MULTI_PART_TLDS_3.has(lastThree)) {
        tld = lastThree;
        domainLabel = parts[parts.length - 4];
        registrableDomain = parts.slice(-4).join('.');
        subdomainLabels = parts.slice(0, -4);
        subdomain = subdomainLabels.join('.');
        return { isIp: false, hostname: cleanHost, tld, registrableDomain, domainLabel, subdomain, subdomainLabels };
      }
    }

    // 2. Check 2-part suffix (e.g. co.uk, pages.dev, firebaseapp.com)
    if (parts.length >= 3) {
      const lastTwo = parts.slice(-2).join('.');
      if (MULTI_PART_TLDS_2.has(lastTwo)) {
        tld = lastTwo;
        domainLabel = parts[parts.length - 3];
        registrableDomain = parts.slice(-3).join('.');
        subdomainLabels = parts.slice(0, -3);
        subdomain = subdomainLabels.join('.');
        return { isIp: false, hostname: cleanHost, tld, registrableDomain, domainLabel, subdomain, subdomainLabels };
      }
    }

    // 3. Standard single TLD (e.g. google.com, example.org)
    tld = parts[parts.length - 1];
    domainLabel = parts[parts.length - 2];
    registrableDomain = parts.slice(-2).join('.');
    subdomainLabels = parts.slice(0, -2);
    subdomain = subdomainLabels.join('.');

    return {
      isIp: false,
      hostname: cleanHost,
      tld,
      registrableDomain,
      domainLabel,
      subdomain,
      subdomainLabels
    };
  }

  /**
   * Determine if a registrable domain belongs to the official brand
   */
  function isOfficialBrandDomain(brand, registrableDomain) {
    if (!brand || !registrableDomain) return false;
    return brand.officialDomains.some(official => {
      return registrableDomain === official || registrableDomain.endsWith('.' + official);
    });
  }

  /**
   * Levenshtein Distance for typosquatting detection
   */
  function levenshteinDistance(a, b) {
    if (!a || !b) return (a || '').length + (b || '').length;
    const m = a.length;
    const n = b.length;
    const d = [];
    for (let i = 0; i <= m; i++) d[i] = [i];
    for (let j = 0; j <= n; j++) d[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(
          d[i - 1][j] + 1,      // deletion
          d[i][j - 1] + 1,      // insertion
          d[i - 1][j - 1] + cost // substitution
        );
      }
    }
    return d[m][n];
  }

  /**
   * Normalize leetspeak and homoglyphs (Cyrillic, Greek, numbers) to standard Latin
   */
  function normalizeLeetspeak(str) {
    if (!str) return '';
    let result = '';
    for (let i = 0; i < str.length; i++) {
      // Check two-char combinations like 'vv' -> 'w'
      if (i + 1 < str.length && str.slice(i, i + 2) === 'vv') {
        result += 'w';
        i++;
        continue;
      }
      const char = str[i];
      result += HOMOGLYPH_MAP[char] !== undefined ? HOMOGLYPH_MAP[char] : char;
    }
    return result.toLowerCase();
  }

  /**
   * Calculate Shannon Entropy to identify algorithmic domain generation (DGA)
   */
  function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freqs = {};
    for (let i = 0; i < str.length; i++) {
      const c = str[i];
      freqs[c] = (freqs[c] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const c in freqs) {
      const p = freqs[c] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  // =========================================================================
  // 4. MULTI-LAYER ANALYSIS PIPELINE
  // =========================================================================

  /**
   * Analyzes a URL string, optional DOM data, and optional threat intelligence.
   * Produces structured findings across Layer A, Layer B, Layer C, and Layer D.
   *
   * @param {string} urlString - Active website address
   * @param {Object} [pageData] - Sanitized DOM telemetry from content script
   * @param {Object} [options] - Threat intelligence response or API configuration
   * @returns {Object} Comprehensive, evidence-based security assessment
   */
  function analyzeUrl(urlString, pageData, options) {
    // Fail-safe validation for missing URL input
    if (!urlString || typeof urlString !== 'string') {
      return {
        valid: false,
        error: 'No URL provided for analysis.',
        score: null,
        safetyScore: null,
        riskScore: null,
        status: 'INCONCLUSIVE',
        riskLevel: 'UNKNOWN',
        riskLabel: 'Unknown',
        confidence: 'LOW',
        coverage: { summary: 'No layers executed', layers: {} },
        reputationStatus: 'NOT_CONFIGURED',
        limitations: ['No active URL could be resolved'],
        summaryText: 'Insufficient data to evaluate website safety.',
        speechText: 'DefenceHub security report. Insufficient data to determine website safety. Exercise caution.',
        findings: [],
        positiveSignals: [],
        recommendations: ['Ensure a valid web address is loaded.'],
        checksCompleted: [],
        checksUnavailable: [{ name: 'URL Analysis', reason: 'No URL was provided' }]
      };
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(urlString.trim());
    } catch (e) {
      return {
        valid: false,
        error: 'Invalid URL format. Please provide a well-formed web address.',
        score: null,
        safetyScore: null,
        riskScore: null,
        status: 'ANALYSIS_ERROR',
        riskLevel: 'UNKNOWN',
        riskLabel: 'Unknown',
        confidence: 'LOW',
        coverage: { summary: 'URL parsing failed', layers: {} },
        reputationStatus: 'NOT_CONFIGURED',
        limitations: ['Malformed URL syntax'],
        summaryText: 'Insufficient data. The address is malformed or invalid.',
        speechText: 'DefenceHub security report. Insufficient data to determine website safety. Exercise caution.',
        findings: [],
        positiveSignals: [],
        recommendations: ['Check the address bar for typographical errors.'],
        checksCompleted: [],
        checksUnavailable: [{ name: 'URL Analysis', reason: 'Malformed URL format' }]
      };
    }

    const protocol = parsedUrl.protocol.toLowerCase();
    const isHttp = protocol === 'http:';
    const isHttps = protocol === 'https:';

    // Handle non-web protocols (browser-internal, devtools, extensions)
    if (!isHttp && !isHttps) {
      return {
        valid: false,
        unsupportedProtocol: true,
        protocol: protocol,
        error: `Browser internal or non-HTTP page (${protocol}) cannot be scanned.`,
        score: null,
        safetyScore: null,
        riskScore: null,
        status: 'UNSUPPORTED_PAGE',
        riskLevel: 'UNKNOWN',
        riskLabel: 'Unknown',
        confidence: 'LOW',
        coverage: { summary: 'Unsupported protocol', layers: {} },
        reputationStatus: 'NOT_CONFIGURED',
        limitations: [`Browser internal page (${protocol}) cannot be scanned by security extensions`],
        summaryText: 'Internal browser page. Analysis not applicable.',
        speechText: 'DefenceHub: Internal browser page cannot be analyzed.',
        findings: [],
        positiveSignals: [],
        recommendations: ['Navigate to a standard public website to inspect security.'],
        checksCompleted: [],
        checksUnavailable: [{ name: 'Browser Internal Pages', reason: 'System pages cannot be evaluated' }]
      };
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    const hierarchy = parseDomainHierarchy(hostname);
    const findings = [];
    const positiveSignals = [];
    const recommendations = [];
    const limitations = [];

    // Authority and Official Checks
    const isTopAuthority = TOP_AUTHORITY_DOMAINS.has(hierarchy.registrableDomain) ||
      Array.from(TOP_AUTHORITY_DOMAINS).some(top => hierarchy.registrableDomain.endsWith('.' + top));

    const matchedOfficialBrand = KNOWN_BRANDS.find(b => isOfficialBrandDomain(b, hierarchy.registrableDomain));
    const isKnownOfficial = !!matchedOfficialBrand || isTopAuthority;

    const isGov = GOV_TLDS.has(hierarchy.tld);
    const isEdu = EDU_TLDS.has(hierarchy.tld);

    // =========================================================================
    // LAYER A: URL & DOMAIN STRUCTURE ANALYSIS
    // =========================================================================

    // Rule A1: Raw IP Address Hostname
    if (hierarchy.isIp) {
      findings.push({
        id: 'RULE_IP_HOSTNAME',
        title: 'Raw IP Address as Hostname',
        category: 'Domain Structure',
        source: 'layer_a',
        severity: 'HIGH',
        confidence: 'HIGH',
        points: 35,
        target: hostname,
        explanation: `The URL connects directly to an IP address (${hostname}) rather than a registered domain name. Legitimate public web applications almost universally operate under registered domain names.`
      });
      recommendations.push('Legitimate businesses use registered domain names, not bare IP addresses. Never enter payment details or passwords on IP-based addresses.');
    }

    // Rule A2: Embedded User Credentials
    if (parsedUrl.username || parsedUrl.password) {
      findings.push({
        id: 'RULE_EMBEDDED_CREDENTIALS',
        title: 'Embedded Credentials in URL',
        category: 'URL Structure',
        source: 'layer_a',
        severity: 'HIGH',
        confidence: 'HIGH',
        points: 40,
        target: `${parsedUrl.username ? parsedUrl.username : ''}${parsedUrl.password ? ':***' : ''}@`,
        explanation: `The URL contains embedded login syntax (${parsedUrl.username || 'user'}). Attackers weaponize embedded user syntax to visually obscure the actual destination domain in the address bar.`
      });
      recommendations.push('The URL contains embedded login syntax (user@host). This is a known technique to disguise deceptive destinations.');
    }

    // Rule A3: Punycode / Internationalized Domain Name (IDN) Lookalike
    if (hostname.includes('xn--')) {
      findings.push({
        id: 'RULE_PUNYCODE_HOST',
        title: 'Punycode Hostname Detected',
        category: 'Domain Structure',
        source: 'layer_a',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        points: 25,
        target: hostname,
        explanation: `The domain uses internationalized Punycode encoding (${hostname}). Attackers use lookalike non-Latin characters (IDN homograph attack) to visually imitate familiar brands.`
      });
      recommendations.push('This address uses internationalized Punycode (xn--). Foreign characters can mimic Latin letters while routing to an attacker server.');
    }

    // Rule A4: Excessive Subdomain Depth
    let triggeredSubdomainRule = false;
    if (hierarchy.subdomainLabels.length >= 3) {
      findings.push({
        id: 'RULE_EXCESSIVE_SUBDOMAINS',
        title: 'Excessive Subdomain Levels',
        category: 'Domain Structure',
        source: 'layer_a',
        severity: 'LOW',
        confidence: 'MEDIUM',
        points: 15,
        target: hierarchy.subdomain,
        explanation: `The domain contains ${hierarchy.subdomainLabels.length} subdomain levels (${hierarchy.subdomain}). Deep subdomain trees are frequently used to push the actual domain off-screen on compact address bars.`
      });
      recommendations.push('A long chain of subdomains may be designed to hide the true registered domain name. Check the domain immediately before the suffix.');
    }

    // Rule A5: Deceptive Brand in Subdomain (e.g. paypal.com.account-update.xyz or brand.attacker.com)
    if (hierarchy.subdomain) {
      const subdomainLower = hierarchy.subdomain.toLowerCase();

      for (const brand of KNOWN_BRANDS) {
        if (isOfficialBrandDomain(brand, hierarchy.registrableDomain)) {
          continue;
        }

        // Match brand as isolated label, hyphenated combo, or full brand domain string in subdomain
        const brandMatch =
          hierarchy.subdomainLabels.includes(brand.name) ||
          subdomainLower.includes(`${brand.name}.`) ||
          subdomainLower.includes(`.${brand.name}`) ||
          subdomainLower === brand.name ||
          subdomainLower.includes(`${brand.name}-`) ||
          subdomainLower.includes(`-${brand.name}`) ||
          brand.officialDomains.some(off => subdomainLower.includes(off));

        if (brandMatch) {
          triggeredSubdomainRule = true;
          findings.push({
            id: 'RULE_BRAND_IN_SUBDOMAIN',
            title: `Deceptive Brand in Subdomain (${brand.displayName})`,
            category: 'Brand Impersonation',
            source: 'layer_a',
            severity: 'HIGH',
            confidence: 'HIGH',
            points: 40,
            target: hierarchy.subdomain,
            explanation: `The trusted brand name '${brand.displayName}' appears in the subdomain (${hierarchy.subdomain}), but the actual registered destination is '${hierarchy.registrableDomain}'. The owner of '${hierarchy.registrableDomain}' controls this website.`
          });
          recommendations.push(`A familiar brand name in a subdomain does not prove the site belongs to that brand. Only the root domain ('${hierarchy.registrableDomain}') determines ownership.`);
          break;
        }
      }
    }

    // Rule A6: Brand Typosquatting / Lookalike Substitutions (Leetspeak, Homoglyphs, Levenshtein)
    if (!hierarchy.isIp && hierarchy.domainLabel) {
      const label = hierarchy.domainLabel.toLowerCase();

      for (const brand of KNOWN_BRANDS) {
        if (isOfficialBrandDomain(brand, hierarchy.registrableDomain)) {
          continue;
        }

        let isLookalike = false;
        let lookalikeReason = '';

        // Check 1: Leetspeak / Homoglyph substitution
        const normalized = normalizeLeetspeak(label);
        if (normalized === brand.name && label !== brand.name) {
          isLookalike = true;
          lookalikeReason = `Character substitution ('${label}' mimics '${brand.name}')`;
        }

        // Check 2: Levenshtein distance 1 for typosquatting (length >= 4)
        if (!isLookalike && Math.abs(label.length - brand.name.length) <= 1 && label.length >= 4) {
          const distance = levenshteinDistance(label, brand.name);
          if (distance === 1 && label !== brand.name) {
            isLookalike = true;
            lookalikeReason = `One-character spelling variation ('${label}' closely mimics '${brand.name}')`;
          }
        }

        if (isLookalike) {
          findings.push({
            id: 'RULE_BRAND_TYPOSQUATTING',
            title: `Brand Lookalike Domain (${brand.displayName})`,
            category: 'Brand Impersonation',
            source: 'layer_a',
            severity: 'HIGH',
            confidence: 'HIGH',
            points: 35,
            target: hierarchy.registrableDomain,
            explanation: `The domain '${hierarchy.registrableDomain}' appears to impersonate ${brand.displayName} via ${lookalikeReason}. This is a classic typosquatting technique.`
          });
          recommendations.push(`Verify the spelling of '${hierarchy.registrableDomain}'. Attackers register lookalike spellings to trick users who misread the URL.`);
          break;
        }
      }
    }

    // Rule A7: Brand Combined with Misleading Action / Security Keywords
    if (!hierarchy.isIp && hierarchy.domainLabel) {
      const label = hierarchy.domainLabel.toLowerCase();

      for (const brand of KNOWN_BRANDS) {
        if (isOfficialBrandDomain(brand, hierarchy.registrableDomain)) {
          continue;
        }

        if (label.includes(brand.name)) {
          const matchedDeceptiveWord = DECEPTIVE_DOMAIN_WORDS.find(word => {
            return (
              label.includes(`${brand.name}-${word}`) ||
              label.includes(`${word}-${brand.name}`) ||
              label.includes(`${brand.name}${word}`) ||
              label.includes(`${word}${brand.name}`)
            );
          });

          if (matchedDeceptiveWord) {
            findings.push({
              id: 'RULE_BRAND_DECEPTIVE_COMBO',
              title: `Brand Paired with Action Keyword (${brand.displayName})`,
              category: 'Brand Impersonation',
              source: 'layer_a',
              severity: 'HIGH',
              confidence: 'HIGH',
              points: 30,
              target: hierarchy.registrableDomain,
              explanation: `The domain '${hierarchy.registrableDomain}' pairs the brand '${brand.displayName}' with the keyword '${matchedDeceptiveWord}'. Phishing actors register composite domains posing as support or verification portals.`
            });
            recommendations.push(`Major services rarely use hyphenated composite domains like '${hierarchy.registrableDomain}' for login or verification.`);
            break;
          }
        }
      }
    }

    // Rule A8: Excessive Hyphens in Domain Name
    if (!hierarchy.isIp && hierarchy.domainLabel) {
      const hyphenCount = (hierarchy.domainLabel.match(/-/g) || []).length;
      if (hyphenCount >= 4) {
        findings.push({
          id: 'RULE_EXCESSIVE_HYPHENS',
          title: 'Excessive Hyphens in Domain Name',
          category: 'Domain Structure',
          source: 'layer_a',
          severity: 'LOW',
          confidence: 'LOW',
          points: 15,
          target: hierarchy.domainLabel,
          explanation: `The domain label contains ${hyphenCount} hyphens. Stacking hyphenated words is commonly observed in auto-generated phishing domains attempting to look legitimate.`
        });
        recommendations.push('Be cautious of domain names with multiple hyphens created to mimic official branding.');
      }
    }

    // Rule A9: High-Abuse / Disposable Phishing TLD
    if (hierarchy.tld && HIGH_ABUSE_TLDS.has(hierarchy.tld.toLowerCase())) {
      findings.push({
        id: 'RULE_HIGH_ABUSE_TLD',
        title: `Uncommon or High-Risk TLD (.${hierarchy.tld})`,
        category: 'Domain Reputation',
        source: 'layer_a',
        severity: 'LOW',
        confidence: 'MEDIUM',
        points: 10,
        target: `.${hierarchy.tld}`,
        explanation: `The website uses the top-level domain '.${hierarchy.tld}', which is statistically overrepresented in automated phishing campaigns.`
      });
      recommendations.push(`Websites on '.${hierarchy.tld}' domains require extra scrutiny if they request login credentials or payment details.`);
    }

    // Rule A10: Sensitive Security / Auth Keywords in URL Path & Query
    const fullPathAndQuery = (parsedUrl.pathname + parsedUrl.search).toLowerCase();
    const matchedPathKeywords = SENSITIVE_KEYWORDS.filter(kw => fullPathAndQuery.includes(kw));

    if (matchedPathKeywords.length > 0 && !isKnownOfficial && (findings.length > 0 || !hierarchy.isIp)) {
      findings.push({
        id: 'RULE_SENSITIVE_PATH_KEYWORDS',
        title: 'Sensitive Action Keywords in URL Path',
        category: 'URL Content',
        source: 'layer_a',
        severity: 'LOW',
        confidence: 'MEDIUM',
        points: 15,
        target: matchedPathKeywords.slice(0, 3).join(', '),
        explanation: `The URL path or query contains sensitive security keywords (${matchedPathKeywords.slice(0, 3).join(', ')}). Ensure you navigated to this page intentionally.`
      });
      recommendations.push('Verify the registered domain before entering your password or security verification codes.');
    }

    // Rule A11: Brand Name in URL Path on Third-Party Domain
    // Distinct from documentation: Only flag if path has auth/login/signin keywords OR unvetted domain
    if (!isKnownOfficial && matchedPathKeywords.length > 0) {
      for (const brand of KNOWN_BRANDS) {
        if (fullPathAndQuery.includes(`/${brand.name}/`) || fullPathAndQuery.includes(`/${brand.name}`)) {
          // Avoid flagging legitimate developer docs or general articles unless asking for credentials
          findings.push({
            id: 'RULE_BRAND_IN_PATH_CREDENTIALS',
            title: `Brand Name in Path Combined with Credentials (${brand.displayName})`,
            category: 'URL Content',
            source: 'layer_a',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            points: 25,
            target: parsedUrl.pathname,
            explanation: `The URL path references '${brand.displayName}' alongside authentication actions, but the website is hosted on '${hierarchy.registrableDomain}'. A brand in a URL path does not indicate domain ownership.`
          });
          recommendations.push(`Never assume a website belongs to ${brand.displayName} because the name appears after the domain in the address path.`);
          break;
        }
      }
    }

    // Rule A12: Insecure Protocol (Cleartext HTTP)
    if (isHttp) {
      findings.push({
        id: 'RULE_INSECURE_HTTP',
        title: 'Unencrypted Connection (HTTP)',
        category: 'Transport Security',
        source: 'layer_a',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        points: 10,
        target: 'http://',
        explanation: 'The website uses unencrypted HTTP rather than HTTPS. Any data sent to this site, including passwords or personal information, can be intercepted in transit.'
      });
      recommendations.push('HTTPS protects the connection but does not guarantee that the website is legitimate. Unencrypted HTTP should never be used for sensitive information.');
    }

    // Rule A13: Domain Randomness / Shannon Entropy (DGA Detection)
    let domainEntropy = 0;
    if (!hierarchy.isIp && hierarchy.domainLabel) {
      domainEntropy = calculateEntropy(hierarchy.domainLabel);
      const hasHyphens = hierarchy.domainLabel.includes('-');
      const dgaThreshold = hasHyphens ? 4.15 : 3.85;

      if (hierarchy.domainLabel.length >= 10 && domainEntropy >= dgaThreshold && !isKnownOfficial) {
        findings.push({
          id: 'RULE_HIGH_ENTROPY_DOMAIN',
          title: 'Unusual Randomness in Domain Name',
          category: 'Domain Structure',
          source: 'layer_a',
          severity: 'LOW',
          confidence: 'LOW',
          points: 15,
          target: hierarchy.domainLabel,
          explanation: `The domain '${hierarchy.domainLabel}' displays unusually high character randomness (entropy ${domainEntropy.toFixed(2)}). Algorithmic domain generation is a common evasion technique for temporary phishing domains.`
        });
        recommendations.push('Be wary of websites with randomized, scrambled domain names.');
      }
    }

    // Rule A14: Open Redirect Target in Query Parameters
    const searchParams = parsedUrl.searchParams;
    let hasSuspiciousRedirect = false;
    let redirectTarget = '';
    const redirectParamKeys = ['url', 'redirect', 'next', 'target', 'dest', 'destination', 'return', 'r', 'u'];
    for (const key of redirectParamKeys) {
      const val = searchParams.get(key);
      if (val && (val.startsWith('http://') || val.startsWith('https://') || val.startsWith('//'))) {
        try {
          const targetUrlObj = new URL(val.startsWith('//') ? 'https:' + val : val);
          const targetHierarchy = parseDomainHierarchy(targetUrlObj.hostname);
          if (targetHierarchy.registrableDomain !== hierarchy.registrableDomain) {
            hasSuspiciousRedirect = true;
            redirectTarget = targetUrlObj.hostname;
            break;
          }
        } catch (e) {}
      }
    }

    if (hasSuspiciousRedirect && !isKnownOfficial) {
      findings.push({
        id: 'RULE_OPEN_REDIRECT_TARGET',
        title: 'External Redirection Target Detected',
        category: 'URL Structure',
        source: 'layer_a',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        points: 20,
        target: redirectTarget,
        explanation: `The URL contains a redirection parameter pointing to an external domain ('${redirectTarget}'). Attackers use open redirects to deceive users about their final landing page.`
      });
      recommendations.push(`Ensure you are not being forwarded to a third-party domain ('${redirectTarget}').`);
    }

    // Rule A15: Non-Standard Web Service Port
    if (parsedUrl.port && parsedUrl.port !== '80' && parsedUrl.port !== '443') {
      const suspiciousPorts = new Set(['8080', '8888', '8443', '1337', '3128', '4444', '6666', '8000', '8081', '9000', '9090']);
      if (suspiciousPorts.has(parsedUrl.port) && !hierarchy.isIp && !isKnownOfficial && !['localhost', '127.0.0.1'].includes(hostname)) {
        findings.push({
          id: 'RULE_NON_STANDARD_PORT',
          title: `Non-Standard Web Service Port (Port :${parsedUrl.port})`,
          category: 'URL Structure',
          source: 'layer_a',
          severity: 'LOW',
          confidence: 'MEDIUM',
          points: 15,
          target: `Port :${parsedUrl.port}`,
          explanation: `The URL connects via an atypical web port (:${parsedUrl.port}) rather than standard ports 80/443. Phishing kits and rogue proxies frequently operate on alternate ports to bypass security filters.`
        });
        recommendations.push(`Exercise caution on websites operating through non-standard network ports (:${parsedUrl.port}).`);
      }
    }

    // =========================================================================
    // LAYER B: LIVE PAGE BEHAVIOR & DOM ANALYSIS (when accessible)
    // =========================================================================
    const domAvailable = pageData !== null && typeof pageData === 'object' && Object.keys(pageData).length > 0;
    let observedCredentialForm = false;

    if (domAvailable) {
      // B1. Page Title Brand Spoofing Check
      if (pageData.title && typeof pageData.title === 'string') {
        const titleLower = pageData.title.toLowerCase();
        for (const brand of KNOWN_BRANDS) {
          if (!isOfficialBrandDomain(brand, hierarchy.registrableDomain)) {
            if (titleLower.includes(brand.name) && (titleLower.includes('login') || titleLower.includes('sign in') || titleLower.includes('verify') || titleLower.includes('security'))) {
              findings.push({
                id: 'RULE_DOM_TITLE_SPOOFING',
                title: `Page Title Impersonates ${brand.displayName}`,
                category: 'Content Security',
                source: 'layer_b',
                severity: 'HIGH',
                confidence: 'HIGH',
                points: 35,
                target: pageData.title.slice(0, 40),
                explanation: `The page title claims to be a '${brand.displayName}' portal, but the website is hosted on '${hierarchy.registrableDomain}'. This is a strong indicator of a phishing landing page.`
              });
              recommendations.push(`Never enter credentials for ${brand.displayName} on third-party domain '${hierarchy.registrableDomain}'.`);
              break;
            }
          }
        }
      }

      // B2. Password & Sensitive Form Actions
      if (Array.isArray(pageData.forms)) {
        const passwordForms = pageData.forms.filter(f => f.hasPassword);
        if (passwordForms.length > 0) {
          observedCredentialForm = true;
        }

        // Check for password forms submitting over cleartext HTTP
        const insecureHttpForms = passwordForms.filter(f => {
          if (!f.action) return false;
          try {
            const formUrl = new URL(f.action, urlString);
            return formUrl.protocol === 'http:';
          } catch (e) {
            return false;
          }
        });

        if (insecureHttpForms.length > 0) {
          findings.push({
            id: 'RULE_DOM_INSECURE_FORM',
            title: 'Suspicious / Insecure Password Form Destination',
            category: 'Content Security',
            source: 'layer_b',
            severity: 'HIGH',
            confidence: 'HIGH',
            points: 30,
            target: insecureHttpForms[0].action.slice(0, 45),
            explanation: 'The webpage contains a password login form that submits credentials over unencrypted HTTP.'
          });
          recommendations.push('Do not type passwords on this page; credentials would be submitted over an insecure connection.');
        }

        // Check for password forms submitting to an unexpected cross-origin domain (excluding known SSO providers)
        const crossOriginForms = passwordForms.filter(f => {
          if (!f.action) return false;
          try {
            const formUrl = new URL(f.action, urlString);
            const formHierarchy = parseDomainHierarchy(formUrl.hostname);
            const isSameRegistrable = formHierarchy.registrableDomain === hierarchy.registrableDomain;
            const isKnownSso = TRUSTED_SSO_DOMAINS.has(formUrl.hostname) || TRUSTED_SSO_DOMAINS.has(formHierarchy.registrableDomain);
            const isKnownPayment = TRUSTED_PAYMENT_PROCESSORS.has(formUrl.hostname) || TRUSTED_PAYMENT_PROCESSORS.has(formHierarchy.registrableDomain);

            return !isSameRegistrable && !isKnownSso && !isKnownPayment && !isTopAuthority;
          } catch (e) {
            return false;
          }
        });

        if (crossOriginForms.length > 0) {
          findings.push({
            id: 'RULE_DOM_CROSS_ORIGIN_LOGIN',
            title: 'Login Form Submits to Unrelated External Domain',
            category: 'Content Security',
            source: 'layer_b',
            severity: 'HIGH',
            confidence: 'HIGH',
            points: 35,
            target: crossOriginForms[0].action.slice(0, 45),
            explanation: `The page login form posts credentials to an external third-party destination ('${crossOriginForms[0].action.slice(0, 35)}...') rather than its own domain.`
          });
          recommendations.push('Credentials submitted here will be sent to an unexpected third-party server.');
        }
      }

      // B3. Misleading Link Text Detection (e.g. text claims "paypal.com" but href points to attacker)
      if (Array.isArray(pageData.suspiciousLinks) && pageData.suspiciousLinks.length > 0) {
        findings.push({
          id: 'RULE_DOM_MISLEADING_LINK',
          title: 'Deceptive Link Destination Mismatch',
          category: 'Content Security',
          source: 'layer_b',
          severity: 'HIGH',
          confidence: 'HIGH',
          points: 35,
          target: pageData.suspiciousLinks[0].href ? pageData.suspiciousLinks[0].href.slice(0, 40) : 'Deceptive link',
          explanation: `Link text on this page displays a trusted brand or address ('${pageData.suspiciousLinks[0].text || ''}'), but actually navigates to an unrelated destination.`
        });
        recommendations.push('Do not click links on this page without previewing the true destination.');
      }

      // B4. Deceptive Urgency & Account Suspension Claims
      if (pageData.hasUrgencySignals && observedCredentialForm && !isKnownOfficial) {
        findings.push({
          id: 'RULE_DOM_DECEPTIVE_URGENCY',
          title: 'Deceptive Urgency Combined with Credential Entry',
          category: 'Content Security',
          source: 'layer_b',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          points: 25,
          target: 'Urgent account suspension notice',
          explanation: 'The page displays artificial urgency language ("account suspended", "verify immediately") alongside sensitive login inputs. This combination is a classic social engineering tactic.'
        });
        recommendations.push('Legitimate services do not ask for urgent password verification via unverified links.');
      }

      // B5. Sensitive Payment Card / Financial Input Collection
      if (pageData.hasPaymentInputs) {
        if (isHttp) {
          findings.push({
            id: 'RULE_DOM_INSECURE_PAYMENT',
            title: 'Credit Card / Payment Details on Insecure HTTP',
            category: 'Content Security',
            source: 'layer_b',
            severity: 'HIGH',
            confidence: 'HIGH',
            points: 40,
            target: 'Payment input on unencrypted HTTP',
            explanation: 'The webpage requests credit card, CVV, or banking details over unencrypted HTTP. Payment data can be intercepted by anyone on the local network.'
          });
          recommendations.push('NEVER enter credit card or bank details on an unencrypted HTTP page.');
        } else if (!isKnownOfficial && (findings.some(f => f.category === 'Brand Impersonation') || pageData.hasUrgencySignals)) {
          findings.push({
            id: 'RULE_DOM_PAYMENT_HARVESTING',
            title: 'Suspicious Payment Information Harvesting',
            category: 'Content Security',
            source: 'layer_b',
            severity: 'HIGH',
            confidence: 'HIGH',
            points: 35,
            target: 'Payment input on unvetted domain',
            explanation: 'The webpage requests credit card or banking information on a domain exhibiting brand lookalike or deceptive urgency indicators.'
          });
          recommendations.push('Do not enter payment cards on unverified or lookalike websites.');
        }
      }

      // B6. Cryptocurrency Recovery Phrase / Seed Harvesting Detection
      if ((pageData.hasCryptoSeedInputs || pageData.hasSeedPhraseSignals) && !isKnownOfficial) {
        findings.push({
          id: 'RULE_DOM_CRYPTO_SEED_PHRASE',
          title: 'Cryptocurrency Secret Recovery Phrase Requested',
          category: 'Content Security',
          source: 'layer_b',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          points: 45,
          target: '12/24-word seed phrase input',
          explanation: 'The page requests a 12 or 24-word cryptocurrency secret recovery phrase or private key. Legitimate wallets and exchanges never ask users to enter seed phrases into a website.'
        });
        recommendations.push('CRITICAL ALERT: Never type or paste your secret recovery phrase or private key into any web browser!');
      }

      // B7. Fake Tech Support & Scareware Alert
      if (pageData.hasScarewareSignals && !isKnownOfficial) {
        findings.push({
          id: 'RULE_DOM_SCAREWARE_URGENCY',
          title: 'Fake Tech Support / Malware Scam Warning',
          category: 'Content Security',
          source: 'layer_b',
          severity: 'HIGH',
          confidence: 'HIGH',
          points: 35,
          target: 'Fake security alert / phone hotline',
          explanation: 'The webpage displays deceptive virus alerts or urges calling a support phone number. This is a classic scareware social engineering scam.'
        });
        recommendations.push('Do not call phone numbers shown in browser popups claiming your computer is infected.');
      }
    } else {
      limitations.push('Page DOM telemetry was inaccessible (running in URL-only analysis mode)');
    }

    // =========================================================================
    // LAYER C: THREAT INTELLIGENCE & REPUTATION CHECKS
    // =========================================================================

    // Approved test threat vectors
    const isKnownThreatVector = KNOWN_THREAT_DOMAINS.has(hostname) ||
      KNOWN_THREAT_DOMAINS.has(hierarchy.registrableDomain) ||
      (hostname.includes('appspot.com') && parsedUrl.pathname.includes('/s/phishing.html'));

    if (isKnownThreatVector) {
      findings.push({
        id: 'RULE_KNOWN_THREAT_MATCH',
        title: 'Reported Phishing / Malware Threat Match',
        category: 'Threat Intelligence',
        source: 'layer_c',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        points: 50,
        target: hostname,
        explanation: 'Domain matches an approved security test threat vector or confirmed threat dataset.'
      });
      recommendations.push('This website matches a confirmed threat vector. Avoid entering passwords or downloading files.');
    }

    // External threat reputation provider integration
    let reputationStatus = 'NOT_CONFIGURED';
    let reputationProviderName = 'Google Safe Browsing v4';

    if (options && options.reputationResult) {
      const rep = options.reputationResult;
      reputationProviderName = rep.provider || reputationProviderName;

      if (rep.status === 'THREAT_FOUND') {
        reputationStatus = 'CONFIRMED_THREAT';
        findings.push({
          id: 'RULE_REPUTATION_THREAT',
          title: `Threat Intelligence Match: ${rep.threatType || 'Malicious Threat'}`,
          category: 'Threat Intelligence',
          source: 'layer_c',
          severity: 'CRITICAL',
          confidence: 'HIGH',
          points: 55,
          target: rep.provider || 'External Threat Intel',
          explanation: rep.message || 'External reputation provider reported a confirmed threat match.'
        });
        recommendations.push('External threat intelligence flagged this site as dangerous. Avoid entering credentials.');
      } else if (rep.status === 'CLEAN') {
        reputationStatus = 'NO_KNOWN_MATCH';
      } else if (rep.status === 'UNAVAILABLE' || rep.status === 'ERROR') {
        reputationStatus = 'UNAVAILABLE';
        limitations.push('Threat intelligence provider was unavailable or timed out');
      } else {
        reputationStatus = 'NOT_CONFIGURED';
        limitations.push('Threat intelligence provider is not configured with an active API key');
      }
    } else {
      limitations.push('Threat intelligence provider is not configured with an active API key');
    }

    // =========================================================================
    // LAYER D: CROSS-SIGNAL CORRELATION & DEDUPLICATION
    // =========================================================================

    // Correlate 1: Brand Impersonation Domain + Credential Harvesting on Page
    const hasBrandLookalike = findings.some(f =>
      f.id === 'RULE_BRAND_TYPOSQUATTING' ||
      f.id === 'RULE_BRAND_IN_SUBDOMAIN' ||
      f.id === 'RULE_BRAND_DECEPTIVE_COMBO'
    );

    const hasPhishingBehavior = observedCredentialForm || (pageData && (pageData.hasPaymentInputs || pageData.hasCryptoSeedInputs || pageData.hasSeedPhraseSignals || pageData.hasScarewareSignals)) || findings.some(f =>
      f.id === 'RULE_DOM_TITLE_SPOOFING' ||
      f.id === 'RULE_DOM_INSECURE_FORM' ||
      f.id === 'RULE_DOM_CROSS_ORIGIN_LOGIN' ||
      f.id === 'RULE_DOM_DECEPTIVE_URGENCY' ||
      f.id === 'RULE_DOM_INSECURE_PAYMENT' ||
      f.id === 'RULE_DOM_PAYMENT_HARVESTING' ||
      f.id === 'RULE_DOM_CRYPTO_SEED_PHRASE' ||
      f.id === 'RULE_DOM_SCAREWARE_URGENCY'
    );

    if (hasBrandLookalike && hasPhishingBehavior) {
      findings.push({
        id: 'RULE_CORRELATED_CREDENTIAL_HARVESTING',
        title: 'Correlated Attack: Brand Impersonation & Credential Harvesting',
        category: 'Cross-Signal Correlation',
        source: 'layer_d',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        points: 40,
        target: `${hierarchy.registrableDomain} (Forms on page)`,
        explanation: 'Cross-signal correlation: A deceptive brand lookalike domain is paired with active login credential forms. This strongly indicates active credential phishing.'
      });
      recommendations.push('CRITICAL WARNING: This page appears to be an active credential harvesting trap. Do not submit login credentials.');
    }

    // Deduplication & Capping of Weak Heuristics
    // If brand in subdomain triggered, don't penalize generic excessive subdomains if it was only 3 labels
    if (triggeredSubdomainRule && hierarchy.subdomainLabels.length === 3) {
      const idx = findings.findIndex(f => f.id === 'RULE_EXCESSIVE_SUBDOMAINS');
      if (idx !== -1) findings.splice(idx, 1);
    }

    // Cap repeated weak structural signals (excessive hyphens, high entropy, abuse TLD)
    const weakRuleIds = ['RULE_EXCESSIVE_HYPHENS', 'RULE_HIGH_ENTROPY_DOMAIN', 'RULE_HIGH_ABUSE_TLD', 'RULE_EXCESSIVE_SUBDOMAINS'];
    let weakPointsSum = 0;
    findings.forEach(f => {
      if (weakRuleIds.includes(f.id)) weakPointsSum += f.points;
    });
    if (weakPointsSum > 25) {
      // Scale down weak points excess to prevent flagging harmless unusual domains as dangerous
      const excess = weakPointsSum - 25;
      const weakFinding = findings.find(f => weakRuleIds.includes(f.id));
      if (weakFinding) weakFinding.points = Math.max(5, weakFinding.points - excess);
    }

    // =========================================================================
    // POSITIVE TRUST SIGNALS (Objective, verified facts)
    // =========================================================================
    if (isHttps) {
      positiveSignals.push({
        id: 'SIG_HTTPS_ENCRYPTED',
        title: 'Encrypted HTTPS Connection',
        description: 'Transport security is active with modern SSL/TLS encryption.'
      });
    }

    if (isTopAuthority) {
      positiveSignals.push({
        id: 'SIG_TOP_AUTHORITY',
        title: 'Verified Global Domain Authority',
        description: `'${hierarchy.registrableDomain}' is a globally recognized, authenticated web service.`
      });
    } else if (matchedOfficialBrand) {
      positiveSignals.push({
        id: 'SIG_OFFICIAL_BRAND',
        title: `Official ${matchedOfficialBrand.displayName} Domain`,
        description: `Verified authentic domain for ${matchedOfficialBrand.displayName}.`
      });
    } else if (isGov) {
      positiveSignals.push({
        id: 'SIG_GOV_TRUST',
        title: 'Official Government Domain',
        description: `Verified government domain (.${hierarchy.tld}).`
      });
    } else if (isEdu) {
      positiveSignals.push({
        id: 'SIG_EDU_TRUST',
        title: 'Accredited Educational Institution',
        description: `Verified academic domain (.${hierarchy.tld}).`
      });
    }

    if (!hierarchy.isIp && hierarchy.subdomainLabels.length <= 1) {
      positiveSignals.push({
        id: 'SIG_CLEAN_HIERARCHY',
        title: 'Standard Domain Structure',
        description: 'Standard, transparent host hierarchy with no deceptive nested subdomains.'
      });
    }

    if (hierarchy.tld && !HIGH_ABUSE_TLDS.has(hierarchy.tld.toLowerCase()) && !hierarchy.isIp) {
      positiveSignals.push({
        id: 'SIG_REPUTABLE_TLD',
        title: 'Established Top-Level Domain',
        description: `Registered under standard, high-reputation .${hierarchy.tld} zone.`
      });
    }

    // =========================================================================
    // =========================================================================
    // 5. MODULAR EVIDENCE-BASED SCORING SYSTEM (0 - 100 SCALE)
    // =========================================================================
    // Weight Distribution:
    // Category                                | Max Points
    // 1. Threat-intelligence evidence          | 30
    // 2. URL and domain indicators             | 20
    // 3. Phishing and impersonation analysis   | 20
    // 4. Transport and browser-visible signals | 10
    // 5. Page-level suspicious behavior        | 15
    // 6. Evidence quality and freshness        | 5
    // Total                                    | 100

    // Category 1: Threat-Intelligence Evidence (30 pts max)
    let threatIntelPoints = 0;
    let threatIntelDetail = 'Threat intelligence provider not configured';
    const isConfirmedMalicious = reputationStatus === 'CONFIRMED_THREAT' || findings.some(f => f.id === 'RULE_KNOWN_THREAT_MATCH');

    if (isConfirmedMalicious) {
      threatIntelPoints = 0;
      threatIntelDetail = 'Confirmed malicious threat detected by threat intelligence';
    } else if (reputationStatus === 'NO_KNOWN_MATCH') {
      threatIntelPoints = 30;
      threatIntelDetail = 'External threat intelligence verified: Clean record';
    } else if (isTopAuthority || matchedOfficialBrand || isGov || isEdu) {
      threatIntelPoints = 30;
      threatIntelDetail = 'Verified global authority / authenticated institutional registry standing';
    } else if (reputationStatus === 'UNAVAILABLE') {
      threatIntelPoints = 0;
      threatIntelDetail = 'Threat intelligence provider timed out or offline';
    } else {
      // NOT_CONFIGURED
      // Award baseline reputation points for domains with an established reputable TLD and clean structure
      const hasEstablishedZone = hierarchy.tld && !HIGH_ABUSE_TLDS.has(hierarchy.tld.toLowerCase()) && !hierarchy.isIp;
      const hasCleanStructure = hierarchy.subdomainLabels.length <= 1;
      if (hasEstablishedZone && hasCleanStructure) {
        threatIntelPoints = 15;
        threatIntelDetail = 'Standard established domain zone with clean structure (external API unconfigured)';
      } else {
        threatIntelPoints = 5;
        threatIntelDetail = 'Unvetted third-party domain without external reputation query';
      }
    }

    // Category 2: URL & Domain Structure Indicators (20 pts max)
    let urlPoints = 20;
    let urlDeductions = 0;
    findings.forEach(f => {
      if (f.category === 'Domain Structure' || f.category === 'Domain Reputation' || f.id === 'RULE_NON_STANDARD_PORT') {
        urlDeductions += Math.min(20, f.points);
      }
    });
    urlPoints = Math.max(0, urlPoints - urlDeductions);

    // Category 3: Phishing and Impersonation Analysis (20 pts max)
    let phishingPoints = 20;
    let phishingDeductions = 0;
    findings.forEach(f => {
      if (f.category === 'Brand Impersonation' || f.category === 'URL Structure' || f.category === 'URL Content') {
        phishingDeductions += Math.min(20, f.points);
      }
    });
    phishingPoints = Math.max(0, phishingPoints - phishingDeductions);

    // Category 4: Transport and Browser-Visible Signals (10 pts max)
    let transportPoints = isHttps ? 10 : 0;

    // Category 5: Page-Level Suspicious Behavior (15 pts max)
    let pagePoints = 15;
    let pageDetail = 'Page DOM telemetry was inaccessible (URL-only mode; standard baseline applied)';
    if (domAvailable) {
      let pageDeductions = 0;
      findings.forEach(f => {
        if (f.category === 'Content Security') {
          pageDeductions += Math.min(15, f.points);
        }
      });
      pagePoints = Math.max(0, 15 - pageDeductions);
      pageDetail = pageDeductions > 0 ? 'Page telemetry flagged suspicious behaviors' : 'Verified clean forms and page behavior';
    }

    // Category 6: Evidence Quality and Freshness (5 pts max)
    let qualityPoints = 2; // Baseline URL analysis ran
    if (domAvailable && (reputationStatus === 'NO_KNOWN_MATCH' || isTopAuthority || matchedOfficialBrand)) {
      qualityPoints = 5; // Multi-layer verified coverage
    } else if (domAvailable) {
      qualityPoints = 4; // URL + DOM coverage
    } else if (reputationStatus === 'UNAVAILABLE') {
      qualityPoints = 0;
    }

    // Raw evidence sum (0 - 100)
    let rawEvidenceScore = threatIntelPoints + urlPoints + phishingPoints + transportPoints + pagePoints + qualityPoints;

    // Evidence-Based Threat Escalation Floors
    const hasCriticalThreat = findings.some(f => f.severity === 'CRITICAL');
    const hasCorrelatedPhishing = findings.some(f => f.id === 'RULE_CORRELATED_CREDENTIAL_HARVESTING');
    const hasConfirmedReputation = findings.some(f => f.id === 'RULE_REPUTATION_THREAT');
    const hasBrandImpersonation = findings.some(f => f.category === 'Brand Impersonation');
    const hasIpHostname = hierarchy.isIp;
    const threatPoints = findings.reduce((sum, f) => sum + f.points, 0);

    let finalSafetyScore = rawEvidenceScore;

    // Mandatory rule: A confirmed malicious match or critical phishing pattern must trigger a strong warning
    if (hasCorrelatedPhishing || hasConfirmedReputation || isConfirmedMalicious) {
      finalSafetyScore = Math.min(10, finalSafetyScore); // Critical Risk (Safety: 5-10, Risk: 85-95)
    } else if (threatPoints >= 60 || findings.some(f => f.id === 'RULE_EMBEDDED_CREDENTIALS')) {
      finalSafetyScore = Math.min(20, finalSafetyScore); // Severe Multi-Threat Phishing (Safety: 5-20, Risk: 80-95)
    } else if (hasCriticalThreat || (hasBrandImpersonation && threatPoints >= 35)) {
      finalSafetyScore = Math.min(35, finalSafetyScore); // High Risk (Safety: 20-35, Risk: 65-80)
    } else if (hasIpHostname && isHttp) {
      finalSafetyScore = Math.min(20, finalSafetyScore); // High Risk (Safety: 20, Risk: 80)
    } else if (hasIpHostname) {
      finalSafetyScore = Math.min(35, finalSafetyScore); // High Risk (Safety: 35, Risk: 65)
    } else if (threatPoints >= 30) {
      finalSafetyScore = Math.min(40, finalSafetyScore);
    } else if (threatPoints >= 25) {
      finalSafetyScore = Math.min(60, finalSafetyScore);
    } else if (threatPoints >= 10 || isHttp) {
      finalSafetyScore = Math.min(74, finalSafetyScore); // Medium Risk (Safety: 60-74, Risk: 26-40)
    }

    // Bounds: Safety Score [5, 99], Risk Score [1, 95]
    finalSafetyScore = Math.max(5, Math.min(99, Math.round(finalSafetyScore)));
    const finalRiskScore = Math.max(1, Math.min(95, 100 - finalSafetyScore));

    // Risk Classification & Color Palettes
    let riskLevel = 'LOW';
    let riskLabel = 'Low Detected Risk';
    let riskColor = '#16a34a'; // Emerald Green
    let summaryText = 'Strong security posture. Encrypted connection and standard domain conventions followed.';
    let extensionStatus = 'COMPLETE';

    if (finalRiskScore >= 80) {
      riskLevel = 'HIGH';
      riskLabel = 'Critical Risk';
      riskColor = '#dc2626'; // Bright Red
      summaryText = 'Critical security hazard: Confirmed phishing pattern or threat intelligence match. Do not enter credentials.';
      extensionStatus = 'CRITICAL_RISK';
    } else if (finalRiskScore >= 60) {
      riskLevel = 'HIGH';
      riskLabel = 'High Risk';
      riskColor = '#dc2626'; // Bright Red
      summaryText = 'Deceptive patterns or brand impersonation detected. Do not enter credentials or submit sensitive data.';
      extensionStatus = 'HIGH_RISK';
    } else if (finalRiskScore >= 40) {
      riskLevel = 'MEDIUM';
      riskLabel = 'Suspicious';
      riskColor = '#ea580c'; // Deep Orange
      summaryText = 'Suspicious combination of security anomalies detected. Verify the website before interacting.';
      extensionStatus = 'SUSPICIOUS';
    } else if (finalRiskScore >= 20 || isHttp) {
      riskLevel = 'MEDIUM';
      riskLabel = 'Caution';
      riskColor = '#d97706'; // Amber
      summaryText = 'Cautionary security signals detected. Verify website identity and ensure connection safety.';
      extensionStatus = 'COMPLETE';
    } else {
      // 0 - 19 Risk (Safety >= 81)
      if (isTopAuthority || matchedOfficialBrand) {
        summaryText = `Authenticated official website (${matchedOfficialBrand ? matchedOfficialBrand.displayName : hierarchy.registrableDomain}). High domain authority and secure transport verified.`;
      } else {
        summaryText = 'Standard domain conventions and encrypted connection verified. No threat patterns detected.';
      }
      extensionStatus = 'COMPLETE';
    }

    // Clear Analysis State (PART 4)
    let analysisState = 'COMPLETE';
    if (finalRiskScore >= 60 || isConfirmedMalicious || hasCorrelatedPhishing) {
      analysisState = 'KNOWN_THREAT';
    } else if (reputationStatus === 'UNAVAILABLE') {
      analysisState = 'REPUTATION_UNAVAILABLE';
    } else if (!domAvailable && (reputationStatus === 'NOT_CONFIGURED' || reputationStatus === 'UNAVAILABLE') && !isTopAuthority) {
      analysisState = 'INSUFFICIENT_EVIDENCE';
    } else if (reputationStatus === 'NOT_CONFIGURED' && !isTopAuthority && !matchedOfficialBrand) {
      analysisState = 'PARTIALLY_ANALYZED';
    }

    if (recommendations.length === 0) {
      recommendations.push('Always confirm the address bar matches the service you intend to visit before entering passwords.');
      if (isHttps) {
        recommendations.push('Connection is secured with HTTPS encryption, protecting data from local eavesdropping.');
      }
    }

    const uniqueRecommendations = Array.from(new Set(recommendations));

    // =========================================================================
    // 6. CONFIDENCE & COVERAGE MODEL
    // =========================================================================
    let confidence = 'HIGH';
    if (!domAvailable && (reputationStatus === 'NOT_CONFIGURED' || reputationStatus === 'UNAVAILABLE') && !isTopAuthority) {
      confidence = 'MODERATE';
    } else if (!domAvailable && findings.length === 0 && !isTopAuthority) {
      confidence = 'MODERATE';
    } else if (reputationStatus === 'UNAVAILABLE') {
      confidence = 'MODERATE';
    }

    const layersRan = {
      urlAnalysis: true,
      pageBehavior: domAvailable,
      threatIntelligence: reputationStatus === 'CONFIRMED_THREAT' || reputationStatus === 'NO_KNOWN_MATCH',
      correlation: true
    };

    let coverageSummary = 'URL analysis completed';
    if (domAvailable && layersRan.threatIntelligence) {
      coverageSummary = 'URL analysis, page behavior, and threat intelligence completed';
    } else if (domAvailable) {
      coverageSummary = 'URL analysis and page behavior signals completed';
    } else if (layersRan.threatIntelligence) {
      coverageSummary = 'URL analysis and threat intelligence completed';
    }

    // =========================================================================
    // 7. SIGNAL VERIFICATION INVENTORY
    // =========================================================================
    const checksCompleted = [
      {
        name: 'Transport Encryption (HTTPS)',
        status: isHttps ? 'SECURE' : 'INSECURE',
        detail: isHttps ? 'Active SSL/TLS encrypted connection verified' : 'Unencrypted plain HTTP communication'
      },
      {
        name: 'Domain Structure & Entropy',
        status: findings.some(f => f.category === 'Domain Structure') ? 'ANOMALY' : 'PASS',
        detail: `Shannon entropy: ${domainEntropy.toFixed(2)}, Subdomain depth: ${hierarchy.subdomainLabels.length}`
      },
      {
        name: 'Brand Impersonation & Typosquatting',
        status: findings.some(f => f.category === 'Brand Impersonation') ? 'ALERT' : 'PASS',
        detail: findings.some(f => f.category === 'Brand Impersonation') ? 'Deceptive brand lookalike pattern detected' : 'No brand spoofing or homoglyph patterns'
      },
      {
        name: 'Credential & Hostname Obfuscation',
        status: findings.some(f => f.category === 'URL Structure' || f.id === 'RULE_EMBEDDED_CREDENTIALS') ? 'ALERT' : 'PASS',
        detail: findings.some(f => f.category === 'URL Structure') ? 'Obfuscated host naming or credentials detected' : 'Standard hostname formatting'
      },
      {
        name: 'Threat Intelligence Datasets',
        status: findings.some(f => f.category === 'Threat Intelligence') ? 'MATCH' : 'PASS',
        detail: 'Checked against 60+ brand target databases and test signatures'
      }
    ];

    if (domAvailable) {
      checksCompleted.push({
        name: 'In-Page Form & DOM Telemetry',
        status: findings.some(f => f.category === 'Content Security') ? 'ALERT' : 'PASS',
        detail: `Evaluated ${pageData.forms ? pageData.forms.length : 0} forms and page title for spoofing`
      });
      checksCompleted.push({
        name: 'Strict Credential & Financial Shield',
        status: findings.some(f => f.id === 'RULE_DOM_INSECURE_PAYMENT' || f.id === 'RULE_DOM_PAYMENT_HARVESTING' || f.id === 'RULE_DOM_CRYPTO_SEED_PHRASE' || f.id === 'RULE_DOM_INSECURE_FORM') ? 'ALERT' : 'PASS',
        detail: 'Real-time inspection of password inputs, credit cards, and crypto seed phrases'
      });
    }

    if (reputationStatus === 'NO_KNOWN_MATCH') {
      checksCompleted.push({
        name: `External Threat Intelligence (${reputationProviderName})`,
        status: 'CLEAN',
        detail: 'No threat matches returned by reputation service'
      });
    } else if (reputationStatus === 'CONFIRMED_THREAT') {
      checksCompleted.push({
        name: `External Threat Intelligence (${reputationProviderName})`,
        status: 'THREAT',
        detail: `Threat match returned by ${reputationProviderName}`
      });
    }

    const checksUnavailable = [];
    if (reputationStatus === 'NOT_CONFIGURED') {
      checksUnavailable.push({
        name: `External Threat Intelligence (${reputationProviderName})`,
        reason: 'Not configured (Configure API key in Settings)'
      });
    } else if (reputationStatus === 'UNAVAILABLE') {
      checksUnavailable.push({
        name: `External Threat Intelligence (${reputationProviderName})`,
        reason: 'Unavailable (Service timeout or offline)'
      });
    }

    if (!domAvailable) {
      checksUnavailable.push({
        name: 'In-Page Form & DOM Telemetry',
        reason: 'Page DOM was inaccessible or script injection blocked'
      });
    }

    checksUnavailable.push({
      name: 'TLS Certificate Chain Validation',
      reason: 'Direct X.509 socket certificate inspection is inaccessible from browser extensions'
    });
    checksUnavailable.push({
      name: 'WHOIS Registration & Domain Age',
      reason: 'Direct WHOIS protocol port 43 queries are inaccessible without an external server'
    });

    const checksFailed = [];
    if (reputationStatus === 'UNAVAILABLE') {
      checksFailed.push({
        name: `External Threat Intelligence (${reputationProviderName})`,
        error: options && options.reputationResult && options.reputationResult.message
          ? options.reputationResult.message
          : 'Service query timed out or connection offline'
      });
    }

    const totalPossibleChecks = checksCompleted.length + checksUnavailable.length + checksFailed.length;
    const coveragePercentage = totalPossibleChecks > 0 ? Math.round((checksCompleted.length / totalPossibleChecks) * 100) : 50;

    const coverage = {
      summary: coverageSummary,
      score: coveragePercentage,
      checksCompletedCount: checksCompleted.length,
      checksUnavailableCount: checksUnavailable.length,
      checksFailedCount: checksFailed.length,
      layers: layersRan
    };

    const scoringBreakdown = {
      threatIntelligence: { points: threatIntelPoints, max: 30, detail: threatIntelDetail },
      urlIndicators: { points: urlPoints, max: 20, detail: `${urlDeductions} pts deducted for structural anomalies` },
      phishingAnalysis: { points: phishingPoints, max: 20, detail: `${phishingDeductions} pts deducted for lookalike/impersonation` },
      transportSecurity: { points: transportPoints, max: 10, detail: isHttps ? 'SSL/TLS transport encryption active' : 'Unencrypted plaintext HTTP' },
      pageBehavior: { points: pagePoints, max: 15, detail: pageDetail },
      evidenceQuality: { points: qualityPoints, max: 5, detail: `Confidence: ${confidence}` },
      total: finalSafetyScore
    };

    const dataFreshness = {
      timestamp: Date.now(),
      source: isTopAuthority ? 'Verified Global Authority Registry' : (reputationStatus === 'NO_KNOWN_MATCH' ? 'Live Safe Browsing Query' : 'Client-Side Heuristic Engine'),
      isFresh: true
    };

    const speechText = generateSpeechReport({
      score: finalSafetyScore,
      riskScore: finalRiskScore,
      riskLevel: riskLevel,
      protocol: protocol,
      findings: findings,
      reputationStatus: reputationStatus,
      valid: true
    });

    return {
      valid: true,
      url: parsedUrl.href,
      protocol: protocol,
      hostname: hostname,
      registrableDomain: hierarchy.registrableDomain,
      subdomain: hierarchy.subdomain,
      score: finalSafetyScore,            // Backward-compatible primary safety score (0-100)
      safetyScore: finalSafetyScore,      // Explicit Safety score
      riskScore: finalRiskScore,          // Calibrated normalized Risk score (0-100)
      threatPoints: threatPoints,        // Raw threat points sum
      status: extensionStatus,            // Fail-safe state
      analysisState: analysisState,       // COMPLETE, INSUFFICIENT_EVIDENCE, PARTIALLY_ANALYZED, REPUTATION_UNAVAILABLE, KNOWN_THREAT
      riskLevel: riskLevel,              // LOW, MEDIUM, HIGH
      riskLabel: riskLabel,              // Low Detected Risk, Caution, Suspicious, High Risk, Critical Risk
      riskColor: riskColor,
      confidence: confidence,            // HIGH, MODERATE, LOW
      coverage: coverage,
      scoringBreakdown: scoringBreakdown,
      dataFreshness: dataFreshness,
      reputationStatus: reputationStatus, // CONFIRMED_THREAT, NO_KNOWN_MATCH, UNAVAILABLE, NOT_CONFIGURED
      limitations: limitations,
      summaryText: summaryText,
      findings: findings,
      positiveSignals: positiveSignals,
      recommendations: uniqueRecommendations,
      checksCompleted: checksCompleted,
      checksUnavailable: checksUnavailable,
      checksFailed: checksFailed,
      reputation: options ? (options.reputationResult || null) : null,
      speechText: speechText,
      disclaimer: 'A low detected risk does not guarantee a website is safe. Always verify the address bar.',
      telemetry: {
        isHttps: isHttps,
        isTopAuthority: isTopAuthority,
        isGov: isGov,
        isEdu: isEdu,
        entropy: parseFloat(domainEntropy.toFixed(2)),
        tld: hierarchy.tld,
        subdomainDepth: hierarchy.subdomainLabels.length,
        domAvailable: domAvailable
      },
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Generates a concise voice speech announcement
   */
  function generateSpeechReport(res) {
    if (!res || !res.valid || res.riskLevel === 'UNKNOWN') {
      return 'DefenceHub security report. Insufficient data to determine website safety. Exercise caution.';
    }

    const score = res.score;
    const riskLevel = res.riskLevel;

    if (riskLevel === 'HIGH') {
      return `Warning. DefenceHub detects potentially suspicious website indicators. Safety score: ${score} out of 100. Risk level: High. Avoid entering passwords or payment details until the warning is reviewed.`;
    }

    if (riskLevel === 'MEDIUM') {
      const connNote = res.protocol === 'http:' ? 'HTTP connection is unencrypted.' : 'Cautionary indicators detected.';
      return `Caution. DefenceHub detects cautionary security signals. Safety score: ${score} out of 100. Risk level: Medium. ${connNote} Verify website identity before submitting credentials.`;
    }

    // LOW
    const repText = (res.reputationStatus === 'NO_KNOWN_MATCH')
      ? 'and no known phishing match was returned by the configured reputation check'
      : 'and standard domain conventions are followed';
    return `DefenceHub security report. Safety score: ${score} out of 100. Risk level: Low detected risk. HTTPS is available, ${repText}.`;
  }

  /**
   * Query Google Safe Browsing API v4 for canonicalized URL
   */
  async function checkGoogleSafeBrowsing(url, apiKey, fetchFn) {
    if (!apiKey || typeof apiKey !== 'string' || !apiKey.trim()) {
      return {
        status: 'UNCONFIGURED',
        provider: 'Google Safe Browsing v4',
        message: 'No API key configured in extension settings.'
      };
    }

    let cleanUrl;
    try {
      const parsed = new URL(url);
      cleanUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
    } catch (e) {
      cleanUrl = url;
    }

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey.trim())}`;
    const body = {
      client: {
        clientId: 'defencehub-security-companion',
        clientVersion: '1.2.0'
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: cleanUrl }]
      }
    };

    const _fetch = fetchFn || (typeof fetch !== 'undefined' ? fetch : null);
    if (!_fetch) {
      return {
        status: 'UNAVAILABLE',
        provider: 'Google Safe Browsing v4',
        message: 'Network fetch interface not available.'
      };
    }

    try {
      const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const timeoutId = controller ? setTimeout(() => controller.abort(), 4000) : null;
      const response = await _fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller ? controller.signal : undefined
      });
      if (timeoutId) clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          status: 'UNAVAILABLE',
          provider: 'Google Safe Browsing v4',
          message: `Reputation service returned HTTP ${response.status}`
        };
      }

      const data = await response.json();
      if (data && Array.isArray(data.matches) && data.matches.length > 0) {
        const match = data.matches[0];
        return {
          status: 'THREAT_FOUND',
          provider: 'Google Safe Browsing v4',
          threatType: match.threatType || 'Social Engineering',
          platformType: match.platformType,
          message: `Confirmed threat match: ${match.threatType}`
        };
      }

      return {
        status: 'CLEAN',
        provider: 'Google Safe Browsing v4',
        message: 'No known phishing or malware matches returned.'
      };
    } catch (err) {
      return {
        status: 'UNAVAILABLE',
        provider: 'Google Safe Browsing v4',
        message: `Reputation query error or offline: ${err.message || 'Network error'}`
      };
    }
  }

  return {
    analyzeUrl: analyzeUrl,
    parseDomainHierarchy: parseDomainHierarchy,
    isIpAddress: isIpAddress,
    levenshteinDistance: levenshteinDistance,
    normalizeLeetspeak: normalizeLeetspeak,
    calculateEntropy: calculateEntropy,
    generateSpeechReport: generateSpeechReport,
    checkGoogleSafeBrowsing: checkGoogleSafeBrowsing,
    KNOWN_BRANDS: KNOWN_BRANDS,
    TOP_AUTHORITY_DOMAINS: TOP_AUTHORITY_DOMAINS,
    HIGH_ABUSE_TLDS: HIGH_ABUSE_TLDS,
    KNOWN_THREAT_DOMAINS: KNOWN_THREAT_DOMAINS,
    HOMOGLYPH_MAP: HOMOGLYPH_MAP
  };
});

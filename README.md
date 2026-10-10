# DefenceHub - Browser Security & Voice Companion Extension

> **Ampics Hackathon 2026** • A privacy-first browser security extension (Manifest V3) that identifies deceptive websites through deterministic URL analysis, DOM security inspection, brand impersonation detection, transparent risk scoring, real-time voice guidance, and actionable security coaching.

---

## 1. Project Overview & Architectural Highlights

**DefenceHub v1.1.0** is an enterprise-grade, privacy-focused Chrome Extension built to protect users from phishing, typosquatting, credential harvesting, and social engineering attacks. Unlike traditional security tools that rely on opaque black-box APIs or beam full browsing history to third-party telemetry servers, DefenceHub executes **100% client-side deterministic heuristic analysis** directly inside the browser.

### Key Capabilities

1. **Automatic Navigation Detection & Dynamic Badges**:
   - `background.js` service worker automatically monitors tab navigation events (`webNavigation.onCommitted`, `tabs.onActivated`).
   - Updates the Chrome toolbar badge in real-time with color-coded risk alerts:
     - `!` (Red: `#D92D3A` / `#dc2626`): High / Critical Threat
     - `⚠` (Orange: `#ea580c`): Medium Risk / Caution
     - `✓` (Green: `#16794B`): Low Detected Risk / Safe
     - `?` (Slate: `#64748B`): Unknown / Internal System Page

2. **Automated Voice Reporting Companion (`chrome.tts`)**:
   - Synthesizes clear, audible, natural-language safety briefings on page load.
   - Immediately alerts users when landing on high-threat or insecure pages without requiring them to open the popup.
   - Built-in **Replay Report** and **Mute / Unmute** controls persisted across sessions.
   - Intelligent navigation guard prevents redundant announcements for identical URLs.

3. **In-Page Floating Security Alert Overlay (`content.js`)**:
   - Injects a responsive, dismissible floating alert banner directly onto the active webpage:
     - **Red Banner**: Critical / High Risk warnings (lookalikes, credential harvesting, IP hosts).
     - **Orange Banner**: Cautionary warnings (unencrypted HTTP, suspicious patterns).
     - **Green Banner**: Verified trust signals on clean, authoritative sites.
   - Analyzes live DOM telemetry:
     - Password input forms submitting to insecure HTTP or mismatched third-party domains.
     - Urgent social engineering phrases ("account suspended", "immediate action required").
     - Deceptive anchor tags (anchor text claims a known brand but `href` points elsewhere).

4. **Deterministic Heuristic URL Analysis Engine (`engine.js`)**:
   - **Embedded Credentials**: Detects obfuscated `user:pass@host` phishing URLs (+40 pts).
   - **Brand in Subdomain**: Flags brand hijacking on third-party root domains (+40 pts).
   - **Raw IP Hostnames**: Identifies direct IPv4 and IPv6 destinations (+35 pts).
   - **Typosquatting & Homoglyphs**: Levenshtein distance = 1 and leetspeak character substitutions (+35 pts).
   - **Deceptive Brand Combos**: Detects brand + action keyword pairs (e.g. `paypal-security.com`, +30 pts).
   - **Punycode / IDN Homographs**: Flags `xn--` internationalized domain spoofing (+25 pts).
   - **Excessive Subdomain Trees & Hyphen Stuffing**: Flags complex domain masking kits (+15 pts).
   - **High-Abuse Disposable TLDs**: Flags cheap spam/phishing domains (+10 pts).
   - **Unencrypted Transport (HTTP)**: Calibrated weak signal (+10 pts).

5. **Multi-Factor Explainable Scoring (0–100)**:
   - Evaluates Transport Encryption (HTTPS), Global Domain Authority (Top-Tier Verified Registry), TLD Reputation, Shannon Entropy / DGA patterns, and Brand Authenticity.
   - Bounded monotonic scoring (Safety Score: 5–99, Risk Index: 1–95%).
   - Itemized telemetry chips and positive trust signals for complete transparency.

6. **Signal Verification Inventory (Transparent Audit)**:
   - Distinguishes clearly between **Checks Completed** and **Checks Unavailable** (e.g. offline reputation checks, internal pages) so users always know the exact evidentiary basis of a scan.

7. **Website DNA Baseline & Change Detection**:
   - Tracks infrastructure profiles per domain (first seen, observation count, baseline protocol, baseline risk).
   - Alerts users if a previously encrypted site unexpectedly downgrades to HTTP or alters its security profile.

8. **Client-Side Password Security Tools (Web Crypto API)**:
   - Generates cryptographically secure passwords locally (never transmitted over any network).
   - Custom length slider (10–32 characters), symbols & numbers toggles, one-click copy.
   - Local Shannon entropy and password strength analyzer.

9. **International Phone Number Validator (E.164)**:
   - Validates international phone formatting, VoIP patterns, and premium-rate prefixes.

10. **Optional Threat Intelligence Integration**:
    - Supports Google Safe Browsing v4 via user-configured API key to supplement local heuristics with Google's cloud phishing & malware threat feeds.

---

## 2. File Structure

All files execute directly from the project directory without any compilation or build steps:

```
DefenceHub/
├── manifest.json                  # Manifest V3 extension configuration & permissions
├── popup.html                     # Semantic popup UI with 5 tabs, drawer & report modal
├── popup.css                      # Professional dark navy design system & animations
├── popup.js                       # Controller handling tabs, storage, TTS, DNA, and UI
├── engine.js                      # Core deterministic heuristics, scoring & TTS generator
├── background.js                  # Service worker: Tab navigation, badge, TTS & Safe Browsing
├── content.js                     # Content script: Live DOM inspection & floating in-page banner
├── icons/                         # Extension icon assets
│   ├── icon16.png                 # 16x16 toolbar icon
│   ├── icon48.png                 # 48x48 extensions management icon
│   └── icon128.png                # 128x128 high-resolution Chrome Web Store icon
├── test_engine.js                 # Unit test suite covering all 11 heuristic rules (20 tests)
├── test_extension_flow.js         # Integration workflow & storage persistence test (6 tests)
├── test_hardened_engine.js        # Hardened 20-scenario audit suite (20 tests)
├── test_harness.js                # Labeled benchmark harness & accuracy metrics (17 tests)
├── test_voice_and_auto_detection.js# Automatic navigation, voice TTS & failover test (9 tests)
├── make_icons.ps1                 # Asset generation script
└── README.md                      # Complete documentation and hackathon submission guide
```

---

## 3. How to Load DefenceHub in Google Chrome

1. Open **Google Chrome** (or any Chromium browser: Brave, Edge, Opera, Vivaldi).
2. Navigate to `chrome://extensions` in the address bar.
3. In the top-right corner, toggle **Developer mode** to **ON**.
4. In the top-left corner, click **Load unpacked**.
5. Select this project directory (`Ampics Hackathon`).
6. **DefenceHub** will appear in your extension list with version `1.1.0`.
7. Click the **Extensions puzzle icon** (`🧩`) in your Chrome toolbar and pin **DefenceHub** for convenient access.

---

## 4. Feature Walkthrough & Hackathon Demo Guide

### Demo Scenario A: Automatic Tab Navigation & Voice Companion
1. Navigate to `https://www.google.com` or `https://github.com`.
2. Notice the toolbar badge changes to **`✓` (Green)**.
3. The Voice Companion speaks a concise, reassuring safety report.
4. An in-page trust badge floats unobtrusively in the corner of the webpage.
5. Click the extension icon to view the **Safety Score (95–98/100)**, verified authority chips, and security advice.

### Demo Scenario B: Built-in Custom URL Tester (No fake sites needed!)
1. Open the DefenceHub popup.
2. Click the **Edit icon (`✏️`)** in the top right to open the **"Simulate & Test Any URL"** drawer.
3. Select any quick preset benchmark chip:
   - **`paypa1.com (Lookalike)`**: Triggers typosquatting/leetspeak detection; score drops to High Risk (~35/100).
   - **`IP Hostname`** (`http://192.168.1.1/admin`): Flags raw IP address and unencrypted HTTP transport (~20/100).
   - **`SafeBrowsing Test`** (`http://testsafebrowsing.appspot.com/s/phishing.html`): High-risk phishing detection.
   - **`HTTP (Insecure)`** (`http://example.com/`): Demonstrates cautionary medium risk (~60/100).
   - **`Wikipedia (Safe)`**: Demonstrates clean, low-risk scan result (~95/100).
4. Click **Analyze** to inspect any arbitrary URL immediately.

### Demo Scenario C: Detailed Evidence Report Modal
1. From any scan result, click **"Detailed Evidence Report"**.
2. A transparent modal opens displaying:
   - **Observed Facts**: Raw cryptographic and structural facts.
   - **Inferences & Confidence**: Rule triggers, calibrated weights, and overall confidence score.
   - **Recommended Safe Next Steps**: Clear, actionable guidance.

### Demo Scenario D: Audio Controls & Mute Mode
1. In the Safety tab, click **Replay** to re-hear the voice briefing for the current page.
2. Click **Mute** to silence automatic announcements; state persists across browser sessions.

### Demo Scenario E: Website DNA Profile
1. Switch to the **DNA** tab.
2. Inspect the stored baseline for the current domain (first seen date, scan observations, protocol baseline, baseline risk).
3. If an anomaly occurs on future visits, DefenceHub flags the shift in configuration.

### Demo Scenario F: Password Tools & Phone Validator
1. Switch to the **Pass** tab: Use the Web Crypto generator to generate secure passwords and test password entropy locally.
2. Switch to the **Phone** tab: Validate E.164 phone numbers with format and prefix breakdown.

### Demo Scenario G: Threat Intelligence Settings
1. Switch to the **Settings** tab.
2. Optionally enter a Google Safe Browsing v4 API key to activate cloud phishing lookups.
3. Review the strict privacy boundary: zero telemetry transmitted without user authorization.

---

## 5. Running the Automated Test Suites

DefenceHub includes 5 automated regression and benchmark test suites that can be run directly using Node.js:

```powershell
# 1. Run Unit Heuristics Tests (20 tests)
node test_engine.js

# 2. Run Integration Workflow & Storage Tests (6 tests)
node test_extension_flow.js

# 3. Run Hardened Engine 20-Scenario Audit Suite (20 tests)
node test_hardened_engine.js

# 4. Run Benchmark Test Harness & Accuracy Metrics (17 tests)
node test_harness.js

# 5. Run Voice Reporting & Automatic Navigation Tests (9 tests)
node test_voice_and_auto_detection.js
```

Or execute all 5 suites consecutively:
```powershell
node test_engine.js; node test_extension_flow.js; node test_hardened_engine.js; node test_harness.js; node test_voice_and_auto_detection.js
```

### Benchmark Accuracy & Validation Metrics

Validated through `test_harness.js` across labeled datasets:

| Metric | Result | Benchmark Standard |
| :--- | :---: | :--- |
| **Precision** | **100.0%** | Zero false-positive brand misclassifications |
| **Recall (Sensitivity)** | **100.0%** | All labeled phishing and lookalike cases caught |
| **False Positive Rate (FPR)** | **0.0%** | Legitimate services receive zero false blocks |
| **Overall Accuracy** | **100.0%** | 17/17 Benchmark scenarios accurately scored |
| **Score Monotonicity** | **Pass** | Independent threats strictly decrease safety score |
| **Score Bounds** | **Pass** | Safety bounded [5, 99], Risk bounded [1, 95] |

---

## 6. Security Heuristics Breakdown

| Heuristic Rule | Category | Weight | Description |
| :--- | :--- | :---: | :--- |
| `RULE_EXTERNAL_PASSWORD_ACTION` | Live DOM Content | +50 | Password input form submits to an untrusted external domain. |
| `RULE_INSECURE_HTTP_PASSWORD_ACTION` | Live DOM Content | +45 | Password input form submits over unencrypted HTTP. |
| `RULE_EMBEDDED_CREDENTIALS` | URL Structure | +40 | URL contains `user:pass@host` syntax to obscure destination. |
| `RULE_BRAND_IN_SUBDOMAIN` | Brand Impersonation | +40 | Known brand placed in subdomain on third-party root. |
| `RULE_IP_HOSTNAME` | Domain Structure | +35 | Direct raw IP address used instead of registered domain. |
| `RULE_BRAND_TYPOSQUATTING` | Brand Impersonation | +35 | Character substitutions (leetspeak) or Levenshtein distance = 1. |
| `RULE_BRAND_DECEPTIVE_COMBO` | Brand Impersonation | +30 | Brand concatenated with action keywords (`security`, `login`, `verify`). |
| `RULE_DECEPTIVE_LINK_DESTINATION` | Live DOM Content | +30 | Anchor text claims a recognized brand, but `href` targets unrelated host. |
| `RULE_PUNYCODE_HOST` | Domain Structure | +25 | Hostname uses `xn--` encoding (potential IDN homograph spoof). |
| `RULE_DECEPTIVE_URGENCY_TEXT` | Live DOM Content | +20 | Page body contains aggressive account suspension/urgency phrasing. |
| `RULE_EXCESSIVE_SUBDOMAINS` | Domain Structure | +15 | 3 or more subdomain levels used to conceal root domain. |
| `RULE_EXCESSIVE_HYPHENS` | Domain Structure | +15 | 3 or more hyphens commonly found in automated phishing kits. |
| `RULE_SENSITIVE_PATH_KEYWORDS` | URL Content | +15 | Path contains credential actions on unverified domain. |
| `RULE_HIGH_ABUSE_TLD` | Domain Reputation | +10 | TLD is overrepresented in disposable phishing campaigns. |
| `RULE_INSECURE_HTTP` | Transport Security | +10 | Weak signal: communication is unencrypted HTTP. |

---

## 7. How to Push to GitHub

To push the project to your GitHub repository:

```powershell
# 1. Initialize git repository (if not already initialized)
git init

# 2. Add all files
git add .

# 3. Create commit
git commit -m "DefenceHub v1.1.0: Complete browser security & voice companion extension"

# 4. Set branch to main
git branch -M main

# 5. Add remote URL (replace with your repo)
git remote add origin https://github.com/<your-username>/defencehub.git

# 6. Push code
git push -u origin main
```

---

## 8. License & Credits

Built for the **Ampics Hackathon 2026**. Licensed under the [MIT License](LICENSE).  
Engineered with an unwavering focus on user privacy, explainable cyber defence, and transparent safety reporting.

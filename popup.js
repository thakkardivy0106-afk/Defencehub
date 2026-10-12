/**
 * DefenceHub - Popup Controller
 * Manages UI interactions, active tab URL resolution, live DOM telemetry,
 * Website DNA baselines, Password Tools, Phone validation, and Chrome storage.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Navigation & Menu Elements
  const tabViews = {
    'tab-scan': document.getElementById('view-scan'),
    'tab-dna': document.getElementById('view-dna'),
    'tab-password': document.getElementById('view-password'),
    'tab-phone': document.getElementById('view-phone'),
    'tab-settings': document.getElementById('view-settings')
  };
  const menuBtn = document.getElementById('menu-btn');
  const menuPopover = document.getElementById('nav-menu-popover');
  const closeMenuPopoverBtn = document.getElementById('close-menu-popover-btn');
  const menuItems = document.querySelectorAll('.menu-item');
  const backNavButtons = document.querySelectorAll('.back-nav-btn');

  // Master-Key Encrypted Password Vault Elements
  const vaultStatusBadge = document.getElementById('vault-status-badge');
  const vaultLockedState = document.getElementById('vault-locked-state');
  const vaultUnlockedState = document.getElementById('vault-unlocked-state');
  const vaultMasterPassInput = document.getElementById('vault-master-pass-input');
  const vaultUnlockBtn = document.getElementById('vault-unlock-btn');
  const vaultLockBtn = document.getElementById('vault-lock-btn');
  const vaultAuthHint = document.getElementById('vault-auth-hint');
  const vaultEntryCount = document.getElementById('vault-entry-count');
  const vaultNewDomain = document.getElementById('vault-new-domain');
  const vaultNewUser = document.getElementById('vault-new-user');
  const vaultNewPass = document.getElementById('vault-new-pass');
  const vaultUseGenBtn = document.getElementById('vault-use-gen-btn');
  const vaultSaveEntryBtn = document.getElementById('vault-save-entry-btn');
  const vaultEmptyNotice = document.getElementById('vault-empty-notice');
  const vaultItemsList = document.getElementById('vault-items-list');

  const VAULT_STORAGE_KEY = 'defencehub_encrypted_vault';
  let vaultState = {
    unlocked: false,
    key: null,
    salt: null,
    credentials: []
  };

  // Scan & Overview Elements
  const tabHostnameEl = document.getElementById('tab-hostname');
  const tabProtocolBadgeEl = document.getElementById('tab-protocol-badge');
  const scanBtn = document.getElementById('scan-btn');
  const scanBtnText = document.getElementById('scan-btn-text');
  
  const unsupportedBanner = document.getElementById('unsupported-banner');
  const errorBanner = document.getElementById('error-banner');
  const errorMessageEl = document.getElementById('error-message');
  
  const loadingState = document.getElementById('loading-state');
  const resultsSection = document.getElementById('results-section');
  
  const scoreNumberEl = document.getElementById('score-number');
  const scoreMeterFillEl = document.getElementById('score-meter-fill');
  const riskLevelBadgeEl = document.getElementById('risk-level-badge');
  const scoreSummaryEl = document.getElementById('score-summary');
  const scoreScaleText = document.getElementById('score-scale-text');

  const telemetryProtocol = document.getElementById('telemetry-protocol');
  const telemetryAuthority = document.getElementById('telemetry-authority');
  const telemetryStructure = document.getElementById('telemetry-structure');
  const confidenceBadgeEl = document.getElementById('confidence-badge');
  const reputationBadgeEl = document.getElementById('reputation-badge');
  const coverageTextEl = document.getElementById('coverage-text');
  
  const findingsSectionTitle = document.getElementById('findings-section-title');
  const findingsCountEl = document.getElementById('findings-count');
  const noFindingsEl = document.getElementById('no-findings');
  const findingsListEl = document.getElementById('findings-list');
  const positiveSignalsList = document.getElementById('positive-signals-list');
  
  const coachListEl = document.getElementById('coach-list');
  
  const historyListEl = document.getElementById('history-list');
  const historyEmptyEl = document.getElementById('history-empty');
  const clearHistoryBtn = document.getElementById('clear-history-btn');
  
  const toggleCustomBtn = document.getElementById('toggle-custom-btn');
  const customDrawer = document.getElementById('custom-url-drawer');
  const closeDrawerBtn = document.getElementById('close-drawer-btn');
  const customUrlInput = document.getElementById('custom-url-input');
  const scanCustomBtn = document.getElementById('scan-custom-btn');
  const chipButtons = document.querySelectorAll('.chip');

  // Blueprint Action Buttons & Modal
  const viewReportBtn = document.getElementById('view-report-btn');
  const leaveSiteBtn = document.getElementById('leave-site-btn');
  const reportModal = document.getElementById('report-modal');
  const closeReportBtn = document.getElementById('close-report-btn');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const reportFactsBox = document.getElementById('report-facts-box');
  const reportInferencesBox = document.getElementById('report-inferences-box');
  const reportActionsBox = document.getElementById('report-actions-box');

  // Website DNA Elements
  const dnaDomainBadge = document.getElementById('dna-domain-badge');
  const dnaStatusBox = document.getElementById('dna-status-box');
  const dnaStatusTitle = document.getElementById('dna-status-title');
  const dnaStatusDesc = document.getElementById('dna-status-desc');
  const dnaFirstSeen = document.getElementById('dna-first-seen');
  const dnaVisitCount = document.getElementById('dna-visit-count');
  const dnaProtocolBase = document.getElementById('dna-protocol-base');
  const dnaRiskBase = document.getElementById('dna-risk-base');
  const forgetDnaBtn = document.getElementById('forget-dna-btn');

  // Password Tools Elements
  const genPassOutput = document.getElementById('gen-password-output');
  const copyPassBtn = document.getElementById('copy-pass-btn');
  const passLenSlider = document.getElementById('pass-len-slider');
  const passLenVal = document.getElementById('pass-len-val');
  const passOptSymbols = document.getElementById('pass-opt-symbols');
  const passOptNumbers = document.getElementById('pass-opt-numbers');
  const generatePassBtn = document.getElementById('generate-pass-btn');
  const checkPassInput = document.getElementById('check-password-input');
  const passStrengthMeter = document.getElementById('pass-strength-meter');
  const passStrengthLabel = document.getElementById('pass-strength-label');

  // Phone Checker Elements
  const phoneInput = document.getElementById('phone-input');
  const checkPhoneBtn = document.getElementById('check-phone-btn');
  const phoneResultCard = document.getElementById('phone-result-card');
  const phoneFormatStatus = document.getElementById('phone-format-status');
  const phoneDetails = document.getElementById('phone-details');

  // Settings Elements
  const clearAllDataBtn = document.getElementById('clear-all-data-btn');

  // Voice Controls & Analysis Status Elements
  const voiceIndicatorDot = document.getElementById('voice-indicator-dot');
  const voiceStatusText = document.getElementById('voice-status-text');
  const voiceReplayBtn = document.getElementById('voice-replay-btn');
  const voiceMuteBtn = document.getElementById('voice-mute-btn');
  const voiceMuteIcon = document.getElementById('voice-mute-icon');
  const voiceMuteText = document.getElementById('voice-mute-text');
  const lastAnalyzedTimeEl = document.getElementById('last-analyzed-time');
  const analysisStatusBadge = document.getElementById('analysis-status-badge');

  // Checks Inventory Elements
  const checksCompletedList = document.getElementById('checks-completed-list');
  const checksUnavailableList = document.getElementById('checks-unavailable-list');
  const checksRatioBadge = document.getElementById('checks-ratio-badge');

  // Settings API Key Elements
  const apiKeyInput = document.getElementById('api-key-input');
  const saveApiKeyBtn = document.getElementById('save-api-key-btn');
  const apiKeyStatus = document.getElementById('api-key-status');

  let currentActiveUrl = '';
  let currentActiveTab = null;
  let latestAnalysisResult = null;
  const HISTORY_KEY = 'defencehub_scan_history';
  const DNA_KEY = 'defencehub_dna_profiles';
  const MAX_HISTORY = 10;

  // ----------------------------------------------------
  // Storage Helper
  // ----------------------------------------------------
  const storage = {
    get: function (key, callback) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get([key], (res) => callback(res[key]));
      } else {
        try {
          const raw = localStorage.getItem(key);
          callback(raw ? JSON.parse(raw) : null);
        } catch (e) {
          callback(null);
        }
      }
    },
    set: function (key, val, callback) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.set({ [key]: val }, () => { if (callback) callback(); });
      } else {
        try {
          localStorage.setItem(key, JSON.stringify(val));
        } catch (e) {}
        if (callback) callback();
      }
    },
    remove: function (key, callback) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.remove([key], () => { if (callback) callback(); });
      } else {
        try { localStorage.removeItem(key); } catch (e) {}
        if (callback) callback();
      }
    }
  };

  // ----------------------------------------------------
  // Unified Menu Navigation & Popover Handling
  // ----------------------------------------------------
  function switchView(targetId) {
    if (!tabViews[targetId]) return;

    // 1. Update menu item selection states
    const items = document.querySelectorAll('.menu-item');
    items.forEach(item => {
      if (item.getAttribute('data-tab') === targetId) {
        item.classList.add('active');
        item.setAttribute('aria-selected', 'true');
      } else {
        item.classList.remove('active');
        item.setAttribute('aria-selected', 'false');
      }
    });

    // 2. Toggle active tab views
    Object.keys(tabViews).forEach(id => {
      if (tabViews[id]) {
        if (id === targetId) {
          tabViews[id].classList.remove('hidden');
        } else {
          tabViews[id].classList.add('hidden');
        }
      }
    });

    // 3. Close popover after navigation
    closeMenuPopover();

    // 4. Trigger view-specific data refresh
    if (targetId === 'tab-dna' && latestAnalysisResult) {
      renderWebsiteDna(latestAnalysisResult.hostname);
    }
  }

  function openMenuPopover() {
    if (menuPopover) {
      menuPopover.classList.remove('hidden');
      if (menuBtn) menuBtn.setAttribute('aria-expanded', 'true');
      const activeItem = menuPopover.querySelector('.menu-item.active') || menuPopover.querySelector('.menu-item');
      if (activeItem) activeItem.focus();
    }
  }

  function closeMenuPopover() {
    if (menuPopover) {
      menuPopover.classList.add('hidden');
      if (menuBtn) menuBtn.setAttribute('aria-expanded', 'false');
    }
  }

  if (menuBtn) {
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (menuPopover && menuPopover.classList.contains('hidden')) {
        openMenuPopover();
      } else {
        closeMenuPopover();
      }
    });
  }

  if (closeMenuPopoverBtn) {
    closeMenuPopoverBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      closeMenuPopover();
    });
  }

  menuItems.forEach(item => {
    item.addEventListener('click', () => {
      const target = item.getAttribute('data-tab');
      if (target) switchView(target);
    });
  });

  backNavButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.getAttribute('data-tab') || 'tab-scan';
      switchView(target);
    });
  });

  // Close menu popover when clicking outside
  document.addEventListener('click', (e) => {
    if (menuPopover && !menuPopover.classList.contains('hidden')) {
      if (!menuPopover.contains(e.target) && e.target !== menuBtn && !menuBtn?.contains(e.target)) {
        closeMenuPopover();
      }
    }
  });

  // Keyboard navigation for Menu Popover (Escape to close, Arrow keys to traverse)
  document.addEventListener('keydown', (e) => {
    if (menuPopover && !menuPopover.classList.contains('hidden')) {
      if (e.key === 'Escape') {
        closeMenuPopover();
        if (menuBtn) menuBtn.focus();
      } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const items = Array.from(menuPopover.querySelectorAll('.menu-item'));
        const currentIndex = items.indexOf(document.activeElement);
        if (e.key === 'ArrowDown') {
          const nextIndex = (currentIndex + 1) % items.length;
          items[nextIndex].focus();
        } else {
          const prevIndex = (currentIndex - 1 + items.length) % items.length;
          items[prevIndex].focus();
        }
      }
    }
  });

  // ----------------------------------------------------
  // Active Tab & DOM Query
  // ----------------------------------------------------
  function queryActiveTab(callback) {
    if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) {
      callback(null);
      return;
    }

    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
      if (tabs && tabs.length > 0 && (tabs[0].url || tabs[0].pendingUrl)) {
        callback(tabs[0]);
        return;
      }

      chrome.tabs.query({ active: true, currentWindow: true }, (tabs2) => {
        if (tabs2 && tabs2.length > 0 && (tabs2[0].url || tabs2[0].pendingUrl)) {
          callback(tabs2[0]);
          return;
        }

        chrome.tabs.query({ active: true }, (tabs3) => {
          if (tabs3 && tabs3.length > 0 && (tabs3[0].url || tabs3[0].pendingUrl)) {
            callback(tabs3[0]);
            return;
          }
          callback(null);
        });
      });
    });
  }

  function inspectPageDom(tab, callback) {
    if (typeof chrome === 'undefined' || !chrome.scripting || !tab || !tab.id) {
      callback(null);
      return;
    }

    const tabUrl = tab.url || tab.pendingUrl || '';
    if (!tabUrl.startsWith('http://') && !tabUrl.startsWith('https://')) {
      callback(null);
      return;
    }

    try {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          try {
            const passwordInputs = document.querySelectorAll('input[type="password"]');
            const forms = Array.from(document.forms).map(f => {
              let actionUrl = '';
              try {
                actionUrl = f.action ? new URL(f.action, window.location.href).href : '';
              } catch (e) {}
              return {
                action: actionUrl,
                method: (f.method || 'GET').toUpperCase(),
                hasPassword: !!f.querySelector('input[type="password"]')
              };
            });
            return {
              title: document.title || '',
              hasPassword: passwordInputs.length > 0,
              passwordCount: passwordInputs.length,
              forms: forms,
              isHttps: window.location.protocol === 'https:',
              iframeCount: document.querySelectorAll('iframe').length
            };
          } catch (e) {
            return null;
          }
        }
      }, (results) => {
        if (chrome.runtime.lastError || !results || !results[0] || !results[0].result) {
          callback(null);
        } else {
          callback(results[0].result);
        }
      });
    } catch (e) {
      callback(null);
    }
  }

  function initActiveTab() {
    queryActiveTab((tab) => {
      if (tab && (tab.url || tab.pendingUrl)) {
        currentActiveTab = tab;
        const targetUrl = tab.url || tab.pendingUrl;
        handleTabUrl(targetUrl, tab);
      } else {
        const previewUrl = window.location.href.startsWith('http') && !window.location.href.includes('popup.html')
          ? window.location.href
          : 'https://www.google.com';
        handleTabUrl(previewUrl, null);
      }
    });
  }

  function handleTabUrl(urlString, tab) {
    currentActiveUrl = urlString;
    currentActiveTab = tab;

    const lower = urlString.toLowerCase();
    if (
      lower.startsWith('chrome://') ||
      lower.startsWith('chrome-extension://') ||
      lower.startsWith('edge://') ||
      lower.startsWith('about:') ||
      lower.startsWith('view-source:') ||
      lower.startsWith('devtools:')
    ) {
      showUnsupported(`System Page: "${urlString.split('/')[2] || 'browser'}" cannot be scanned.`);
      return;
    }

    try {
      const parsed = new URL(urlString);
      tabHostnameEl.textContent = parsed.hostname;
      tabHostnameEl.title = parsed.hostname;

      if (parsed.protocol === 'http:') {
        tabProtocolBadgeEl.textContent = 'HTTP';
        tabProtocolBadgeEl.className = 'badge badge-risk badge-med';
      } else {
        tabProtocolBadgeEl.textContent = 'HTTPS';
        tabProtocolBadgeEl.className = 'badge badge-protocol';
      }

      unsupportedBanner.classList.add('hidden');
      scanBtn.disabled = false;

      // Check if background service worker already completed auto-scan
      if (tab && tab.id && typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'GET_TAB_SCAN', tabId: tab.id }, (resp) => {
          if (resp && resp.scan && resp.scan.url === urlString) {
            latestAnalysisResult = resp.scan;
            loadingState.classList.add('hidden');
            resultsSection.classList.remove('hidden');
            renderResults(resp.scan);
            saveScanToHistory(resp.scan);
            updateWebsiteDna(resp.scan);
            return;
          }
          performScan(urlString, tab);
        });
      } else {
        performScan(urlString, tab);
      }
    } catch (e) {
      showUnsupported('Invalid or unparseable URL in current tab.');
    }
  }

  function showUnsupported(msg) {
    tabHostnameEl.textContent = 'Unsupported Page';
    tabProtocolBadgeEl.textContent = 'SYS';
    tabProtocolBadgeEl.className = 'badge badge-inconclusive';
    scanBtn.disabled = true;
    unsupportedBanner.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    if (msg) {
      document.getElementById('unsupported-message').textContent = msg;
    }
  }

  function showError(msg) {
    errorMessageEl.textContent = msg;
    errorBanner.classList.remove('hidden');
  }

  function hideError() {
    errorBanner.classList.add('hidden');
  }

  // ----------------------------------------------------
  // Scan Execution
  // ----------------------------------------------------
  function performScan(urlString, tab) {
    hideError();

    loadingState.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    scanBtn.disabled = true;
    scanBtnText.textContent = 'Scanning...';

    inspectPageDom(tab, (pageData) => {
      setTimeout(() => {
        try {
          const result = DefenceHubEngine.analyzeUrl(urlString, pageData);

          if (!result.valid) {
            loadingState.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtnText.textContent = 'Refresh & Scan Website';
            showError(result.error || 'Failed to analyze URL.');
            return;
          }

          latestAnalysisResult = result;
          renderResults(result);
          saveScanToHistory(result);
          updateWebsiteDna(result);
        } catch (err) {
          showError(`Scan error: ${err.message}`);
        } finally {
          loadingState.classList.add('hidden');
          resultsSection.classList.remove('hidden');
          scanBtn.disabled = false;
          scanBtnText.textContent = 'Refresh & Scan Website';
        }
      }, 100);
    });
  }

  // ----------------------------------------------------
  // Render Scan Results into DOM
  // ----------------------------------------------------
  function renderResults(result) {
    scoreNumberEl.textContent = result.score;
    scoreMeterFillEl.style.width = `${result.score}%`;
    scoreMeterFillEl.style.backgroundColor = result.riskColor;

    riskLevelBadgeEl.textContent = result.riskLabel;
    riskLevelBadgeEl.className = 'badge badge-risk';
    if (result.riskLevel === 'LOW') {
      riskLevelBadgeEl.classList.add('badge-low');
    } else if (result.riskLevel === 'MEDIUM') {
      riskLevelBadgeEl.classList.add('badge-med');
    } else {
      riskLevelBadgeEl.classList.add('badge-high');
    }

    if (scoreScaleText) {
      scoreScaleText.textContent = `Safety Score • ${result.riskScore}% Risk Index`;
    }

    // Telemetry Badges
    if (telemetryProtocol) {
      if (result.protocol === 'https:') {
        telemetryProtocol.textContent = '✓ HTTPS Encrypted';
        telemetryProtocol.className = 'telemetry-chip chip-secure';
      } else {
        telemetryProtocol.textContent = '⚠ HTTP Insecure';
        telemetryProtocol.className = 'telemetry-chip chip-danger';
      }
    }

    if (telemetryAuthority) {
      if (result.telemetry && result.telemetry.isTopAuthority) {
        telemetryAuthority.textContent = '✓ Verified Authority';
        telemetryAuthority.className = 'telemetry-chip chip-secure';
      } else if (result.telemetry && result.telemetry.isGov) {
        telemetryAuthority.textContent = '✓ Official Gov Domain';
        telemetryAuthority.className = 'telemetry-chip chip-secure';
      } else if (result.telemetry && result.telemetry.isEdu) {
        telemetryAuthority.textContent = '✓ Accredited Academic';
        telemetryAuthority.className = 'telemetry-chip chip-secure';
      } else if (result.riskLevel === 'HIGH') {
        telemetryAuthority.textContent = '⚠ Deceptive Threat';
        telemetryAuthority.className = 'telemetry-chip chip-danger';
      } else {
        telemetryAuthority.textContent = `• .${result.telemetry ? result.telemetry.tld : 'domain'}`;
        telemetryAuthority.className = 'telemetry-chip';
      }
    }

    if (telemetryStructure) {
      if (result.findings.some(f => f.category === 'Domain Structure')) {
        telemetryStructure.textContent = '⚠ Structural Anomaly';
        telemetryStructure.className = 'telemetry-chip chip-warning';
      } else if (result.telemetry && result.telemetry.domAvailable === false) {
        telemetryStructure.textContent = '• URL-Only (DOM Inaccessible)';
        telemetryStructure.className = 'telemetry-chip';
      } else {
        telemetryStructure.textContent = '✓ Clean Domain';
        telemetryStructure.className = 'telemetry-chip chip-secure';
      }
    }

    // Evidence & Confidence Model Badges
    if (confidenceBadgeEl) {
      confidenceBadgeEl.textContent = `${result.confidence || 'MODERATE'} CONFIDENCE`;
      if (result.confidence === 'HIGH') {
        confidenceBadgeEl.style.background = '#1e3a5f';
        confidenceBadgeEl.style.color = '#93c5fd';
      } else if (result.confidence === 'LOW') {
        confidenceBadgeEl.style.background = '#451a03';
        confidenceBadgeEl.style.color = '#fdba74';
      } else {
        confidenceBadgeEl.style.background = '#27374d';
        confidenceBadgeEl.style.color = '#cbd5e1';
      }
    }

    if (reputationBadgeEl) {
      if (result.reputationStatus === 'CONFIRMED_THREAT') {
        reputationBadgeEl.textContent = 'Confirmed Threat';
        reputationBadgeEl.style.background = '#450a0a';
        reputationBadgeEl.style.color = '#fca5a5';
      } else if (result.reputationStatus === 'NO_KNOWN_MATCH') {
        reputationBadgeEl.textContent = 'No Known Match';
        reputationBadgeEl.style.background = '#064e3b';
        reputationBadgeEl.style.color = '#6ee7b7';
      } else if (result.reputationStatus === 'UNAVAILABLE') {
        reputationBadgeEl.textContent = 'Service Unavailable';
        reputationBadgeEl.style.background = '#374151';
        reputationBadgeEl.style.color = '#d1d5db';
      } else {
        reputationBadgeEl.textContent = 'Not Configured';
        reputationBadgeEl.style.background = '#27374d';
        reputationBadgeEl.style.color = '#cbd5e1';
      }
    }

    if (coverageTextEl && result.coverage) {
      coverageTextEl.textContent = result.coverage.summary || 'URL analysis completed';
    }

    scoreSummaryEl.textContent = result.summaryText;

    const threatCount = result.findings.length;
    const signalCount = result.positiveSignals ? result.positiveSignals.length : 0;

    if (threatCount > 0) {
      findingsSectionTitle.textContent = 'Detected Threat Patterns';
      findingsCountEl.textContent = `${threatCount} ${threatCount === 1 ? 'Threat' : 'Threats'}`;
      findingsCountEl.className = 'badge badge-risk badge-high';

      noFindingsEl.classList.add('hidden');
      if (positiveSignalsList) positiveSignalsList.classList.add('hidden');
      findingsListEl.classList.remove('hidden');

      findingsListEl.innerHTML = '';
      result.findings.forEach((finding) => {
        const item = document.createElement('div');
        item.className = 'finding-item';

        const topRow = document.createElement('div');
        topRow.className = 'finding-top-row';

        const title = document.createElement('span');
        title.className = 'finding-title';
        title.textContent = finding.title;

        const points = document.createElement('span');
        points.className = 'finding-points';
        points.textContent = `+${finding.points} pts risk`;

        topRow.appendChild(title);
        topRow.appendChild(points);

        const exp = document.createElement('p');
        exp.className = 'finding-explanation';
        exp.textContent = finding.explanation;

        item.appendChild(topRow);
        item.appendChild(exp);

        if (finding.target) {
          const targetEl = document.createElement('div');
          targetEl.className = 'finding-target';
          targetEl.textContent = `Target: ${finding.target}`;
          item.appendChild(targetEl);
        }

        findingsListEl.appendChild(item);
      });
    } else {
      findingsSectionTitle.textContent = 'Verified Security Signals';
      findingsCountEl.textContent = `${signalCount} Verified`;
      findingsCountEl.className = 'badge badge-risk badge-low';

      findingsListEl.classList.add('hidden');
      noFindingsEl.classList.add('hidden');

      if (positiveSignalsList) {
        positiveSignalsList.classList.remove('hidden');
        positiveSignalsList.innerHTML = '';

        if (result.positiveSignals && result.positiveSignals.length > 0) {
          result.positiveSignals.forEach((sig) => {
            const item = document.createElement('div');
            item.className = 'signal-item';

            const icon = document.createElement('span');
            icon.className = 'signal-icon';
            icon.textContent = '✓';

            const textDiv = document.createElement('div');
            textDiv.className = 'signal-text';

            const sigTitle = document.createElement('span');
            sigTitle.className = 'signal-title';
            sigTitle.textContent = sig.title;

            const sigDesc = document.createElement('span');
            sigDesc.className = 'signal-desc';
            sigDesc.textContent = sig.description;

            textDiv.appendChild(sigTitle);
            textDiv.appendChild(sigDesc);

            item.appendChild(icon);
            item.appendChild(textDiv);

            positiveSignalsList.appendChild(item);
          });
        } else {
          noFindingsEl.classList.remove('hidden');
        }
      } else {
        noFindingsEl.classList.remove('hidden');
      }
    }

    coachListEl.innerHTML = '';
    result.recommendations.forEach((rec) => {
      const li = document.createElement('li');
      li.textContent = rec;
      coachListEl.appendChild(li);
    });

    // Render Signal Verification Inventory (Checks Completed vs Unavailable)
    if (checksCompletedList && Array.isArray(result.checksCompleted)) {
      checksCompletedList.innerHTML = '';
      result.checksCompleted.forEach(c => {
        const row = document.createElement('div');
        row.className = 'check-item';

        const left = document.createElement('div');
        const name = document.createElement('span');
        name.className = 'check-name';
        name.textContent = c.name;
        const detail = document.createElement('span');
        detail.className = 'check-detail';
        detail.textContent = ` • ${c.detail}`;
        left.appendChild(name);
        left.appendChild(detail);

        const pill = document.createElement('span');
        pill.className = 'check-status-pill';
        if (c.status === 'SECURE' || c.status === 'PASS' || c.status === 'CLEAN') {
          pill.classList.add('check-pass');
          pill.textContent = c.status;
        } else if (c.status === 'WARN' || c.status === 'ANOMALY') {
          pill.classList.add('check-warn');
          pill.textContent = c.status;
        } else {
          pill.classList.add('check-fail');
          pill.textContent = c.status;
        }

        row.appendChild(left);
        row.appendChild(pill);
        checksCompletedList.appendChild(row);
      });
    }

    if (checksUnavailableList && Array.isArray(result.checksUnavailable)) {
      checksUnavailableList.innerHTML = '';
      result.checksUnavailable.forEach(c => {
        const row = document.createElement('div');
        row.className = 'check-item';

        const left = document.createElement('div');
        const name = document.createElement('span');
        name.className = 'check-name';
        name.textContent = c.name;
        const detail = document.createElement('span');
        detail.className = 'check-detail';
        detail.textContent = ` • ${c.reason}`;
        left.appendChild(name);
        left.appendChild(detail);

        const pill = document.createElement('span');
        pill.className = 'check-status-pill check-unavail';
        pill.textContent = 'UNAVAILABLE';

        row.appendChild(left);
        row.appendChild(pill);
        checksUnavailableList.appendChild(row);
      });
    }

    if (checksRatioBadge && result.checksCompleted && result.checksUnavailable) {
      checksRatioBadge.textContent = `${result.checksCompleted.length} Verified • ${result.checksUnavailable.length} Unavailable`;
    }

    if (lastAnalyzedTimeEl) {
      const timeStr = result.timestamp ? new Date(result.timestamp).toLocaleTimeString() : 'Just now';
      lastAnalyzedTimeEl.textContent = `Analyzed: ${timeStr} • Real-time telemetry`;
    }
  }

  // ----------------------------------------------------
  // Detailed Report Modal
  // ----------------------------------------------------
  function openDetailedReport() {
    if (!latestAnalysisResult) return;
    const res = latestAnalysisResult;

    // 1. Facts
    reportFactsBox.innerHTML = `
      <div>• <strong>Destination Hostname:</strong> ${res.hostname}</div>
      <div>• <strong>Protocol:</strong> ${res.protocol.toUpperCase()} ${res.protocol === 'https:' ? '(Encrypted SSL/TLS)' : '(Unencrypted cleartext)'}</div>
      <div>• <strong>Registrable Domain:</strong> ${res.registrableDomain || 'N/A'}</div>
      <div>• <strong>TLD Zone:</strong> .${res.telemetry ? res.telemetry.tld : 'com'}</div>
      <div>• <strong>Analysis Coverage:</strong> ${res.coverage ? res.coverage.summary : 'URL Analysis'}</div>
      <div>• <strong>Reputation Status:</strong> ${res.reputationStatus || 'NOT_CONFIGURED'}</div>
      <div>• <strong>Observed Threat Findings:</strong> ${res.findings.length} detected patterns</div>
      <div>• <strong>Verified Trust Signals:</strong> ${res.positiveSignals ? res.positiveSignals.length : 0} verified</div>
    `;

    // 2. Inferences
    const limitationsList = res.limitations && res.limitations.length > 0
      ? `<div style="margin-top:6px; color:#f59e0b;">• <em>Known Analysis Limitations:</em> ${res.limitations.join('; ')}</div>`
      : '';

    reportInferencesBox.innerHTML = `
      <div>• <strong>Assessed Risk Level:</strong> ${res.riskLabel} (${res.riskScore}% normalized risk index)</div>
      <div>• <strong>Confidence Rating:</strong> ${res.confidence || 'MODERATE'} confidence based on available layers</div>
      <div>• <strong>Safety Rating:</strong> ${res.score} / 100</div>
      <div>• <strong>Context:</strong> ${res.summaryText}</div>
      ${limitationsList}
      ${res.findings.map(f => `<div style="margin-top:4px;">• <em>[${f.severity || 'WARN'}] ${f.title}:</em> ${f.explanation}</div>`).join('')}
    `;

    // 3. Actions
    reportActionsBox.innerHTML = `
      <div>1. <strong>Verification:</strong> ${res.recommendations[0] || 'Verify domain in address bar.'}</div>
      <div>2. <strong>Credential Advice:</strong> ${res.riskLevel === 'HIGH' ? 'Do NOT enter passwords or credit card details on this site.' : 'Standard caution advised before entering sensitive credentials.'}</div>
      <div>3. <strong>Immediate Action:</strong> ${res.riskLevel === 'HIGH' ? 'Leave page or navigate to the official verified website directly.' : 'Continue browsing with normal security awareness.'}</div>
    `;

    reportModal.classList.remove('hidden');
  }

  viewReportBtn.addEventListener('click', openDetailedReport);
  closeReportBtn.addEventListener('click', () => reportModal.classList.add('hidden'));
  modalCloseBtn.addEventListener('click', () => reportModal.classList.add('hidden'));

  // Leave Site Action (Blueprint Wireframe)
  leaveSiteBtn.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.tabs && currentActiveTab && currentActiveTab.id) {
      chrome.tabs.update(currentActiveTab.id, { url: 'https://www.google.com' });
      window.close();
    } else {
      window.location.href = 'https://www.google.com';
    }
  });

  // ----------------------------------------------------
  // Website DNA (Baseline & Change Tracking)
  // ----------------------------------------------------
  function updateWebsiteDna(result) {
    if (!result || !result.hostname) return;
    const domain = result.hostname;

    storage.get(DNA_KEY, (profiles) => {
      const data = profiles || {};
      const existing = data[domain];

      if (!existing) {
        data[domain] = {
          firstSeen: new Date().toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' }),
          visitCount: 1,
          protocol: result.protocol,
          riskLevel: result.riskLevel
        };
      } else {
        existing.visitCount = (existing.visitCount || 1) + 1;
        existing.lastVisit = new Date().toLocaleDateString();
      }

      storage.set(DNA_KEY, data, () => {
        renderWebsiteDna(domain);
      });
    });
  }

  function renderWebsiteDna(domain) {
    if (!domain) return;
    dnaDomainBadge.textContent = domain;

    storage.get(DNA_KEY, (profiles) => {
      const data = profiles || {};
      const profile = data[domain];

      if (!profile) {
        dnaFirstSeen.textContent = 'Today';
        dnaVisitCount.textContent = '1 scan';
        dnaProtocolBase.textContent = latestAnalysisResult ? latestAnalysisResult.protocol.toUpperCase() : 'HTTPS';
        dnaRiskBase.textContent = latestAnalysisResult ? latestAnalysisResult.riskLabel : 'Low';
        dnaStatusBox.className = 'dna-status-banner dna-match';
        dnaStatusTitle.textContent = 'Baseline Established Today';
        dnaStatusDesc.textContent = 'Initial security fingerprint saved for this domain.';
        return;
      }

      dnaFirstSeen.textContent = profile.firstSeen || 'Today';
      dnaVisitCount.textContent = `${profile.visitCount} ${profile.visitCount === 1 ? 'visit' : 'visits'}`;
      dnaProtocolBase.textContent = (profile.protocol || 'https:').toUpperCase();
      dnaRiskBase.textContent = profile.riskLevel || 'Low';

      // Change Detection check
      if (latestAnalysisResult && latestAnalysisResult.protocol !== profile.protocol) {
        dnaStatusBox.className = 'dna-status-banner dna-changed';
        dnaStatusTitle.textContent = '⚠️ Protocol Shift Detected';
        dnaStatusDesc.textContent = `Security degraded from baseline ${profile.protocol.toUpperCase()} to ${latestAnalysisResult.protocol.toUpperCase()}.`;
      } else {
        dnaStatusBox.className = 'dna-status-banner dna-match';
        dnaStatusTitle.textContent = '✓ Matches Security Baseline';
        dnaStatusDesc.textContent = `No suspicious infrastructure drift observed across ${profile.visitCount} visits.`;
      }
    });
  }

  forgetDnaBtn.addEventListener('click', () => {
    if (!latestAnalysisResult || !latestAnalysisResult.hostname) return;
    const domain = latestAnalysisResult.hostname;
    storage.get(DNA_KEY, (profiles) => {
      const data = profiles || {};
      delete data[domain];
      storage.set(DNA_KEY, data, () => {
        renderWebsiteDna(domain);
      });
    });
  });

  // ----------------------------------------------------
  // Password Tools (Web Crypto API - 100% Client-Side)
  // ----------------------------------------------------
  function generateSecurePassword() {
    const len = parseInt(passLenSlider.value, 10);
    const useSymbols = passOptSymbols.checked;
    const useNumbers = passOptNumbers.checked;

    let charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useNumbers) charset += '0123456789';
    if (useSymbols) charset += '!@#$%^&*()-_=+[]{}|;:,.<>?';

    const randomValues = new Uint32Array(len);
    window.crypto.getRandomValues(randomValues);

    let password = '';
    for (let i = 0; i < len; i++) {
      password += charset[randomValues[i] % charset.length];
    }

    genPassOutput.value = password;
  }

  passLenSlider.addEventListener('input', () => {
    passLenVal.textContent = passLenSlider.value;
    generateSecurePassword();
  });

  generatePassBtn.addEventListener('click', generateSecurePassword);

  copyPassBtn.addEventListener('click', () => {
    if (!genPassOutput.value) return;
    navigator.clipboard.writeText(genPassOutput.value).then(() => {
      copyPassBtn.textContent = 'Copied!';
      setTimeout(() => { copyPassBtn.textContent = 'Copy'; }, 1500);
    });
  });

  checkPassInput.addEventListener('input', () => {
    const pwd = checkPassInput.value;
    if (!pwd) {
      passStrengthMeter.style.width = '0%';
      passStrengthLabel.textContent = 'Enter password above';
      return;
    }

    let score = 0;
    if (pwd.length >= 8) score += 25;
    if (pwd.length >= 14) score += 25;
    if (/[A-Z]/.test(pwd) && /[a-z]/.test(pwd)) score += 20;
    if (/\d/.test(pwd)) score += 15;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 15;

    passStrengthMeter.style.width = `${score}%`;
    if (score < 40) {
      passStrengthMeter.style.backgroundColor = 'var(--danger)';
      passStrengthLabel.textContent = 'Weak: Vulnerable to simple dictionary guessing';
    } else if (score < 75) {
      passStrengthMeter.style.backgroundColor = 'var(--suspicious)';
      passStrengthLabel.textContent = 'Moderate: Consider adding length or special symbols';
    } else {
      passStrengthMeter.style.backgroundColor = 'var(--low-risk)';
      passStrengthLabel.textContent = 'Strong: Robust resistance against brute-force';
    }
  });

  // ----------------------------------------------------
  // Master-Key Protected Password Vault (Web Crypto API)
  // Zero-Knowledge PBKDF2 (100,000 rounds) + AES-GCM 256
  // ----------------------------------------------------
  function bufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBuffer(b64) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  async function deriveMasterKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
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
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const plaintext = enc.encode(JSON.stringify(credentials));

    const ciphertext = await window.crypto.subtle.encrypt(
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

    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      ciphertext
    );

    return JSON.parse(dec.decode(decrypted));
  }

  function renderVaultEntries() {
    if (!vaultItemsList || !vaultEntryCount || !vaultEmptyNotice) return;

    vaultEntryCount.textContent = `${vaultState.credentials.length} ${vaultState.credentials.length === 1 ? 'Credential' : 'Credentials'} Stored`;

    if (vaultState.credentials.length === 0) {
      vaultEmptyNotice.classList.remove('hidden');
      vaultItemsList.classList.add('hidden');
      vaultItemsList.innerHTML = '';
      return;
    }

    vaultEmptyNotice.classList.add('hidden');
    vaultItemsList.classList.remove('hidden');
    vaultItemsList.innerHTML = '';

    vaultState.credentials.forEach((entry, idx) => {
      const row = document.createElement('li');
      row.className = 'vault-item-row';

      const info = document.createElement('div');
      info.className = 'vault-item-info';

      const domSpan = document.createElement('span');
      domSpan.className = 'vault-item-domain';
      domSpan.textContent = entry.domain;

      const userSpan = document.createElement('span');
      userSpan.className = 'vault-item-user';
      userSpan.textContent = `${entry.user || 'No username'} • ••••••••`;

      info.appendChild(domSpan);
      info.appendChild(userSpan);

      const actions = document.createElement('div');
      actions.className = 'vault-item-actions';

      const copyBtn = document.createElement('button');
      copyBtn.className = 'btn btn-sm btn-secondary';
      copyBtn.textContent = 'Copy';
      copyBtn.title = 'Copy password to clipboard';
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(entry.pass).then(() => {
          copyBtn.textContent = 'Copied!';
          setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
        });
      });

      const delBtn = document.createElement('button');
      delBtn.className = 'btn btn-sm btn-secondary danger-link';
      delBtn.textContent = '✕';
      delBtn.title = 'Delete credential';
      delBtn.addEventListener('click', async () => {
        vaultState.credentials.splice(idx, 1);
        const encrypted = await encryptVault(vaultState.credentials, vaultState.key, vaultState.salt);
        storage.set(VAULT_STORAGE_KEY, encrypted, () => {
          renderVaultEntries();
        });
      });

      actions.appendChild(copyBtn);
      actions.appendChild(delBtn);

      row.appendChild(info);
      row.appendChild(actions);

      vaultItemsList.appendChild(row);
    });
  }

  function renderUnlockedVault() {
    vaultLockedState.classList.add('hidden');
    vaultUnlockedState.classList.remove('hidden');
    vaultStatusBadge.textContent = 'Unlocked';
    vaultStatusBadge.className = 'badge badge-low';
    renderVaultEntries();
  }

  if (vaultUnlockBtn) {
    vaultUnlockBtn.addEventListener('click', async () => {
      const password = (vaultMasterPassInput.value || '').trim();
      if (!password || password.length < 4) {
        vaultAuthHint.textContent = 'Master password must be at least 4 characters.';
        vaultAuthHint.style.color = '#f87171';
        return;
      }

      storage.get(VAULT_STORAGE_KEY, async (record) => {
        try {
          if (!record || !record.ciphertext) {
            // First time initialization: generate salt, derive key, store empty record
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const key = await deriveMasterKey(password, salt);
            const initialRecord = await encryptVault([], key, salt);
            storage.set(VAULT_STORAGE_KEY, initialRecord, () => {
              vaultState.key = key;
              vaultState.salt = salt;
              vaultState.credentials = [];
              vaultState.unlocked = true;
              renderUnlockedVault();
            });
          } else {
            // Existing vault: derive key and decrypt
            const salt = base64ToBuffer(record.salt);
            const key = await deriveMasterKey(password, salt);
            const creds = await decryptVault(record, key);
            vaultState.key = key;
            vaultState.salt = salt;
            vaultState.credentials = creds;
            vaultState.unlocked = true;
            renderUnlockedVault();
          }
        } catch (err) {
          vaultAuthHint.textContent = 'Incorrect master password or corrupted vault record.';
          vaultAuthHint.style.color = '#f87171';
        }
      });
    });
  }

  if (vaultLockBtn) {
    vaultLockBtn.addEventListener('click', () => {
      vaultState.key = null;
      vaultState.salt = null;
      vaultState.credentials = [];
      vaultState.unlocked = false;
      vaultMasterPassInput.value = '';
      vaultLockedState.classList.remove('hidden');
      vaultUnlockedState.classList.add('hidden');
      vaultStatusBadge.textContent = 'Locked';
      vaultStatusBadge.className = 'badge badge-med';
      vaultAuthHint.textContent = 'Vault locked. Enter master password to access credentials.';
      vaultAuthHint.style.color = 'var(--text-secondary)';
    });
  }

  if (vaultUseGenBtn) {
    vaultUseGenBtn.addEventListener('click', () => {
      if (!genPassOutput.value) {
        generateSecurePassword();
      }
      if (vaultNewPass) {
        vaultNewPass.value = genPassOutput.value;
      }
    });
  }

  if (vaultSaveEntryBtn) {
    vaultSaveEntryBtn.addEventListener('click', async () => {
      const domain = (vaultNewDomain.value || '').trim();
      const user = (vaultNewUser.value || '').trim();
      const pass = vaultNewPass.value;

      if (!domain || !pass) {
        alert('Please provide at least a website/domain and a password.');
        return;
      }

      const newEntry = {
        domain: domain,
        user: user,
        pass: pass,
        timestamp: Date.now()
      };

      vaultState.credentials.unshift(newEntry);
      const encrypted = await encryptVault(vaultState.credentials, vaultState.key, vaultState.salt);
      storage.set(VAULT_STORAGE_KEY, encrypted, () => {
        vaultNewDomain.value = '';
        vaultNewUser.value = '';
        vaultNewPass.value = '';
        renderVaultEntries();
      });
    });
  }

  // ----------------------------------------------------
  // Phone Number Checker
  // ----------------------------------------------------
  checkPhoneBtn.addEventListener('click', () => {
    const raw = phoneInput.value.trim();
    if (!raw) return;

    // International E.164 pattern validation
    const cleanDigits = raw.replace(/[^\d+]/g, '');
    const isE164 = /^\+?[1-9]\d{7,14}$/.test(cleanDigits);

    phoneResultCard.classList.remove('hidden');
    if (isE164) {
      phoneFormatStatus.textContent = '✓ Format Valid (E.164 Compliant)';
      phoneFormatStatus.style.color = 'var(--low-risk)';
      phoneDetails.textContent = `Normalized: ${cleanDigits} • Length: ${cleanDigits.replace('+', '').length} digits. Valid international structure.`;
    } else {
      phoneFormatStatus.textContent = '⚠ Non-Standard Format';
      phoneFormatStatus.style.color = 'var(--suspicious)';
      phoneDetails.textContent = 'Number does not follow standard 8-15 digit international telephony format.';
    }
  });

  // ----------------------------------------------------
  // History Management
  // ----------------------------------------------------
  function saveScanToHistory(result) {
    storage.get(HISTORY_KEY, (history) => {
      const list = history || [];
      const filtered = list.filter((item) => item.hostname !== result.hostname);

      const entry = {
        hostname: result.hostname,
        url: result.url,
        score: result.score,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        riskLabel: result.riskLabel,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      filtered.unshift(entry);
      const updated = filtered.slice(0, MAX_HISTORY);

      storage.set(HISTORY_KEY, updated, () => {
        renderHistoryList(updated);
      });
    });
  }

  function loadHistory() {
    storage.get(HISTORY_KEY, (history) => {
      renderHistoryList(history || []);
    });
  }

  function renderHistoryList(history) {
    historyListEl.innerHTML = '';

    if (!history || history.length === 0) {
      historyEmptyEl.classList.remove('hidden');
      historyListEl.classList.add('hidden');
      return;
    }

    historyEmptyEl.classList.add('hidden');
    historyListEl.classList.remove('hidden');

    history.forEach((item) => {
      const li = document.createElement('li');
      li.className = 'history-item';
      li.title = `Click to re-scan ${item.hostname}`;

      const hostSpan = document.createElement('span');
      hostSpan.className = 'history-host';
      hostSpan.textContent = item.hostname;

      const rightDiv = document.createElement('div');
      rightDiv.className = 'history-right';

      const timeSpan = document.createElement('span');
      timeSpan.className = 'history-time';
      timeSpan.textContent = item.timestamp;

      const badgeSpan = document.createElement('span');
      badgeSpan.className = 'history-badge';
      badgeSpan.textContent = `${item.score}`;
      if (item.riskLevel === 'LOW') {
        badgeSpan.classList.add('badge-low');
      } else if (item.riskLevel === 'MEDIUM') {
        badgeSpan.classList.add('badge-med');
      } else {
        badgeSpan.classList.add('badge-high');
      }

      rightDiv.appendChild(timeSpan);
      rightDiv.appendChild(badgeSpan);

      li.appendChild(hostSpan);
      li.appendChild(rightDiv);

      li.addEventListener('click', () => {
        tabHostnameEl.textContent = item.hostname;
        performScan(item.url || `https://${item.hostname}`, null);
      });

      historyListEl.appendChild(li);
    });
  }

  function clearHistory() {
    storage.remove(HISTORY_KEY, () => {
      renderHistoryList([]);
    });
  }

  clearHistoryBtn.addEventListener('click', clearHistory);

  // Clear all data
  clearAllDataBtn.addEventListener('click', () => {
    storage.remove(HISTORY_KEY, () => {
      storage.remove(DNA_KEY, () => {
        renderHistoryList([]);
        if (latestAnalysisResult) renderWebsiteDna(latestAnalysisResult.hostname);
        clearAllDataBtn.textContent = 'Cleared!';
        setTimeout(() => { clearAllDataBtn.textContent = 'Clear All Data'; }, 1500);
      });
    });
  });

  // ----------------------------------------------------
  // Re-Analyze Active Website Execution (PART 6)
  // Bypasses stale cache, queries live DOM, protects against concurrent requests
  // ----------------------------------------------------
  let isReanalyzing = false;

  async function reanalyzeActiveWebsite() {
    if (isReanalyzing) {
      console.warn('[DefenceHub] Re-analysis already running. Duplicate request prevented.');
      return;
    }

    isReanalyzing = true;
    scanBtn.disabled = true;
    scanBtnText.textContent = 'Re-analyzing Active Website...';
    hideError();

    loadingState.classList.remove('hidden');
    resultsSection.classList.add('hidden');

    try {
      // 1. Query active tab directly
      const tab = await new Promise((resolve) => queryActiveTab(resolve));
      if (!tab || (!tab.url && !tab.pendingUrl)) {
        showError('No active browser tab found to re-analyze.');
        return;
      }

      const rawUrl = tab.url || tab.pendingUrl;
      const lower = rawUrl.toLowerCase().trim();

      if (
        lower.startsWith('chrome://') ||
        lower.startsWith('chrome-extension://') ||
        lower.startsWith('edge://') ||
        lower.startsWith('about:') ||
        lower.startsWith('view-source:') ||
        lower.startsWith('devtools:')
      ) {
        showUnsupported(`System Page: "${rawUrl.split('/')[2] || 'browser'}" cannot be scanned.`);
        return;
      }

      if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
        showError(`Unsupported protocol scheme: ${rawUrl}`);
        return;
      }

      currentActiveUrl = rawUrl;
      currentActiveTab = tab;
      const targetTabId = tab.id;
      const targetUrl = rawUrl;

      // Update hostname header immediately
      try {
        const parsed = new URL(rawUrl);
        tabHostnameEl.textContent = parsed.hostname;
        tabHostnameEl.title = parsed.hostname;
        if (parsed.protocol === 'http:') {
          tabProtocolBadgeEl.textContent = 'HTTP';
          tabProtocolBadgeEl.className = 'badge badge-risk badge-med';
        } else {
          tabProtocolBadgeEl.textContent = 'HTTPS';
          tabProtocolBadgeEl.className = 'badge badge-protocol';
        }
      } catch (e) {}

      // 2. Query live DOM telemetry from the active tab
      const pageDomData = await new Promise((resolve) => inspectPageDom(tab, resolve));

      // 3. Request fresh analysis from background worker (bypasses reputation cache)
      let freshResult = null;
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        freshResult = await new Promise((resolve) => {
          chrome.runtime.sendMessage({
            type: 'REANALYZE_TAB',
            tabId: targetTabId,
            url: targetUrl
          }, (resp) => {
            if (chrome.runtime.lastError || !resp || resp.status !== 'ok' || !resp.scan) {
              resolve(null);
            } else {
              resolve(resp.scan);
            }
          });
        });
      }

      // Fallback: If background service worker was inactive or unavailable, compute locally
      if (!freshResult) {
        freshResult = DefenceHubEngine.analyzeUrl(targetUrl, pageDomData);
      }

      // 4. Guard against tab/URL navigation during asynchronous analysis
      const currentTabNow = await new Promise((resolve) => queryActiveTab(resolve));
      if (currentTabNow && currentTabNow.id === targetTabId && (currentTabNow.url || currentTabNow.pendingUrl) !== targetUrl) {
        console.warn('[DefenceHub] Tab navigated during analysis. Discarding stale result.');
        return;
      }

      // 5. Render results & update state
      if (!freshResult || !freshResult.valid) {
        showError(freshResult && freshResult.error ? freshResult.error : 'Failed to re-analyze website.');
        return;
      }

      latestAnalysisResult = freshResult;
      renderResults(freshResult);
      saveScanToHistory(freshResult);
      updateWebsiteDna(freshResult);

    } catch (err) {
      showError(`Re-analysis error: ${err.message}`);
    } finally {
      isReanalyzing = false;
      loadingState.classList.add('hidden');
      if (latestAnalysisResult) {
        resultsSection.classList.remove('hidden');
      }
      scanBtn.disabled = false;
      scanBtnText.textContent = 'Re-analyze Active Website';
    }
  }

  scanBtn.addEventListener('click', reanalyzeActiveWebsite);

  toggleCustomBtn.addEventListener('click', () => {
    customDrawer.classList.toggle('hidden');
    if (!customDrawer.classList.contains('hidden')) {
      customUrlInput.focus();
    }
  });

  closeDrawerBtn.addEventListener('click', () => {
    customDrawer.classList.add('hidden');
  });

  scanCustomBtn.addEventListener('click', () => {
    const customUrl = customUrlInput.value.trim();
    if (!customUrl) return;

    let normalized = customUrl;
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'https://' + normalized;
    }

    try {
      const parsed = new URL(normalized);
      tabHostnameEl.textContent = parsed.hostname;
      tabHostnameEl.title = parsed.hostname;
      performScan(normalized, null);
      customDrawer.classList.add('hidden');
    } catch (e) {
      showError('Please enter a valid URL.');
    }
  });

  customUrlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') scanCustomBtn.click();
  });

  chipButtons.forEach((chip) => {
    chip.addEventListener('click', () => {
      const target = chip.getAttribute('data-test');
      if (target) {
        customUrlInput.value = target;
        scanCustomBtn.click();
      }
    });
  });

  // ----------------------------------------------------
  // Voice Controls & Settings Integration
  // ----------------------------------------------------
  function updateVoiceUi(isMuted) {
    if (voiceIndicatorDot) {
      voiceIndicatorDot.className = isMuted ? 'voice-indicator-dot muted' : 'voice-indicator-dot';
    }
    if (voiceStatusText) {
      voiceStatusText.textContent = isMuted
        ? 'Voice Muted • Click Unmute to hear automatic reports'
        : 'Voice Active • Automatic voice report on navigation';
    }
    if (voiceMuteIcon) voiceMuteIcon.textContent = isMuted ? '🔇' : '🔊';
    if (voiceMuteText) voiceMuteText.textContent = isMuted ? 'Unmute' : 'Mute';
  }

  function initVoiceAndSettings() {
    // 1. Fetch current status from background
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (resp) => {
        if (resp && resp.isMuted !== undefined) {
          updateVoiceUi(resp.isMuted);
        }
      });
    }

    // 2. Wire Replay Report Button
    if (voiceReplayBtn) {
      voiceReplayBtn.addEventListener('click', () => {
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({
            type: 'REPLAY_REPORT',
            tabId: currentActiveTab ? currentActiveTab.id : null
          }, () => {
            if (chrome.runtime.lastError) {}
          });
        }
      });
    }

    // 3. Wire Mute / Unmute Button
    if (voiceMuteBtn) {
      voiceMuteBtn.addEventListener('click', () => {
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'TOGGLE_MUTE' }, (resp) => {
            if (resp && resp.isMuted !== undefined) {
              updateVoiceUi(resp.isMuted);
            }
          });
        }
      });
    }

    // 4. Wire Safe Browsing API Key in Settings
    if (apiKeyInput && saveApiKeyBtn) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['defencehub_settings'], (res) => {
          if (res && res.defencehub_settings && res.defencehub_settings.apiKey) {
            apiKeyInput.value = res.defencehub_settings.apiKey;
            if (apiKeyStatus) apiKeyStatus.textContent = '✓ Google Safe Browsing API Key configured & active.';
          }
        });
      }

      saveApiKeyBtn.addEventListener('click', () => {
        const key = apiKeyInput.value.trim();
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'SET_API_KEY', apiKey: key }, () => {
            if (apiKeyStatus) {
              apiKeyStatus.textContent = key
                ? '✓ API Key saved! Re-evaluating current website...'
                : 'API Key cleared. Standard local heuristics active.';
            }
            setTimeout(() => {
              if (currentActiveUrl) performScan(currentActiveUrl, currentActiveTab);
            }, 600);
          });
        }
      });
    }

    // 4b. Wire Strict Credential Shield Toggle
    const strictShieldToggle = document.getElementById('strict-shield-toggle');
    if (strictShieldToggle) {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['defencehub_settings'], (res) => {
          if (res && res.defencehub_settings) {
            strictShieldToggle.checked = res.defencehub_settings.strictShieldEnabled !== false;
          }
        });
      }

      strictShieldToggle.addEventListener('change', () => {
        const enabled = strictShieldToggle.checked;
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'TOGGLE_STRICT_SHIELD', enabled }, () => {
            if (chrome.runtime.lastError) {}
          });
        }
      });
    }

    // 5. Listen for Tab Analysis updates pushed from background
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((message) => {
        if (message && message.type === 'TAB_ANALYSIS_UPDATED' && message.result) {
          if (currentActiveTab && message.tabId === currentActiveTab.id) {
            latestAnalysisResult = message.result;
            loadingState.classList.add('hidden');
            resultsSection.classList.remove('hidden');
            renderResults(message.result);
            saveScanToHistory(message.result);
            updateWebsiteDna(message.result);
          }
        }
      });
    }
  }

  // Initialize
  initVoiceAndSettings();
  initActiveTab();
  loadHistory();
  generateSecurePassword();
});

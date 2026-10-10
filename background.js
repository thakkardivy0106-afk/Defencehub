/**
 * DefenceHub - Background Service Worker (Manifest V3)
 * Automatic Website Detection, Threat Intelligence, and Voice Reporting Engine.
 */

// Import Core Security Engine
importScripts('engine.js');

// In-Memory state caches
const tabScanCache = new Map();
const lastAnalyzedUrlByTab = new Map();
const lastSpokenUrlByTab = new Map();
const activeScanIdByTab = new Map();
let currentActiveTabId = null;

// User preferences (persisted in chrome.storage.local)
let appSettings = {
  isDefenceHubOn: true,
  isMuted: false,
  apiKey: ''
};

// Reputation Cache (Domain -> { status, provider, threatType, timestamp })
const reputationCache = new Map();
const REPUTATION_TTL_MS = 60 * 60 * 1000; // 1 hour

// Badge Configurations
const BADGE_CONFIG = {
  CRITICAL: { text: '!', color: '#dc2626', title: 'Critical Phishing Risk' },
  HIGH: { text: '!', color: '#D92D3A', title: 'High Risk Website' },
  MEDIUM: { text: '⚠', color: '#ea580c', title: 'Medium Risk / Caution' },
  LOW: { text: '✓', color: '#16794B', title: 'Low Detected Risk' },
  UNKNOWN: { text: '?', color: '#64748B', title: 'Unknown / Insufficient Data' }
};

/**
 * Sync active tab on startup/service worker resume
 */
function syncActiveTab() {
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    try {
      chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
        if (chrome.runtime.lastError) return;
        if (tabs && tabs[0]) {
          currentActiveTabId = tabs[0].id;
        }
      });
    } catch (e) {}
  }
}
syncActiveTab();

/**
 * Initialize settings from chrome.storage.local to survive service worker restart
 */
function initSettings() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(['defencehub_settings', 'defencehub_tab_scans'], (res) => {
      if (chrome.runtime.lastError) return;
      if (res && res.defencehub_settings) {
        appSettings = Object.assign(appSettings, res.defencehub_settings);
      }
      if (res && res.defencehub_tab_scans) {
        try {
          Object.entries(res.defencehub_tab_scans).forEach(([tid, scan]) => {
            tabScanCache.set(Number(tid), scan);
          });
        } catch (e) {}
      }
    });
  }
}
initSettings();

/**
 * Persist active tab scans to storage for recovery after suspension
 */
function persistTabScans() {
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    const obj = {};
    tabScanCache.forEach((scan, tid) => {
      obj[tid] = scan;
    });
    chrome.storage.local.set({ defencehub_tab_scans: obj });
  }
}

/**
 * Safely broadcast runtime messages to extension UI (popups/pages)
 * Avoids uncaught errors when the popup is closed.
 */
function broadcastMessage(msg) {
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    try {
      chrome.runtime.sendMessage(msg, () => {
        if (chrome.runtime.lastError) {
          // Normal: No popup window is currently open to receive the broadcast
        }
      });
    } catch (e) {}
  }
}

/**
 * Updates action badge for a tab with error suppression for closed tabs
 */
function updateTabBadge(tabId, riskLevel, score) {
  if (!tabId || typeof chrome === 'undefined' || !chrome.action) return;

  const config = BADGE_CONFIG[riskLevel] || BADGE_CONFIG.UNKNOWN;
  try {
    chrome.action.setBadgeText({ tabId, text: config.text }, () => {
      if (chrome.runtime.lastError) {}
    });
    chrome.action.setBadgeBackgroundColor({ tabId, color: config.color }, () => {
      if (chrome.runtime.lastError) {}
    });
    chrome.action.setTitle({
      tabId,
      title: `DefenceHub: ${config.title} (Safety Score: ${score !== null ? score + '/100' : 'N/A'})`
    }, () => {
      if (chrome.runtime.lastError) {}
    });
  } catch (err) {
    // Tab might have closed
  }
}

/**
 * Stops any ongoing text-to-speech announcement immediately
 */
function stopSpeech() {
  if (typeof chrome !== 'undefined' && chrome.tts && chrome.tts.stop) {
    try {
      chrome.tts.stop();
    } catch (e) {}
  }
}

/**
 * Speaks a concise security report using Chrome TTS
 */
function speakReport(text, tabId, force = false) {
  if (!text) return;
  if (!appSettings.isDefenceHubOn) return;
  if (appSettings.isMuted && !force) return;

  stopSpeech();

  if (typeof chrome !== 'undefined' && chrome.tts && chrome.tts.speak) {
    try {
      chrome.tts.speak(text, {
        rate: 1.0,
        pitch: 1.0,
        enqueue: false,
        onEvent: (event) => {
          // Handled if needed
        }
      }, () => {
        if (chrome.runtime.lastError) {
          console.warn('[DefenceHub TTS] Warning speaking report:', chrome.runtime.lastError.message);
        }
      });
    } catch (err) {
      console.warn('[DefenceHub TTS] Error speaking report:', err);
    }
  }
}

/**
 * Resolve external reputation with caching & rate limiting
 */
async function resolveReputation(url) {
  if (!appSettings.apiKey) {
    return {
      status: 'UNCONFIGURED',
      provider: 'Google Safe Browsing v4',
      message: 'No API key configured in extension settings.'
    };
  }

  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;

    const cached = reputationCache.get(domain);
    if (cached && (Date.now() - cached.timestamp < REPUTATION_TTL_MS)) {
      return cached.result;
    }

    const result = await DefenceHubEngine.checkGoogleSafeBrowsing(url, appSettings.apiKey);
    reputationCache.set(domain, { result, timestamp: Date.now() });
    return result;
  } catch (e) {
    return {
      status: 'UNAVAILABLE',
      provider: 'Google Safe Browsing v4',
      message: 'Failed to evaluate external reputation.'
    };
  }
}

/**
 * Core automatic website analysis pipeline for a tab
 */
async function analyzeTab(tabId, rawUrl, sourceEvent, isExplicit = false) {
  if (!tabId || !rawUrl) return null;

  // Filter out internal and unsupported schemes
  const lowerUrl = rawUrl.toLowerCase().trim();
  if (
    !lowerUrl.startsWith('http://') &&
    !lowerUrl.startsWith('https://')
  ) {
    return null;
  }

  // De-duplicate rapid consecutive events on the same URL
  const prev = lastAnalyzedUrlByTab.get(tabId);
  const now = Date.now();
  if (!isExplicit && prev && prev.url === rawUrl && (now - prev.timestamp < 3500)) {
    return tabScanCache.get(tabId) || null;
  }
  lastAnalyzedUrlByTab.set(tabId, { url: rawUrl, timestamp: now });

  const scanRequestId = `${now}_${Math.random().toString(36).slice(2, 8)}`;
  activeScanIdByTab.set(tabId, scanRequestId);

  // 1. Resolve optional external reputation
  const repResult = await resolveReputation(rawUrl);

  // Discard stale response if a newer scan request was dispatched while waiting for reputation
  if (activeScanIdByTab.get(tabId) !== scanRequestId) {
    return null;
  }

  // 2. Perform comprehensive heuristic & rule analysis
  const existingScan = tabScanCache.get(tabId);
  const pageDomData = existingScan && existingScan.pageDomData ? existingScan.pageDomData : null;
  const analysisResult = DefenceHubEngine.analyzeUrl(rawUrl, pageDomData, { reputationResult: repResult });
  analysisResult.scanId = scanRequestId;

  // 3. Cache result
  tabScanCache.set(tabId, analysisResult);
  persistTabScans();

  // 4. Update tab toolbar badge
  updateTabBadge(tabId, analysisResult.riskLevel, analysisResult.score);

  // 5. Automatic Voice Reporting
  // Announce if tab is the active tab and has not already spoken for this exact URL
  function checkAndSpeak() {
    if (!analysisResult.speechText) return;
    const lastSpoken = lastSpokenUrlByTab.get(tabId);
    if (lastSpoken === rawUrl) return;

    if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.get) {
      chrome.tabs.get(tabId, (tab) => {
        if (chrome.runtime.lastError || !tab) return;
        if (tab.active) {
          currentActiveTabId = tabId;
          lastSpokenUrlByTab.set(tabId, rawUrl);
          speakReport(analysisResult.speechText, tabId);
        }
      });
    } else if (tabId === currentActiveTabId || currentActiveTabId === null) {
      lastSpokenUrlByTab.set(tabId, rawUrl);
      speakReport(analysisResult.speechText, tabId);
    }
  }
  checkAndSpeak();

  // 6. Broadcast update to open popups or tabs
  broadcastMessage({
    type: 'TAB_ANALYSIS_UPDATED',
    tabId: tabId,
    result: analysisResult
  });

  return analysisResult;
}

// ----------------------------------------------------
// Event Listeners: Navigation, Tab Activation & Messages
// ----------------------------------------------------

// 1. Tab Updated (Page load / URL change)
if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (tab && tab.active) {
      currentActiveTabId = tabId;
    }
    if (changeInfo.status === 'complete' || (changeInfo.url && changeInfo.url.startsWith('http'))) {
      const targetUrl = changeInfo.url || (tab && tab.url);
      if (targetUrl) {
        analyzeTab(tabId, targetUrl, 'onUpdated');
      }
    }
  });
}

// 2. Tab Activated (Switching between tabs)
if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.onActivated) {
  chrome.tabs.onActivated.addListener((activeInfo) => {
    // Immediately stop speech from previous tab
    stopSpeech();

    currentActiveTabId = activeInfo.tabId;
    chrome.tabs.get(activeInfo.tabId, (tab) => {
      if (chrome.runtime.lastError || !tab || !tab.url) return;
      if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
        const cached = tabScanCache.get(activeInfo.tabId);
        if (cached) {
          updateTabBadge(activeInfo.tabId, cached.riskLevel, cached.score);
          const lastSpoken = lastSpokenUrlByTab.get(activeInfo.tabId);
          if (lastSpoken !== tab.url && cached.speechText) {
            lastSpokenUrlByTab.set(activeInfo.tabId, tab.url);
            speakReport(cached.speechText, activeInfo.tabId);
          }
        } else {
          analyzeTab(activeInfo.tabId, tab.url, 'onActivated');
        }
      }
    });
  });
}

// 3. WebNavigation onCommitted (Handles full navigations and HTTP Redirects)
if (typeof chrome !== 'undefined' && chrome.webNavigation && chrome.webNavigation.onCommitted) {
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && details.url && (details.url.startsWith('http://') || details.url.startsWith('https://'))) {
      analyzeTab(details.tabId, details.url, 'onCommitted');
    }
  });
}

// 4. WebNavigation onHistoryStateUpdated (Handles Single-Page Application navigation)
if (typeof chrome !== 'undefined' && chrome.webNavigation && chrome.webNavigation.onHistoryStateUpdated) {
  chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId === 0 && details.url && (details.url.startsWith('http://') || details.url.startsWith('https://'))) {
      analyzeTab(details.tabId, details.url, 'onHistoryStateUpdated');
    }
  });
}

// 5. Tab Closed (Clean up memory)
if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    tabScanCache.delete(tabId);
    lastAnalyzedUrlByTab.delete(tabId);
    lastSpokenUrlByTab.delete(tabId);
    activeScanIdByTab.delete(tabId);
    persistTabScans();
  });
}

// 6. Runtime Messages
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || !message.type) return;

    const senderTabId = sender && sender.tab ? sender.tab.id : currentActiveTabId;

    // Content script DOM inspection complete
    if (message.type === 'SCAN_COMPLETE') {
      if (senderTabId) {
        const cached = tabScanCache.get(senderTabId);
        if (cached && (!message.url || cached.url === message.url)) {
          const reAnalyzed = DefenceHubEngine.analyzeUrl(cached.url, message.pageData, { reputationResult: cached.reputation });
          reAnalyzed.pageDomData = message.pageData;
          tabScanCache.set(senderTabId, reAnalyzed);
          persistTabScans();
          updateTabBadge(senderTabId, reAnalyzed.riskLevel, reAnalyzed.score);

          broadcastMessage({
            type: 'TAB_ANALYSIS_UPDATED',
            tabId: senderTabId,
            result: reAnalyzed
          });
        }
      }
      sendResponse({ status: 'ok' });
      return true;
    }

    // Popup requesting tab scan
    if (message.type === 'GET_TAB_SCAN') {
      const tabId = message.tabId || currentActiveTabId;
      const scan = tabScanCache.get(tabId) || null;
      sendResponse({ scan: scan, settings: appSettings });
      return true;
    }

    // Replay report button clicked
    if (message.type === 'REPLAY_REPORT') {
      const tabId = message.tabId || currentActiveTabId;
      const scan = tabScanCache.get(tabId);
      if (scan && scan.speechText) {
        speakReport(scan.speechText, tabId, true);
        sendResponse({ status: 'ok', spoken: true });
      } else {
        sendResponse({ status: 'no_report', spoken: false });
      }
      return true;
    }

    // Toggle Mute / Unmute
    if (message.type === 'TOGGLE_MUTE') {
      appSettings.isMuted = !appSettings.isMuted;
      if (appSettings.isMuted) {
        stopSpeech();
      }
      chrome.storage.local.set({ defencehub_settings: appSettings });
      sendResponse({ isMuted: appSettings.isMuted });
      return true;
    }

    // Toggle Extension On / Off
    if (message.type === 'TOGGLE_ENABLED') {
      appSettings.isDefenceHubOn = message.enabled !== undefined ? message.enabled : !appSettings.isDefenceHubOn;
      if (!appSettings.isDefenceHubOn) {
        stopSpeech();
      }
      chrome.storage.local.set({ defencehub_settings: appSettings });
      sendResponse({ isDefenceHubOn: appSettings.isDefenceHubOn });
      return true;
    }

    // Set Safe Browsing API Key
    if (message.type === 'SET_API_KEY') {
      appSettings.apiKey = (message.apiKey || '').trim();
      reputationCache.clear(); // Clear cache to re-evaluate with new key
      chrome.storage.local.set({ defencehub_settings: appSettings });
      // Re-analyze active tab if available
      if (currentActiveTabId) {
        chrome.tabs.get(currentActiveTabId, (tab) => {
          if (chrome.runtime.lastError || !tab || !tab.url) return;
          analyzeTab(currentActiveTabId, tab.url, 'apiKeyChanged', true);
        });
      }
      sendResponse({ status: 'ok', hasKey: !!appSettings.apiKey });
      return true;
    }

    // Get current app settings & voice status
    if (message.type === 'GET_STATUS') {
      sendResponse({
        isDefenceHubOn: appSettings.isDefenceHubOn,
        isMuted: appSettings.isMuted,
        hasApiKey: !!appSettings.apiKey,
        activeTabId: currentActiveTabId
      });
      return true;
    }
  });
}

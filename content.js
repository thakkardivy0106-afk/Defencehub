/**
 * DefenceHub - Content Script & In-Page Security Alert Overlay
 * Automatically evaluates active website security and displays
 * an immediate floating popup alert:
 * - RED banner for HIGH RISK (Unsafe) (#D92D3A)
 * - ORANGE banner for MEDIUM RISK (Caution) (#ea580c)
 * - GREEN banner for LOW RISK (Safe) (#16794B)
 *
 * Strict Security Guard:
 * - Active interception of password and payment inputs on high-risk or insecure pages
 * - Inline warning badges on untrusted credential forms
 * - Detection of payment card harvesting, crypto seed phrase phishing, and scareware
 */

(function () {
  'use strict';

  // Prevent duplicate injections
  if (window.__DEFENCEHUB_CONTENT_LOADED__) return;
  window.__DEFENCEHUB_CONTENT_LOADED__ = true;

  // Only run in top-level browsing context, never in frames or iframes
  if (window !== window.top) return;

  const currentUrl = window.location.href;
  if (!currentUrl.startsWith('http://') && !currentUrl.startsWith('https://')) return;

  // State: session unlock flag for power users
  window.__DEFENCEHUB_STRICT_UNLOCKED__ = false;

  // 1. Extract live DOM telemetry for the engine (Strictly non-sensitive telemetry)
  function extractPageData() {
    try {
      const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]'));
      
      // Payment card & banking input pattern sniffer (Checks attribute names & placeholders, never input values)
      const allInputs = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]), select'));
      let hasPaymentInputs = false;
      let paymentInputsCount = 0;

      const cardPatterns = /card[-_]?num|cc[-_]?num|credit[-_]?card|\bpan\b|account[-_]?number/i;
      const cvvPatterns = /\bcvv\b|\bcvc\b|security[-_]?code|card[-_]?code|verification[-_]?code/i;
      const ssnPatterns = /\bssn\b|social[-_]?sec|national[-_]?id|tax[-_]?id/i;

      allInputs.forEach(input => {
        const descriptor = `${input.name || ''} ${input.id || ''} ${input.autocomplete || ''} ${input.placeholder || ''} ${input.getAttribute('aria-label') || ''}`.toLowerCase();
        if (cardPatterns.test(descriptor) || cvvPatterns.test(descriptor) || ssnPatterns.test(descriptor)) {
          hasPaymentInputs = true;
          paymentInputsCount++;
        }
      });

      // Cryptocurrency 12/24-word seed phrase or private key harvesting sniffer
      let hasCryptoSeedInputs = false;
      const seedInputPatterns = /seed[-_]?phrase|recovery[-_]?phrase|\bmnemonic\b|private[-_]?key|12[-_]?word|24[-_]?word/i;
      const textareas = Array.from(document.querySelectorAll('textarea, input[type="text"]'));
      textareas.forEach(t => {
        const desc = `${t.name || ''} ${t.id || ''} ${t.placeholder || ''} ${t.getAttribute('aria-label') || ''}`.toLowerCase();
        if (seedInputPatterns.test(desc)) {
          hasCryptoSeedInputs = true;
        }
      });

      const forms = Array.from(document.forms).map(f => {
        let actionUrl = '';
        try {
          actionUrl = f.action ? new URL(f.action, window.location.href).href : '';
        } catch (e) {}
        return {
          action: actionUrl,
          method: (f.method || 'GET').toUpperCase(),
          hasPassword: !!f.querySelector('input[type="password"]'),
          hasPayment: Array.from(f.querySelectorAll('input')).some(i => {
            const d = `${i.name || ''} ${i.id || ''} ${i.placeholder || ''}`.toLowerCase();
            return cardPatterns.test(d) || cvvPatterns.test(d);
          })
        };
      });

      // Deceptive urgency / account suspension detection in untrusted page text
      let hasUrgencySignals = false;
      let hasSeedPhraseSignals = hasCryptoSeedInputs;
      let hasScarewareSignals = false;

      try {
        const bodyText = (document.body ? document.body.innerText : '').toLowerCase();
        
        const urgencyPhrases = [
          'account suspended', 'account has been locked', 'unauthorized access detected',
          'immediate action required', 'verify within 24 hours', 'action required to prevent',
          'security alert: unusual activity', 'confirm your identity immediately',
          'billing payment failed', 'payment declined: update now', 'kyc verification required',
          'tax refund pending'
        ];
        hasUrgencySignals = urgencyPhrases.some(phrase => bodyText.includes(phrase));

        const cryptoPhrases = [
          '12-word recovery phrase', 'secret recovery phrase', 'enter your seed phrase',
          'backup phrase', 'enter your private key', 'mnemonic phrase', 'restore metamask wallet',
          'wallet validation', 'connect ledger'
        ];
        if (cryptoPhrases.some(phrase => bodyText.includes(phrase))) {
          hasSeedPhraseSignals = true;
        }

        const scarewarePhrases = [
          'call microsoft support', 'call apple support', 'virus detected', 'trojan spyware alert',
          'critical alert from microsoft', 'windows defender alert', 'call toll free',
          'computer has been locked', 'call security support', 'call 1-8'
        ];
        hasScarewareSignals = scarewarePhrases.some(phrase => bodyText.includes(phrase));
      } catch (e) {}

      // Misleading link detection (Anchor text claims a brand/domain but href points elsewhere)
      const suspiciousLinks = [];
      try {
        const anchors = document.querySelectorAll('a[href]');
        const knownBrandNames = [
          'paypal.com', 'google.com', 'apple.com', 'microsoft.com', 'amazon.com',
          'chase.com', 'bankofamerica.com', 'metamask.io', 'binance.com', 'coinbase.com'
        ];
        for (let i = 0; i < Math.min(anchors.length, 60); i++) {
          const a = anchors[i];
          const text = (a.innerText || '').trim().toLowerCase();
          const href = a.href || '';
          if (href.startsWith('http://') || href.startsWith('https://')) {
            for (const brandDomain of knownBrandNames) {
              if (text.includes(brandDomain)) {
                try {
                  const hrefUrl = new URL(href);
                  if (!hrefUrl.hostname.includes(brandDomain)) {
                    suspiciousLinks.push({ text: a.innerText.slice(0, 30), href: href });
                    break;
                  }
                } catch (e) {}
              }
            }
          }
          if (suspiciousLinks.length >= 3) break;
        }
      } catch (e) {}

      return {
        title: document.title || '',
        hasPassword: passwordInputs.length > 0,
        passwordCount: passwordInputs.length,
        hasPaymentInputs: hasPaymentInputs,
        paymentInputsCount: paymentInputsCount,
        hasCryptoSeedInputs: hasCryptoSeedInputs,
        hasSeedPhraseSignals: hasSeedPhraseSignals,
        hasScarewareSignals: hasScarewareSignals,
        forms: forms,
        hasUrgencySignals: hasUrgencySignals,
        suspiciousLinks: suspiciousLinks,
        isHttps: window.location.protocol === 'https:',
        iframeCount: document.querySelectorAll('iframe').length
      };
    } catch (e) {
      return null;
    }
  }

  // 2. Perform security analysis
  if (typeof DefenceHubEngine === 'undefined') {
    return;
  }

  const pageData = extractPageData();
  const result = DefenceHubEngine.analyzeUrl(currentUrl, pageData);
  if (!result || !result.valid) return;

  // 3. Notify background service worker to update toolbar badge and sync live DOM
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({
        type: 'SCAN_COMPLETE',
        url: currentUrl,
        riskLevel: result.riskLevel,
        riskLabel: result.riskLabel,
        score: result.score,
        riskScore: result.riskScore,
        hostname: result.hostname,
        status: result.status,
        confidence: result.confidence,
        pageData: pageData,
        timestamp: Date.now()
      }, () => {
        if (chrome.runtime.lastError) {
          // Silent catch to suppress port closed warning
        }
      });
    }
  } catch (e) {}

  // 4. Render In-Page Floating Popup Alert using Shadow DOM for isolation
  function renderInPagePopup(res) {
    if (document.getElementById('defencehub-overlay-host')) return;

    const hostEl = document.createElement('div');
    hostEl.id = 'defencehub-overlay-host';
    hostEl.style.cssText = 'all: initial; position: fixed; top: 16px; right: 16px; z-index: 2147483647; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; pointer-events: auto;';

    const shadow = hostEl.attachShadow({ mode: 'open' });

    // Distinct Theme Palettes: Red (High), Orange (Medium), Green (Low)
    let colorTheme = {
      headerBg: '#16794B',      // Rich Emerald Green
      bannerBg: '#f0fdf4',      // Soft Green
      border: '#16794B',
      textColor: '#14532d',
      title: 'LOW RISK • SAFE',
      icon: '🛡️',
      subText: 'Verified safe domain conventions & encrypted transport.',
      riskBadge: 'SAFE (95%+)',
      riskBadgeBg: '#dcfce7',
      riskBadgeColor: '#166534'
    };

    if (res.riskLevel === 'HIGH' || res.status === 'CRITICAL_RISK' || res.status === 'HIGH_RISK') {
      colorTheme = {
        headerBg: '#D92D3A',    // High-alert Crimson Red
        bannerBg: '#fef2f2',    // Soft Red Alert
        border: '#D92D3A',
        textColor: '#991b1b',
        title: res.status === 'CRITICAL_RISK' ? 'CRITICAL RISK • UNSAFE' : 'HIGH RISK • UNSAFE',
        icon: '🚨',
        subText: 'Deceptive patterns, brand impersonation, or dangerous threat signals detected!',
        riskBadge: 'HIGH RISK / DANGER',
        riskBadgeBg: '#fee2e2',
        riskBadgeColor: '#991b1b'
      };
    } else if (res.riskLevel === 'MEDIUM' || res.status === 'SUSPICIOUS') {
      colorTheme = {
        headerBg: '#ea580c',    // Safety Orange
        bannerBg: '#fff7ed',    // Soft Orange/Amber
        border: '#ea580c',
        textColor: '#9a3412',
        title: 'MEDIUM RISK • CAUTION',
        icon: '⚠️',
        subText: 'Cautionary signals detected. Verify website identity before submitting credentials.',
        riskBadge: 'CAUTION NEEDED',
        riskBadgeBg: '#ffedd5',
        riskBadgeColor: '#9a3412'
      };
    }

    const firstFinding = res.findings && res.findings.length > 0 ? res.findings[0].title : null;

    const styles = `
      * { box-sizing: border-box; margin: 0; padding: 0; }
      .dh-popup {
        width: 330px;
        background: #ffffff;
        border: 2.5px solid ${colorTheme.border};
        border-radius: 12px;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.22), 0 3px 8px rgba(0, 0, 0, 0.1);
        overflow: hidden;
        animation: dhSlideIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 13px;
        color: #182338;
      }
      .dh-popup.dh-slide-out {
        animation: dhSlideOut 0.32s cubic-bezier(0.4, 0, 0.2, 1) forwards;
      }
      @keyframes dhSlideIn {
        from { transform: translateX(115%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      @keyframes dhSlideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(115%); opacity: 0; }
      }
      .dh-header {
        background-color: ${colorTheme.headerBg};
        color: #ffffff;
        padding: 10px 14px;
        display: flex;
        align-items: center;
        justify-content: space-between;
      }
      .dh-title-row {
        display: flex;
        align-items: center;
        gap: 8px;
        font-weight: 800;
        font-size: 12.5px;
        letter-spacing: 0.4px;
        text-transform: uppercase;
      }
      .dh-icon {
        font-size: 15px;
      }
      .dh-close-btn {
        background: transparent;
        border: none;
        color: #ffffff;
        font-size: 19px;
        font-weight: 700;
        cursor: pointer;
        padding: 0 4px;
        line-height: 1;
        opacity: 0.88;
        transition: opacity 0.15s ease, transform 0.15s ease;
      }
      .dh-close-btn:hover {
        opacity: 1;
        transform: scale(1.15);
      }
      .dh-body {
        padding: 13px 14px;
        background: ${colorTheme.bannerBg};
        display: flex;
        flex-direction: column;
        gap: 9px;
      }
      .dh-score-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      .dh-host {
        font-weight: 700;
        font-size: 13.5px;
        color: #182338;
        max-width: 195px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .dh-score-badges {
        display: flex;
        align-items: center;
        gap: 6px;
      }
      .dh-score-badge {
        font-weight: 800;
        font-size: 12px;
        padding: 2.5px 8px;
        border-radius: 9999px;
        background: #ffffff;
        border: 1.5px solid ${colorTheme.border};
        color: ${colorTheme.headerBg};
      }
      .dh-message {
        font-size: 11.5px;
        color: ${colorTheme.textColor};
        line-height: 1.4;
      }
      .dh-alert-item {
        background: #ffffff;
        border-left: 3.5px solid ${colorTheme.border};
        padding: 7px 9px;
        border-radius: 5px;
        font-size: 11.5px;
        font-weight: 600;
        color: #182338;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      }
      .dh-strict-tag {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        font-size: 10px;
        font-weight: 700;
        color: #991b1b;
        background: #fee2e2;
        padding: 2px 6px;
        border-radius: 4px;
        width: fit-content;
      }
      .dh-actions {
        display: flex;
        gap: 7px;
        margin-top: 3px;
      }
      .dh-btn {
        flex: 1;
        padding: 7px 11px;
        font-size: 12px;
        font-weight: 700;
        border-radius: 7px;
        cursor: pointer;
        border: none;
        text-align: center;
        transition: opacity 0.15s ease, transform 0.1s ease;
      }
      .dh-btn-danger {
        background: #D92D3A;
        color: #ffffff;
        box-shadow: 0 2px 6px rgba(217, 45, 58, 0.35);
      }
      .dh-btn-secondary {
        background: #ffffff;
        border: 1px solid #cbd5e1;
        color: #182338;
      }
      .dh-btn:hover {
        opacity: 0.92;
        transform: translateY(-1px);
      }
      .dh-btn:active {
        transform: translateY(0);
      }
    `;

    const html = `
      <style>${styles}</style>
      <div class="dh-popup">
        <div class="dh-header">
          <div class="dh-title-row">
            <span class="dh-icon">${colorTheme.icon}</span>
            <span>${colorTheme.title}</span>
          </div>
          <div style="display:flex; align-items:center; gap:6px;">
            <button class="dh-close-btn" id="dh-replay" title="Replay voice report" style="font-size:14px;">🔁</button>
            <button class="dh-close-btn" id="dh-mute" title="Toggle voice mute" style="font-size:14px;">🔊</button>
            <button class="dh-close-btn" id="dh-close" title="Dismiss alert">&times;</button>
          </div>
        </div>
        <div class="dh-body">
          <div class="dh-score-row">
            <span class="dh-host" title="${res.hostname}">${res.hostname}</span>
            <div class="dh-score-badges">
              <span class="dh-score-badge">${res.score}/100</span>
            </div>
          </div>
          <p class="dh-message">${colorTheme.subText}</p>
          ${firstFinding ? `<div class="dh-alert-item">⚠️ ${firstFinding}</div>` : ''}
          ${res.riskLevel === 'HIGH' ? '<div class="dh-strict-tag">🛡️ Strict Credential Shield Active</div>' : ''}
          <div class="dh-actions">
            ${res.riskLevel === 'HIGH' ? '<button class="dh-btn dh-btn-danger" id="dh-leave">Leave Site</button>' : ''}
            <button class="dh-btn dh-btn-secondary" id="dh-dismiss">Dismiss</button>
          </div>
        </div>
      </div>
    `;

    shadow.innerHTML = html;

    // Resilient mount onto body or documentElement
    const targetParent = document.body || document.documentElement;
    if (targetParent) {
      targetParent.appendChild(hostEl);
    } else {
      window.addEventListener('DOMContentLoaded', () => {
        (document.body || document.documentElement).appendChild(hostEl);
      });
    }

    // Event listeners inside Shadow DOM
    const closeBtn = shadow.getElementById('dh-close');
    const dismissBtn = shadow.getElementById('dh-dismiss');
    const leaveBtn = shadow.getElementById('dh-leave');
    const replayBtn = shadow.getElementById('dh-replay');
    const muteBtn = shadow.getElementById('dh-mute');

    if (replayBtn) {
      replayBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'REPLAY_REPORT' }, () => {
            if (chrome.runtime.lastError) {}
          });
        }
      });
    }

    if (muteBtn) {
      muteBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'TOGGLE_MUTE' }, (resp) => {
            if (chrome.runtime.lastError) {}
            if (resp && resp.isMuted !== undefined) {
              muteBtn.textContent = resp.isMuted ? '🔇' : '🔊';
            }
          });
        }
      });
    }

    let isClosing = false;
    function removeOverlay() {
      if (isClosing) return;
      isClosing = true;
      const popup = shadow.querySelector('.dh-popup');
      if (popup) {
        popup.classList.add('dh-slide-out');
        setTimeout(() => {
          if (hostEl && hostEl.parentNode) {
            hostEl.parentNode.removeChild(hostEl);
          }
        }, 320);
      } else if (hostEl && hostEl.parentNode) {
        hostEl.parentNode.removeChild(hostEl);
      }
    }

    if (closeBtn) closeBtn.addEventListener('click', removeOverlay);
    if (dismissBtn) dismissBtn.addEventListener('click', removeOverlay);
    if (leaveBtn) {
      leaveBtn.addEventListener('click', () => {
        window.location.href = 'https://www.google.com';
      });
    }

    // Auto-dismiss low-risk green popup after 4 seconds with pause-on-hover
    if (res.riskLevel === 'LOW') {
      let dismissTimer = setTimeout(removeOverlay, 4000);
      hostEl.addEventListener('mouseenter', () => clearTimeout(dismissTimer));
      hostEl.addEventListener('mouseleave', () => {
        dismissTimer = setTimeout(removeOverlay, 2500);
      });
    }
  }

  // 5. Strict Credential & Sensitive Form Interceptor Shield
  function initStrictSecurityShield(res, page) {
    const isHighThreat = res.riskLevel === 'HIGH' || res.status === 'CRITICAL_RISK' || res.status === 'HIGH_RISK';
    const isInsecureForm = !res.isHttps && (page.hasPassword || page.hasPaymentInputs);
    
    // Only arm strict blocking on high-risk sites or unencrypted credential forms
    if (!isHighThreat && !isInsecureForm) return;

    // Attach in-line visual warning badges adjacent to sensitive inputs
    function attachInlineInputBadges() {
      const sensitiveInputs = document.querySelectorAll('input[type="password"], input[name*="card"], input[name*="cvv"]');
      sensitiveInputs.forEach(input => {
        if (input.getAttribute('data-dh-badged')) return;
        input.setAttribute('data-dh-badged', 'true');
        
        try {
          const badge = document.createElement('div');
          badge.className = 'dh-inline-warning-badge';
          badge.style.cssText = 'all: initial; display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 700; color: #991b1b; background: #fee2e2; border: 1px solid #f87171; border-radius: 4px; padding: 2px 7px; margin-top: 4px; margin-bottom: 4px; font-family: -apple-system, sans-serif;';
          badge.textContent = isHighThreat 
            ? '🚨 DefenceHub Strict Guard: Untrusted / Phishing Risk Site' 
            : '⚠️ DefenceHub: Unencrypted Plaintext HTTP Form';
          if (input.parentNode) {
            input.parentNode.insertBefore(badge, input.nextSibling);
          }
        } catch (e) {}
      });
    }

    // Render Strict Security Interceptor Modal (Center Screen Blocking Overlay)
    function showStrictInterceptorModal(triggerInput) {
      if (window.__DEFENCEHUB_STRICT_UNLOCKED__) return;
      if (document.getElementById('defencehub-modal-host')) return;

      const modalHost = document.createElement('div');
      modalHost.id = 'defencehub-modal-host';
      modalHost.style.cssText = 'all: initial; position: fixed; inset: 0; z-index: 2147483647; display: flex; align-items: center; justify-content: center; background: rgba(11, 19, 41, 0.82); backdrop-filter: blur(4px); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; pointer-events: auto;';

      const shadow = modalHost.attachShadow({ mode: 'open' });
      const firstFindingText = res.findings && res.findings.length > 0 ? res.findings[0].title : 'High-risk security anomaly detected';

      const modalStyles = `
        * { box-sizing: border-box; margin: 0; padding: 0; }
        .modal-card {
          width: 90%;
          max-width: 440px;
          background: #ffffff;
          border: 3px solid #D92D3A;
          border-radius: 14px;
          box-shadow: 0 20px 48px rgba(0, 0, 0, 0.4);
          overflow: hidden;
          animation: popIn 0.28s cubic-bezier(0.16, 1, 0.3, 1) forwards;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          color: #182338;
        }
        @keyframes popIn {
          from { transform: scale(0.92); opacity: 0; }
          to { transform: scale(1); opacity: 1; }
        }
        .modal-header {
          background: #D92D3A;
          color: #ffffff;
          padding: 14px 18px;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .modal-title {
          font-size: 14px;
          font-weight: 800;
          letter-spacing: 0.5px;
          text-transform: uppercase;
        }
        .modal-body {
          padding: 18px;
          display: flex;
          flex-direction: column;
          gap: 12px;
          background: #fef2f2;
        }
        .modal-alert-box {
          background: #ffffff;
          border-left: 4px solid #D92D3A;
          padding: 10px 12px;
          border-radius: 6px;
          font-size: 12.5px;
          font-weight: 600;
          color: #991b1b;
        }
        .modal-desc {
          font-size: 12.5px;
          line-height: 1.5;
          color: #374151;
        }
        .modal-actions {
          display: flex;
          flex-direction: column;
          gap: 8px;
          margin-top: 4px;
        }
        .btn {
          padding: 10px 14px;
          font-size: 13px;
          font-weight: 700;
          border-radius: 8px;
          cursor: pointer;
          border: none;
          text-align: center;
          transition: transform 0.1s ease, opacity 0.15s ease;
        }
        .btn-leave {
          background: #D92D3A;
          color: #ffffff;
          box-shadow: 0 3px 8px rgba(217, 45, 58, 0.4);
        }
        .btn-unlock {
          background: #ffffff;
          color: #64748b;
          border: 1px solid #cbd5e1;
        }
        .btn:hover {
          opacity: 0.93;
          transform: translateY(-1px);
        }
      `;

      shadow.innerHTML = `
        <style>${modalStyles}</style>
        <div class="modal-card">
          <div class="modal-header">
            <span style="font-size:20px;">🛡️</span>
            <span class="modal-title">Strict Shield: Credential Input Blocked</span>
          </div>
          <div class="modal-body">
            <div class="modal-alert-box">
              ⚠️ Threat: ${firstFindingText} (${res.score}/100 Safety Score)
            </div>
            <p class="modal-desc">
              DefenceHub has temporarily locked credential entry on <strong>${res.hostname}</strong>. 
              Submitting passwords, payment cards, or sensitive data on this unverified or dangerous page creates an extreme risk of credential theft.
            </p>
            <div class="modal-actions">
              <button class="btn btn-leave" id="btn-leave-safe">🛡️ Leave Website Immediately (Recommended)</button>
              <button class="btn btn-unlock" id="btn-unlock-temp">⚠️ Temporarily Unlock Fields (Proceed with Caution)</button>
            </div>
          </div>
        </div>
      `;

      document.body.appendChild(modalHost);

      const leaveBtn = shadow.getElementById('btn-leave-safe');
      const unlockBtn = shadow.getElementById('btn-unlock-temp');

      leaveBtn.addEventListener('click', () => {
        window.location.href = 'https://www.google.com';
      });

      unlockBtn.addEventListener('click', () => {
        window.__DEFENCEHUB_STRICT_UNLOCKED__ = true;
        if (modalHost.parentNode) {
          modalHost.parentNode.removeChild(modalHost);
        }
        if (triggerInput && typeof triggerInput.focus === 'function') {
          triggerInput.focus();
        }
      });
    }

    // Intercept user interaction on sensitive inputs
    function setupInputGuards() {
      const inputs = document.querySelectorAll('input[type="password"], input[name*="card"], input[name*="cvv"], input[name*="seed"]');
      inputs.forEach(inp => {
        inp.addEventListener('focus', (e) => {
          if (!window.__DEFENCEHUB_STRICT_UNLOCKED__) {
            inp.blur();
            showStrictInterceptorModal(inp);
          }
        });
      });

      // Intercept form submissions containing credentials
      const allForms = Array.from(document.forms);
      allForms.forEach(form => {
        form.addEventListener('submit', (e) => {
          if (!window.__DEFENCEHUB_STRICT_UNLOCKED__) {
            const hasCreds = form.querySelector('input[type="password"], input[name*="card"], input[name*="cvv"]');
            if (hasCreds) {
              e.preventDefault();
              e.stopPropagation();
              showStrictInterceptorModal(hasCreds);
            }
          }
        }, true);
      });
    }

    attachInlineInputBadges();
    setupInputGuards();
  }

  // Trigger popup & strict shield when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      renderInPagePopup(result);
      initStrictSecurityShield(result, pageData);
    });
  } else {
    renderInPagePopup(result);
    initStrictSecurityShield(result, pageData);
  }
})();

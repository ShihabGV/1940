/**
 * AI Safe Guard - Content Script
 * Injects security bar and analyzes URLs
 */

(function () {
  'use strict';

  // Only on http/https
  if (!location.href.startsWith('http')) return;

  const BAR_ID = '__ai_safe_guard_bar__';
  let securityBar = null;

  // ========== CREATE AND INSERT BAR ==========
  function createBar() {
    if (document.getElementById(BAR_ID)) return document.getElementById(BAR_ID);

    const bar = document.createElement('div');
    bar.id = BAR_ID;
    bar.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      z-index: 2147483647 !important;
      padding: 12px 20px !important;
      background: #16a34a !important;
      color: #fff !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      font-size: 14px !important;
      display: flex !important;
      justify-content: space-between !important;
      align-items: center !important;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2) !important;
      margin: 0 !important;
      border: 0 !important;
      width: 100% !important;
      box-sizing: border-box !important;
    `;

    bar.innerHTML = `
      <div style="display: flex; gap: 15px; align-items: center; flex: 1;">
        <span style="font-weight: 700; font-size: 15px;">🛡️ AI Safe Guard</span>
        <span id="threat-level" style="font-weight: 600;"></span>
      </div>
      <div style="display: flex; gap: 10px; align-items: center;">
        <span id="bar-url" style="font-size: 12px; opacity: 0.8; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"></span>
        <button id="close-btn" style="padding: 4px 12px; background: rgba(255,255,255,0.15); border: none; color: #fff; cursor: pointer; border-radius: 4px; font-size: 12px; font-weight: 500;">✕ Close</button>
      </div>
    `;

    // Close handler
    bar.querySelector('#close-btn').onclick = () => {
      bar.style.display = 'none';
      securityBar = null;
    };

    // Insert into page
    const target = document.body || document.documentElement;
    target.insertBefore(bar, target.firstChild);
    
    console.log('[AI Safe Guard] Bar injected into page');
    return bar;
  }

  // ========== UPDATE BAR WITH SCORE ==========
  function updateBar(score, url) {
    if (!securityBar) securityBar = createBar();
    if (!securityBar) {
      console.error('[AI Safe Guard] Failed to create bar');
      return;
    }

    let color, threat;
    if (score >= 85) {
      color = '#dc2626';
      threat = '🟥 DANGEROUS';
    } else if (score >= 60) {
      color = '#f97316';
      threat = '🟧 SUSPICIOUS';
    } else if (score >= 35) {
      color = '#eab308';
      threat = '🟨 MEDIUM';
    } else {
      color = '#16a34a';
      threat = '🟩 SAFE';
    }

    securityBar.style.background = color;
    
    const threatEl = securityBar.querySelector('#threat-level');
    if (threatEl) {
      threatEl.textContent = `${threat} (${score}/100)`;
    }

    const urlEl = securityBar.querySelector('#bar-url');
    if (urlEl) {
      urlEl.textContent = url;
      urlEl.title = url;
    }

    console.log('[AI Safe Guard] Bar updated:', threat, 'Score:', score, 'URL:', url);
  }

  // ========== ANALYZE URL WITH AI ==========
  function analyzeUrl(url) {
    try {
      // Check if AI model is available
      if (typeof window.aiPredictRisk !== 'function') {
        console.warn('[AI Safe Guard] AI model not available yet');
        return 35; // default
      }

      // Call AI model
      const result = window.aiPredictRisk(url);
      console.log('[AI Safe Guard] AI result:', result);

      let score = 35;
      if (typeof result === 'number') {
        score = result;
      } else if (result && typeof result.score === 'number') {
        score = result.score;
      } else if (result && typeof result.prob === 'number') {
        score = Math.round(result.prob * 100);
      }

      console.log('[AI Safe Guard] Final AI score:', score);
      return score;
    } catch (error) {
      console.error('[AI Safe Guard] Analysis error:', error);
      return 35;
    }
  }

  // ========== SCAN PAGE VULNERABILITIES ==========
  function scanVulnerabilities() {
    try {
      if (typeof window.scanPageVulnerabilities !== 'function') {
        console.log('[AI Safe Guard] Vulnerability scanner not ready');
        return { vulnerabilities: {}, score: 0, hasVulnerabilities: false };
      }

      const vulnResult = window.scanPageVulnerabilities();
      console.log('[AI Safe Guard] Vulnerability scan complete:', vulnResult);
      return vulnResult;
    } catch (error) {
      console.error('[AI Safe Guard] Vulnerability scan error:', error);
      return { vulnerabilities: {}, score: 0, hasVulnerabilities: false };
    }
  }

  // ========== SEND TO BACKGROUND ==========
  function reportFindings(score, url) {
    try {
      // Get vulnerability scan results
      const vulnResult = scanVulnerabilities();

      const payload = {
        type: 'PAGE_FINDINGS',
        findings: {
          url: url,
          aiScore: score,
          vulnerabilities: vulnResult.vulnerabilities || {},
          vulnerabilityScore: vulnResult.score || 0,
          phishing: { suspicious: false },
          keylogger: { suspicious: false },
          sessionRisk: { score: 0 }
        }
      };
      console.log('[Content] Sending message to background:', payload);
      
      chrome.runtime.sendMessage(payload, (response) => {
        console.log('[Content] Message response:', response);
      });
      
    } catch (error) {
      console.error('[Content] Report error:', error);
    }
  }

  // ========== MAIN INIT ==========
  function analyze() {
    const currentUrl = location.href;
    console.log('[AI Safe Guard] Analyzing:', currentUrl);
    
    const score = analyzeUrl(currentUrl);
    updateBar(score, currentUrl);
    reportFindings(score, currentUrl);
  }

  // Run on load
  console.log('[AI Safe Guard] Content script started');
  
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', analyze);
  } else {
    setTimeout(analyze, 100);
  }

  // Re-analyze when AI model loads
  let aiCheckAttempts = 0;
  const aiCheckInterval = setInterval(() => {
    aiCheckAttempts++;
    if (typeof window.aiPredictRisk === 'function') {
      clearInterval(aiCheckInterval);
      console.log('[AI Safe Guard] AI model now available, re-analyzing');
      analyze();
    }
    if (aiCheckAttempts > 100) {
      clearInterval(aiCheckInterval);
      console.warn('[AI Safe Guard] Timeout waiting for AI model');
    }
  }, 50);

  // Monitor URL changes (for SPAs)
  let lastUrl = location.href;
  setInterval(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      console.log('[AI Safe Guard] URL changed, re-analyzing');
      analyze();
    }
  }, 500);

  // Listen for clipboard copy requests from background script
  console.log('[AI Safe Guard] Setting up message listener for clipboard operations');
  
  console.log('[AI Safe Guard] Initialization complete');
})();

// Message listener for background script operations (outside IIFE to ensure it runs)
console.log('[Content] Setting up message listener for clipboard and alert operations');

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('[Content] Received message:', request.action);
  
  if (request.action === 'copyToClipboard') {
    console.log('[Content] Processing clipboard request for:', request.text.substring(0, 50));
    
    navigator.clipboard.writeText(request.text).then(() => {
      console.log('[Content] ✅ Text copied to clipboard successfully');
      sendResponse({ success: true });
    }).catch(err => {
      console.error('[Content] ❌ Failed to copy to clipboard:', err);
      sendResponse({ success: false, error: err.message });
    });
    return true; // Keep channel open for async response
  }
  
  if (request.action === 'showAlert') {
    console.log('[Content] Showing alert:', request.title);
    alert(request.message);
    sendResponse({ success: true });
  }
});

console.log('[Content] Message listener setup complete');
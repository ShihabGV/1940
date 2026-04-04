/**
 * AI Safe Guard - Utility Functions
 * Shared utilities for the extension
 */

// ==================== SECURITY ====================
function escapeHtml(str) {
  if (!str) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(str).replace(/[&<>"']/g, char => map[char]);
}

function isValidUrl(urlString) {
  try {
    new URL(urlString);
    return true;
  } catch {
    return false;
  }
}

// ==================== STORAGE ====================
async function getSettings() {
  const defaults = {
    blockOnHighRisk: true,
    minRiskToWarn: 60,
    minRiskToBlock: 85,
    vtEnable: false,
    vtKey: "",
    protectionEnabled: true,
    locale: 'en'
  };
  return new Promise((resolve) => {
    chrome.storage.sync.get(Object.keys(defaults), (stored) => {
      resolve({ ...defaults, ...stored });
    });
  });
}

async function saveSettings(settings) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(settings, resolve);
  });
}

async function addLog(entry) {
  return new Promise((resolve) => {
    try {
      entry.ts = entry.ts || Date.now();
      chrome.storage.local.get(['logs'], (result) => {
        let logs = result.logs || [];
        if (!Array.isArray(logs)) logs = [];
        logs.unshift(entry);
        chrome.storage.local.set({ logs: logs.slice(0, 500) }, () => {
          console.log('[AI Safe Guard] Log added');
          resolve();
        });
      });
    } catch (error) {
      console.error('[AI Safe Guard] Error adding log:', error);
      resolve();
    }
  });
}

async function clearLogs() {
  return new Promise((resolve) => {
    chrome.storage.local.set({ logs: [] }, resolve);
  });
}

async function getLogs() {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(['logs'], (result) => {
        if (chrome.runtime.lastError) {
          console.error('[AI Safe Guard] Storage error:', chrome.runtime.lastError);
          resolve([]);
        } else {
          const logs = result.logs || [];
          console.log('[AI Safe Guard] Retrieved logs:', logs.length);
          resolve(logs);
        }
      });
    } catch (error) {
      console.error('[AI Safe Guard] Error getting logs:', error);
      resolve([]);
    }
  });
}

// ==================== NOTIFICATIONS ====================
function sendNotification(title, message, type = 'basic') {
  if (!chrome.notifications) return;
  chrome.notifications.create({
    type,
    iconUrl: chrome.runtime.getURL('images/icon-128.png'),
    title: escapeHtml(title),
    message: escapeHtml(message),
    isClickable: true,
    requireInteraction: false
  });
}

// ==================== LOGGING ====================
const Logger = {
  log(msg, data = null) { console.log(`[AI Safe Guard] ${msg}`, data || ''); },
  info(msg, data = null) { console.info(`[AI Safe Guard] INFO: ${msg}`, data || ''); },
  warn(msg, data = null) { console.warn(`[AI Safe Guard] WARN: ${msg}`, data || ''); },
  error(msg, data = null) { console.error(`[AI Safe Guard] ERROR: ${msg}`, data || ''); }
};

// ==================== FORMAT HELPERS ====================
function formatTime(timestamp) {
  if (!timestamp) return 'Unknown';
  return new Date(timestamp).toLocaleString();
}

function getRiskColor(score) {
  if (score >= 85) return '#dc2626';
  if (score >= 60) return '#f97316';
  if (score >= 35) return '#eab308';
  return '#16a34a';
}

function getRiskText(score) {
  if (score >= 85) return '🟥 Dangerous';
  if (score >= 60) return '🟧 Suspicious';
  if (score >= 35) return '🟨 Medium';
  return '🟩 Safe';
}

// ==================== RATE LIMITER ====================
class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = [];
  }
  canMakeRequest() {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.windowMs);
    if (this.requests.length < this.maxRequests) {
      this.requests.push(now);
      return true;
    }
    return false;
  }
}

// ==================== EXPORTS ====================
// Expose to global scope
if (typeof window !== 'undefined') {
  window.getLogs = getLogs;
  window.addLog = addLog;
  window.clearLogs = clearLogs;
  window.getSettings = getSettings;
  window.saveSettings = saveSettings;
  window.escapeHtml = escapeHtml;
  window.formatTime = formatTime;
  window.Logger = Logger;
  window.getRiskColor = getRiskColor;
  window.getRiskText = getRiskText;
  window.RateLimiter = RateLimiter;
}

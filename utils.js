/**
 * AI Safe Guard - Utility Functions
 * Shared utilities for the extension
 */

// ==================== LOCALIZATION ====================
const I18N = {
  en: {
    // General
    appName: "AI Safe Guard",
    protection: "Protection",
    riskLevel: "Risk Level",
    
    // Risk levels
    safeLevel: "Safe",
    mediumLevel: "Medium",
    suspiciousLevel: "Suspicious",
    dangerousLevel: "Dangerous",
    
    // Messages
    blockedForSafety: "Blocked for your safety",
    protectionEnabled: "Protection Enabled ✅",
    protectionDisabled: "Protection Disabled ❌",
    enableVirusTotal: "Enable VirusTotal Scan",
    apiKeyPlaceholder: "Enter VirusTotal API Key",
    saveSettings: "Save Settings",
    settingsSaved: "Settings Saved ✅",
    clearLog: "Clear Logs",
    totalEvents: "Total Events",
    warnings: "Warnings",
    blockedHigh: "High Risk Blocks",
    highRiskDownload: "High Risk Download",
    suspiciousExtension: "Suspicious extension detected",
    malwareBlocked: "Malware Blocked",
    suspiciousDownload: "Suspicious Download",
    virusotalDetected: "VirusTotal detected as malicious",
    hide: "Hide",
    timestamp: "Time",
    aiScore: "AI Score",
    sessionRisk: "Session Risk",
    phishing: "Phishing",
    keylogger: "Keylogger",
    dashboard: "Dashboard",
    hide: "Hide"
  },
  ar: {
    appName: "حارس الذكاء الاصطناعي",
    protection: "الحماية",
    riskLevel: "مستوى الخطر",
    
    safeLevel: "آمن",
    mediumLevel: "متوسط",
    suspiciousLevel: "مريب",
    dangerousLevel: "خطر جدًا",
    
    blockedForSafety: "تم حظر الموقع لحمايتك",
    protectionEnabled: "الحماية مفعلة ✅",
    protectionDisabled: "الحماية معطلة ❌",
    enableVirusTotal: "تفعيل فحص VirusTotal",
    apiKeyPlaceholder: "ضع VirusTotal API Key هنا",
    saveSettings: "حفظ الإعدادات",
    settingsSaved: "تم الحفظ ✅",
    clearLog: "مسح السجل",
    totalEvents: "إجمالي الأحداث",
    warnings: "تحذيرات",
    blockedHigh: "حظر عالي المخاطر",
    highRiskDownload: "تحميل مرتفع الخطورة",
    suspiciousExtension: "تم اكتشاف امتداد مريب",
    malwareBlocked: "تم حظر البرمجيات الخبيثة",
    suspiciousDownload: "تحميل مريب",
    virusotalDetected: "تم اكتشافه كضار من قبل VirusTotal",
    hide: "إخفاء",
    timestamp: "الوقت",
    aiScore: "درجة الذكاء الاصطناعي",
    sessionRisk: "خطر الجلسة",
    phishing: "التصيد الاحتيالي",
    keylogger: "مسجل لوحة المفاتيح",
    dashboard: "لوحة التحكم"
  }
};

// Get localization strings
function t(key, locale = 'en') {
  return (I18N[locale] || I18N['en'])[key] || key;
}

// ==================== SECURITY ====================
/**
 * Escape HTML entities to prevent XSS
 */
function escapeHtml(str) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(str).replace(/[&<>"']/g, char => map[char]);
}

/**
 * Validate URL format
 */
function isValidUrl(urlString) {
  try {
    new URL(urlString);
    return true;
  } catch {
    return false;
  }
}

// ==================== STORAGE ====================
/**
 * Get settings with defaults
 */
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
  const stored = await chrome.storage.sync.get(Object.keys(defaults));
  return { ...defaults, ...stored };
}

/**
 * Save settings
 */
async function saveSettings(settings) {
  await chrome.storage.sync.set(settings);
}

/**
 * Add log entry
 */
async function addLog(entry) {
  try {
    entry.ts = Date.now();
    const { logs = [] } = await chrome.storage.local.get(['logs']);
    logs.unshift(entry);
    await chrome.storage.local.set({ logs: logs.slice(0, 500) });
  } catch (error) {
    console.error('[AI Safe Guard] Error adding log:', error);
  }
}

/**
 * Clear all logs
 */
async function clearLogs() {
  try {
    await chrome.storage.local.set({ logs: [] });
  } catch (error) {
    console.error('[AI Safe Guard] Error clearing logs:', error);
  }
}

/**
 * Get all logs
 */
async function getLogs() {
  try {
    const { logs = [] } = await chrome.storage.local.get(['logs']);
    return logs;
  } catch (error) {
    console.error('[AI Safe Guard] Error getting logs:', error);
    return [];
  }
}

// ==================== NOTIFICATIONS ====================
/**
 * Send desktop notification
 */
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
/**
 * Unified logging with levels
 */
const Logger = {
  log(msg, data = null) {
    console.log(`[AI Safe Guard] ${msg}`, data || '');
  },
  info(msg, data = null) {
    console.info(`[AI Safe Guard] INFO: ${msg}`, data || '');
  },
  warn(msg, data = null) {
    console.warn(`[AI Safe Guard] WARN: ${msg}`, data || '');
  },
  error(msg, data = null) {
    console.error(`[AI Safe Guard] ERROR: ${msg}`, data || '');
  }
};

// ==================== FORMAT HELPERS ====================
/**
 * Format timestamp to readable format
 */
function formatTime(timestamp) {
  return new Date(timestamp).toLocaleString();
}

/**
 * Format risk level with color
 */
function getRiskColor(score) {
  if (score >= 85) return '#dc2626'; // Red
  if (score >= 60) return '#f97316'; // Orange
  if (score >= 35) return '#eab308'; // Yellow
  return '#16a34a'; // Green
}

/**
 * Get risk level text
 */
function getRiskText(score) {
  if (score >= 85) return '🟥 Dangerous';
  if (score >= 60) return '🟧 Suspicious';
  if (score >= 35) return '🟨 Medium';
  return '🟩 Safe';
}

// ==================== TIMEOUT/RETRY ====================
/**
 * Retry function with exponential backoff
 */
async function retry(fn, maxAttempts = 3, delayMs = 1000) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      return await fn();
    } catch (error) {
      if (i === maxAttempts - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, delayMs * Math.pow(2, i)));
    }
  }
}

/**
 * Timeout wrapper for promises
 */
function withTimeout(promise, ms = 5000) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Operation timeout')), ms)
    )
  ]);
}

// ==================== BATCH OPERATIONS ====================
/**
 * Simple request debounce
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

/**
 * Thread-safe counter for rate limiting
 */
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

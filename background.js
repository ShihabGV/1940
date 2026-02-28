/**
 * AI Safe Guard - Background Service Worker
 * Handles threat detection, VirusTotal integration, and download monitoring
 */

// ==================== IMPORT UTILS ====================
importScripts('utils.js');

// ==================== INITIALIZATION ====================
console.log('[BG] Service Worker started');

// Rate limiter for API calls (5 requests per 60 seconds)
const vtRateLimiter = new RateLimiter(5, 60000);

// ==================== CONTEXT MENU SETUP ====================
/**
 * Create context menu items for CyberChef-like encoding/decoding
 */
console.log('[BG] Service worker starting - creating context menus');

function setupContextMenus() {
  try {
    // Clear existing menus
    chrome.contextMenus.removeAll();
    console.log('[BG] Cleared old context menus');

    // Parent menu
    chrome.contextMenus.create({
      id: 'security-tools-root',
      title: '🔍 Security Tools',
      contexts: ['selection', 'link', 'page']
    });
    console.log('[BG] Created parent menu: security-tools-root');

    // Base64 Encode
    chrome.contextMenus.create({
      id: 'encode-base64',
      parentId: 'security-tools-root',
      title: '📝 Encode Base64',
      contexts: ['selection']
    });

    // Base64 Decode
    chrome.contextMenus.create({
      id: 'decode-base64',
      parentId: 'security-tools-root',
      title: '📖 Decode Base64',
      contexts: ['selection']
    });

    // URL Encode
    chrome.contextMenus.create({
      id: 'encode-url',
      parentId: 'security-tools-root',
      title: '🔗 Encode URL',
      contexts: ['selection']
    });

    // URL Decode
    chrome.contextMenus.create({
      id: 'decode-url',
      parentId: 'security-tools-root',
      title: '🔓 Decode URL',
      contexts: ['selection']
    });

    // Separator
    chrome.contextMenus.create({
      id: 'separator-1',
      parentId: 'security-tools-root',
      type: 'separator'
    });

    // VirusTotal check
    chrome.contextMenus.create({
      id: 'virustotal-check',
      parentId: 'security-tools-root',
      title: '🦠 Check on VirusTotal',
      contexts: ['link', 'page']
    });

    console.log('[BG] All context menus created successfully');
  } catch (error) {
    console.error('[BG] Error creating context menus:', error);
  }
}

// Setup menus immediately on worker startup
setupContextMenus();

// Also setup on install
chrome.runtime.onInstalled.addListener(() => {
  console.log('[BG] Extension installed/updated - refreshing context menus');
  setupContextMenus();
});

/**
 * Handle context menu clicks
 */
chrome.contextMenus.onClicked.addListener((info, tab) => {
  const text = info.selectionText || '';
  console.log('='.repeat(50));
  console.log('[CONTEXT MENU] CLICKED!');
  console.log('[CONTEXT MENU] Menu ID:', info.menuItemId);
  console.log('[CONTEXT MENU] Selected text:', text.substring(0, 100));
  console.log('[CONTEXT MENU] Link URL:', info.linkUrl);
  console.log('[CONTEXT MENU] Tab URL:', tab?.url);
  console.log('='.repeat(50));
  
  switch(info.menuItemId) {
    case 'encode-base64':
      console.log('[HANDLER] Calling handleBase64Encode');
      handleBase64Encode(text);
      break;
    case 'decode-base64':
      console.log('[HANDLER] Calling handleBase64Decode');
      handleBase64Decode(text);
      break;
    case 'encode-url':
      console.log('[HANDLER] Calling handleURLEncode');
      handleURLEncode(text);
      break;
    case 'decode-url':
      console.log('[HANDLER] Calling handleURLDecode');
      handleURLDecode(text);
      break;
    case 'virustotal-check':
      console.log('[HANDLER] Calling checkUrlOnVirusTotal');
      checkUrlOnVirusTotal(info.linkUrl || tab.url);
      break;
    default:
      console.log('[CONTEXT MENU] Unknown menu ID:', info.menuItemId);
  }
});

/**
 * CyberChef Helper Functions - SIMPLIFIED FOR VISIBILITY
 */
function handleBase64Encode(text) {
  try {
    if (!text || text.length === 0) {
      alert('❌ No text selected. Select text first, then right-click!');
      return;
    }
    
    const encoded = btoa(text);
    console.log('[BG] BASE64 ENCODED:', encoded);
    
    // Try to copy to clipboard
    navigator.clipboard.writeText(encoded).then(() => {
      alert(`✅ Base64 Encoded!\n\n${encoded}\n\n(Copied to clipboard)`);
    }).catch(() => {
      alert(`✅ Base64 Encoded!\n\n${encoded}\n\n(Click to copy: Ctrl+C)`);
    });
  } catch (error) {
    console.error('[BG] Base64 encode error:', error);
    alert('❌ Error: ' + error.message);
  }
}

function handleBase64Decode(text) {
  try {
    if (!text || text.length === 0) {
      alert('❌ No text selected. Select text first, then right-click!');
      return;
    }
    
    const decoded = atob(text);
    console.log('[BG] BASE64 DECODED:', decoded);
    
    navigator.clipboard.writeText(decoded).then(() => {
      alert(`✅ Base64 Decoded!\n\n${decoded}\n\n(Copied to clipboard)`);
    }).catch(() => {
      alert(`✅ Base64 Decoded!\n\n${decoded}\n\n(Click to copy: Ctrl+C)`);
    });
  } catch (error) {
    console.error('[BG] Base64 decode error:', error);
    alert('❌ Error: Invalid Base64 string');
  }
}

function handleURLEncode(text) {
  try {
    if (!text || text.length === 0) {
      alert('❌ No text selected. Select text first, then right-click!');
      return;
    }
    
    const encoded = encodeURIComponent(text);
    console.log('[BG] URL ENCODED:', encoded);
    
    navigator.clipboard.writeText(encoded).then(() => {
      alert(`✅ URL Encoded!\n\n${encoded}\n\n(Copied to clipboard)`);
    }).catch(() => {
      alert(`✅ URL Encoded!\n\n${encoded}\n\n(Click to copy: Ctrl+C)`);
    });
  } catch (error) {
    console.error('[BG] URL encode error:', error);
    alert('❌ Error: ' + error.message);
  }
}

function handleURLDecode(text) {
  try {
    if (!text || text.length === 0) {
      alert('❌ No text selected. Select text first, then right-click!');
      return;
    }
    
    const decoded = decodeURIComponent(text);
    console.log('[BG] URL DECODED:', decoded);
    
    navigator.clipboard.writeText(decoded).then(() => {
      alert(`✅ URL Decoded!\n\n${decoded}\n\n(Copied to clipboard)`);
    }).catch(() => {
      alert(`✅ URL Decoded!\n\n${decoded}\n\n(Click to copy: Ctrl+C)`);
    });
  } catch (error) {
    console.error('[BG] URL decode error:', error);
    alert('❌ Error: Could not decode URL');
  }
}

/**
 * Check URL on VirusTotal
 */
async function checkUrlOnVirusTotal(url) {
  try {
    if (!url || !url.startsWith('http')) {
      url = url || 'unknown';
      alert('❌ Invalid URL: ' + url);
      return;
    }

    console.log('[BG] VirusTotal check starting for:', url);
    
    const settings = await getSettings();
    
    if (!settings.vtEnable || !settings.vtKey) {
      alert('⚠️ VirusTotal not configured!\n\nSet your API key in the popup settings first.');
      console.log('[BG] VT disabled or no API key');
      return;
    }

    alert('🔍 Scanning on VirusTotal...\n\n' + truncateUrl(url, 60));
    console.log('[BG] Scanning URL:', url);
    
    // Use the existing scanUrl function
    const result = await scanUrlWithVirusTotal(url, settings.vtKey);
    
    if (result) {
      console.log('[BG] VT Result:', result);
      const malicious = result.malicious || 0;
      const clean = result.undetected || 0;
      const message = `Detections: ${malicious}\nClean: ${clean}`;
      
      if (malicious > 0) {
        alert(`🚨 THREATS DETECTED!\n\n${message}`);
      } else {
        alert(`✅ No threats detected!\n\n${message}`);
      }
    } else {
      alert('⚠️ Could not get VirusTotal results. Try again.');
    }
  } catch (error) {
    console.error('[BG] VirusTotal check error:', error);
    alert('❌ Error: Could not scan\n\n' + error.message);
  }
}

/**
 * Wrapper function for VirusTotal scanning
 */
async function scanUrlWithVirusTotal(url, apiKey) {
  try {
    return await checkVirusTotal(url, apiKey);
  } catch (error) {
    Logger.error('Scan wrapper error', error);
    return null;
  }
}

// ==================== MESSAGE LISTENER ====================
/**
 * Listen for threat analysis results from content scripts
 */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('[BG] Message received:', msg?.type, 'from', sender?.url);
  
  if (msg?.type !== 'PAGE_FINDINGS') {
    console.log('[BG] Ignoring message, not PAGE_FINDINGS');
    return;
  }

  console.log('[BG] Processing PAGE_FINDINGS:', msg.findings);
  handlePageFindings(msg, sender)
    .catch(error => {
      console.error('[BG] Error handling page findings:', error);
      Logger.error('Error handling page findings', error);
    });
});

/**
 * Handle page findings from content script
 */
async function handlePageFindings(msg, sender) {
  try {
    console.log('[BG] handlePageFindings called');
    const settings = await getSettings();
    console.log('[BG] Settings:', settings);

    // Check if protection is enabled
    if (!settings.protectionEnabled) {
      console.log('[BG] Protection disabled, skipping');
      Logger.log('Protection disabled, skipping analysis');
      return;
    }

    const findings = msg.findings;
    console.log('[BG] Findings:', findings);

    // Calculate composite risk score
    let riskScore = calculateRiskScore(findings);
    console.log('[BG] Calculated risk score:', riskScore);

    // Log the event
    const logEntry = {
      url: findings.url,
      aiScore: findings.aiScore || 0,
      vulnerabilityScore: findings.vulnerabilityScore || 0,
      vulnerabilities: findings.vulnerabilities || {},
      phishing: findings.phishing || {},
      keylogger: findings.keylogger || {},
      sessionRisk: findings.sessionRisk || {},
      finalRisk: riskScore,
      source: 'page_analysis'
    };
    console.log('[BG] About to save log entry:', logEntry);
    
    await addLog(logEntry);
    console.log('[BG] Log saved successfully');

    // Send notification if above threshold
    if (riskScore >= settings.minRiskToWarn) {
      console.log('[BG] Risk above threshold, sending notification');
      sendNotification(
        `⚠️ Security Alert (${riskScore}/100)`,
        truncateUrl(findings.url, 50)
      );
    }

    // Block page if high risk
    if (settings.blockOnHighRisk && riskScore >= settings.minRiskToBlock && sender.tab) {
      blockMaliciousPage(sender.tab.id, findings.url, riskScore);
    }

    Logger.info('Page analyzed', { url: findings.url, risk: riskScore });
  } catch (error) {
    Logger.error('Error in handlePageFindings', error);
  }
}

/**
 * Calculate composite risk score from multiple threat vectors
 */
function calculateRiskScore(findings) {
  let score = findings.aiScore || 50;

  // Vulnerability detection weight (XSS, SQL Injection, CSRF, etc)
  if (findings.vulnerabilityScore && findings.vulnerabilityScore > 0) {
    // Blend vulnerability score with AI score
    const vulnWeight = findings.vulnerabilityScore * 0.4;
    score = Math.min(100, score + vulnWeight);
    
    // If high vulnerability detected, escalate warning
    if (findings.vulnerabilityScore >= 50) {
      score = Math.max(score, 75);
    }
  }

  // Phishing detection weight
  if (findings.phishing?.suspicious) {
    score = Math.max(score, 90);
  }

  // Keylogger detection weight
  if (findings.keylogger?.suspicious) {
    score = Math.max(score, 80);
  }

  // Session risk weight
  const sessionRiskScore = (findings.sessionRisk?.score || 0) * 0.3;
  score = Math.min(100, score + Math.round(sessionRiskScore));

  return Math.min(100, Math.max(0, score));
}

/**
 * Block a malicious page by replacing with warning page
 */
function blockMaliciousPage(tabId, url, riskScore) {
  try {
    const warningPage = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8" />
        <title>AI Safe Guard - Blocked</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            color: #f1f5f9;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
          }
          .container {
            max-width: 600px;
            background: rgba(30, 41, 59, 0.8);
            border: 2px solid #dc2626;
            border-radius: 12px;
            padding: 40px;
            text-align: center;
            backdrop-filter: blur(10px);
          }
          .icon {
            font-size: 64px;
            margin-bottom: 20px;
          }
          h1 {
            font-size: 24px;
            margin-bottom: 10px;
            color: #fca5a5;
          }
          .risk-score {
            display: inline-block;
            padding: 10px 20px;
            background: rgba(220, 38, 38, 0.2);
            border: 1px solid rgba(220, 38, 38, 0.5);
            border-radius: 8px;
            margin: 20px 0;
            font-size: 18px;
            font-weight: 600;
            color: #fca5a5;
          }
          .details {
            background: rgba(15, 23, 42, 0.5);
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            font-size: 13px;
            line-height: 1.6;
            text-align: left;
            color: #cbd5e1;
            word-break: break-all;
          }
          .warning {
            color: #fbbf24;
            margin: 20px 0;
            font-size: 13px;
          }
          .action-buttons {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            justify-content: center;
          }
          button {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.2s;
          }
          .btn-back {
            background: rgba(59, 130, 246, 0.2);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.4);
          }
          .btn-back:hover {
            background: rgba(59, 130, 246, 0.3);
          }
          .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(148, 163, 184, 0.2);
            font-size: 12px;
            color: #64748b;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="icon">🚫</div>
          <h1>This site is blocked</h1>
          <p>AI Safe Guard blocked this page for your safety</p>
          <div class="risk-score">Risk Level: ${riskScore}/100</div>
          <div class="details">
            <strong>URL:</strong><br />
            ${escapeHtml(url)}
          </div>
          <div class="warning">⚠️ Proceed only if you are certain this site is safe</div>
          <div class="action-buttons">
            <button class="btn-back" onclick="history.back()">← Go Back</button>
          </div>
          <div class="footer">
            Protected by AI Safe Guard | Risk Score: ${riskScore}/100
          </div>
        </div>
      </body>
      </html>
    `;

    const dataUrl = `data:text/html;charset=utf-8,${encodeURIComponent(warningPage)}`;
    chrome.tabs.update(tabId, { url: dataUrl });
    Logger.warn('Malicious page blocked', { url, risk: riskScore });
  } catch (error) {
    Logger.error('Error blocking page', error);
  }
}

/**
 * Truncate URL for display
 */
function truncateUrl(url, maxLength = 50) {
  return url.length > maxLength ? url.substring(0, maxLength) + '...' : url;
}

// ==================== DOWNLOAD MONITORING ====================
const RISKY_DOWNLOAD_EXTENSIONS = [
  '.exe', '.msi', '.bat', '.cmd', '.scr', '.ps1',
  '.vbs', '.js', '.jar', '.apk', '.iso', '.img',
  '.dll', '.com', '.pif', '.zip', '.rar', '.7z'
];

/**
 * Monitor downloads for threats
 */
chrome.downloads.onCreated.addListener((item) => {
  handleDownload(item).catch(error => {
    Logger.error('Error handling download', error);
  });
});

/**
 * Handle download security check
 */
async function handleDownload(item) {
  try {
    const settings = await getSettings();

    if (!settings.protectionEnabled) {
      Logger.log('Protection disabled, skipping download check');
      return;
    }

    const url = item.finalUrl || item.url || '';
    const filename = (item.filename || '').toLowerCase();

    Logger.log('Download started', { filename, url });

    // Check file extension
    const hasRiskyExtension = RISKY_DOWNLOAD_EXTENSIONS.some(ext =>
      filename.endsWith(ext)
    );

    if (hasRiskyExtension) {
      Logger.warn('Risky file extension detected', filename);
      sendNotification(
        '⚠️ Suspicious Download Detected',
        `File: ${filename}`
      );

      // Add to logs
      await addLog({
        url,
        type: 'suspicious_download',
        filename,
        finalRisk: 75,
        source: 'download_monitor'
      });
    }

    // Check with VirusTotal if enabled
    if (settings.vtEnable && settings.vtKey && url.startsWith('http')) {
      if (!vtRateLimiter.canMakeRequest()) {
        Logger.warn('VirusTotal rate limit reached');
        return;
      }

      try {
        const verdict = await checkVirusTotal(url, settings.vtKey);
        await addLog({
          url,
          type: 'virustotal_scan',
          filename,
          verdict,
          finalRisk: calculateVTRisk(verdict),
          source: 'virustotal'
        });

        if (verdict.malicious >= 1) {
          Logger.error('Malware detected by VirusTotal', url);
          sendNotification(
            '🛑 MALWARE BLOCKED',
            `${filename}\n${verdict.malicious} vendors detected malware`
          );

          // Cancel and erase the download
          try {
            await chrome.downloads.cancel(item.id);
            await chrome.downloads.erase({ id: item.id });
            Logger.info('Malicious download cancelled and erased');
          } catch (e) {
            Logger.warn('Could not erase download', e.message);
          }
        } else if (verdict.suspicious >= 1) {
          Logger.warn('Suspicious file detected by VirusTotal', url);
          sendNotification(
            '⚠️ Suspicious Download',
            `${filename}\n${verdict.suspicious} vendors marked as suspicious`
          );
        }
      } catch (error) {
        Logger.error('VirusTotal check failed', error);
      }
    }
  } catch (error) {
    Logger.error('Error in handleDownload', error);
  }
}

/**
 * Calculate risk score from VirusTotal verdict
 */
function calculateVTRisk(verdict) {
  const { malicious = 0, suspicious = 0, undetected = 0 } = verdict;
  
  if (malicious >= 5) return 100;
  if (malicious >= 1) return 90;
  if (suspicious >= 3) return 75;
  if (suspicious >= 1) return 65;
  if (undetected >= 10) return 45;
  
  return 20; // Safe
}

// ==================== VIRUSTOTAL API ====================

/**
 * Check URL against VirusTotal
 */
async function checkVirusTotal(url, apiKey) {
  try {
    Logger.log('VirusTotal: Submitting URL for analysis');

    // Submit URL
    const submitRes = await withTimeout(
      fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: 'url=' + encodeURIComponent(url)
      }),
      8000
    );

    if (!submitRes.ok) {
      const errorMsg = await (submitRes.text().catch(() => 'Unknown error'));
      throw new Error(`VirusTotal submission failed: ${submitRes.status}`);
    }

    const submitData = await submitRes.json();
    const analysisId = submitData?.data?.id;

    if (!analysisId) {
      throw new Error('No analysis ID returned from VirusTotal');
    }

    Logger.log('VirusTotal: Analysis submitted', analysisId);

    // Poll for results (up to 3 attempts with 2 second delays)
    for (let attempt = 0; attempt < 3; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 2000));

      try {
        const resultRes = await withTimeout(
          fetch(
            `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
            { headers: { 'x-apikey': apiKey } }
          ),
          8000
        );

        if (!resultRes.ok) continue;

        const resultData = await resultRes.json();
        const status = resultData?.data?.attributes?.status;
        const stats = resultData?.data?.attributes?.stats;

        if (status === 'completed' && stats) {
          Logger.info('VirusTotal: Analysis complete', stats);
          return {
            harmless: stats.harmless || 0,
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            undetected: stats.undetected || 0,
            timeout: stats.timeout || 0
          };
        }
      } catch (pollError) {
        Logger.warn(`VirusTotal poll attempt ${attempt + 1} failed`, pollError.message);
      }
    }

    // Return empty verdict if no response
    Logger.warn('VirusTotal: Analysis not completed in time');
    return { harmless: 0, malicious: 0, suspicious: 0, undetected: 0, timeout: 0 };
  } catch (error) {
    Logger.error('VirusTotal API error', error);
    throw error;
  }
}

// ==================== CLEANUP & MAINTENANCE ====================

/**
 * Periodic cleanup of old logs
 */
async function cleanupLogs() {
  try {
    const { logs = [] } = await chrome.storage.local.get(['logs']);
    if (logs.length > 500) {
      await chrome.storage.local.set({ logs: logs.slice(0, 500) });
      console.log('[BG] Logs cleaned up');
    }
  } catch (error) {
    console.error('[BG] Error cleaning logs:', error);
  }
}

console.log('[BG] Background worker initialization complete');

Logger.log('AI Safe Guard background worker initialized successfully');  
/**
 * AI Safe Guard - Dashboard Script
 * Displays security logs and statistics
 */

const LOGS_PER_PAGE = 25;
let allLogs = [];
let currentPage = 1;
let autoRefreshInterval = null;

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', async () => {
  try {
    console.log('[Dashboard] ========== INITIALIZING ==========');
    console.log('[Dashboard] Checking for getLogs:', typeof getLogs);
    
    // Direct storage check
    console.log('[Dashboard] Checking chrome storage directly...');
    const storageData = await chrome.storage.local.get(null);
    console.log('[Dashboard] ALL storage data:', storageData);
    console.log('[Dashboard] Logs array:', storageData.logs);
    console.log('[Dashboard] Number of logs in storage:', storageData.logs ? storageData.logs.length : 0);
    
    // Load initial data
    await loadLogs();
    updateStatistics();

    // Event listeners
    const clearBtn = document.getElementById('clearBtn');
    const exportBtn = document.getElementById('exportBtn');
    const autoRefreshBtn = document.getElementById('autoRefreshBtn');
    
    console.log('[Dashboard] Buttons found:', { clearBtn, exportBtn, autoRefreshBtn });
    
    if (clearBtn) clearBtn.addEventListener('click', handleClearLogs);
    if (exportBtn) exportBtn.addEventListener('click', handleExportLogs);
    if (autoRefreshBtn) autoRefreshBtn.addEventListener('click', toggleAutoRefresh);

    // Auto-load new logs periodically if not already auto-refreshing
    setInterval(loadLogs, 5000); // Check every 5 seconds
    
    console.log('[Dashboard] Initialization complete');
  } catch (error) {
    console.error('[Dashboard] Initialization error:', error);
    showError('Failed to initialize dashboard: ' + error.message);
  }
});

// ==================== DATA LOADING ====================

/**
 * Load logs from storage
 */
async function loadLogs() {
  try {
    console.log('[Dashboard] loadLogs called');
    const logs = await getLogs();
    console.log('[Dashboard] Logs retrieved:', logs);
    console.log('[Dashboard] Number of logs:', logs ? logs.length : 0);
    
    allLogs = logs || [];
    currentPage = 1; // Reset to first page
    
    console.log('[Dashboard] About to render logs table');
    renderLogsTable();
    updateStatistics();
    console.log('[Dashboard] Logs loaded successfully');
  } catch (error) {
    console.error('[Dashboard] Error loading logs:', error);
    showError('Failed to load logs: ' + error.message);
  }
}

/**
 * Update statistics display
 */
function updateStatistics() {
  const safe = allLogs.filter(log => log.finalRisk < 35).length;
  const medium = allLogs.filter(log => log.finalRisk >= 35 && log.finalRisk < 60).length;
  const suspicious = allLogs.filter(log => log.finalRisk >= 60 && log.finalRisk < 85).length;
  const dangerous = allLogs.filter(log => log.finalRisk >= 85).length;

  document.getElementById('totalEvents').textContent = allLogs.length.toLocaleString();
  document.getElementById('safeCount').textContent = safe;
  document.getElementById('mediumCount').textContent = medium;
  document.getElementById('suspiciousCount').textContent = suspicious;
  document.getElementById('dangerousCount').textContent = dangerous;
}

// ==================== TABLE RENDERING ====================

/**
 * Render logs table with pagination
 */
function renderLogsTable() {
  const container = document.getElementById('logsContainer');

  if (allLogs.length === 0) {
    container.innerHTML = '<div class="logs-empty">No security events recorded yet</div>';
    return;
  }

  // Calculate pagination
  const totalPages = Math.ceil(allLogs.length / LOGS_PER_PAGE);
  currentPage = Math.max(1, Math.min(currentPage, totalPages));

  const startIndex = (currentPage - 1) * LOGS_PER_PAGE;
  const endIndex = startIndex + LOGS_PER_PAGE;
  const pageLogs = allLogs.slice(startIndex, endIndex);

  // Build table HTML
  let html = `
    <table>
      <thead>
        <tr>
          <th style="width: 70px;">Risk</th>
          <th style="width: 180px;">Time</th>
          <th style="flex: 1;">URL</th>
          <th style="width: 80px;">AI Score</th>
          <th style="width: 60px;">Details</th>
        </tr>
      </thead>
      <tbody>
  `;

  pageLogs.forEach((log, index) => {
    const riskBadge = getRiskBadge(log.finalRisk);
    const time = formatTime(log.ts);
    const url = escapeHtml(log.url || '(Unknown)');
    const logId = `log-${startIndex + index}`;

    html += `
      <tr>
        <td>
          <span class="risk-badge ${riskBadge.className}">${log.finalRisk}/100</span>
        </td>
        <td class="time-cell">${time}</td>
        <td class="url-cell" title="${log.url || ''}">${url}</td>
        <td>${log.aiScore || '-'}</td>
        <td style="text-align: center;">
          <button style="
            padding: 4px 8px;
            background: rgba(59, 130, 246, 0.2);
            color: #93c5fd;
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;"
            onclick="toggleDetails('${logId}')">
            ▼
          </button>
        </td>
      </tr>
      <tr id="${logId}-details" class="details-row">
        <td colspan="5">
          <div class="detail-item">
            <span>URL:</span>
            <span style="color: #93c5fd; word-break: break-all;">${url}</span>
          </div>
          <div class="detail-item">
            <span>AI Score:</span>
            <span>${log.aiScore || 'N/A'}</span>
          </div>
          ${log.phishing ? `<div class="detail-item">
            <span>Phishing Detected:</span>
            <span>${log.phishing.suspicious ? '⚠️ Yes' : '✓ No'}</span>
          </div>` : ''}
          ${log.keylogger ? `<div class="detail-item">
            <span>Keylogger Detected:</span>
            <span>${log.keylogger.suspicious ? '⚠️ Yes' : '✓ No'}</span>
          </div>` : ''}
          ${log.sessionRisk ? `<div class="detail-item">
            <span>Session Risk:</span>
            <span>${log.sessionRisk.score || 0}/100</span>
          </div>` : ''}
          <div class="detail-item">
            <span>Source:</span>
            <span>${log.source || 'Unknown'}</span>
          </div>
        </td>
      </tr>
    `;
  });

  html += '</tbody></table>';

  // Add pagination controls
  if (totalPages > 1) {
    html += `
      <div class="page-info">
        Page ${currentPage} of ${totalPages} (${allLogs.length} total events)
      </div>
      <div class="pagination">
        <button ${currentPage === 1 ? 'disabled' : ''} onclick="goToPage(1)">⏮ First</button>
        <button ${currentPage === 1 ? 'disabled' : ''} onclick="goToPage(${currentPage - 1})">◀ Prev</button>
        <span style="color: #cbd5e1; display: flex; align-items: center; padding: 0 12px;">
          Page ${currentPage}
        </span>
        <button ${currentPage === totalPages ? 'disabled' : ''} onclick="goToPage(${currentPage + 1})">Next ▶</button>
        <button ${currentPage === totalPages ? 'disabled' : ''} onclick="goToPage(${totalPages})">Last ⏭</button>
      </div>
    `;
  }

  container.innerHTML = html;
}

/**
 * Get risk badge styling
 */
function getRiskBadge(risk) {
  if (risk >= 85) return { className: 'dangerous', text: '🔴 Dangerous' };
  if (risk >= 60) return { className: 'suspicious', text: '🟠 Suspicious' };
  if (risk >= 35) return { className: 'medium', text: '🟡 Medium' };
  return { className: 'safe', text: '🟢 Safe' };
}

/**
 * Toggle details row visibility
 */
function toggleDetails(logId) {
  const detailsRow = document.getElementById(logId + '-details');
  if (detailsRow) {
    detailsRow.classList.toggle('shown');
  }
}

/**
 * Navigate to specific page
 */
function goToPage(page) {
  currentPage = page;
  renderLogsTable();
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ==================== ACTIONS ====================

/**
 * Handle clear logs action
 */
async function handleClearLogs() {
  if (!confirm('⚠️ Are you sure you want to clear all logs? This cannot be undone.')) {
    return;
  }

  try {
    await clearLogs();
    allLogs = [];
    currentPage = 1;
    renderLogsTable();
    updateStatistics();
    Logger.log('All logs cleared');
  } catch (error) {
    Logger.error('Error clearing logs', error);
    showError('Failed to clear logs');
  }
}

/**
 * Handle export logs to JSON
 */
function handleExportLogs() {
  if (allLogs.length === 0) {
    alert('No logs to export');
    return;
  }

  try {
    const dataStr = JSON.stringify(allLogs, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `ai-safeguard-logs-${new Date().toISOString()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    Logger.log('Logs exported successfully');
  } catch (error) {
    Logger.error('Error exporting logs', error);
    showError('Failed to export logs');
  }
}

/**
 * Toggle auto-refresh
 */
function toggleAutoRefresh() {
  const btn = document.getElementById('autoRefreshBtn');

  if (autoRefreshInterval) {
    clearInterval(autoRefreshInterval);
    autoRefreshInterval = null;
    btn.style.background = 'rgba(59, 130, 246, 0.15)';
    btn.style.color = '#93c5fd';
    Logger.log('Auto-refresh disabled');
  } else {
    autoRefreshInterval = setInterval(loadLogs, 2000); // Refresh every 2 seconds
    btn.style.background = 'rgba(16, 185, 129, 0.2)';
    btn.style.color = '#10b981';
    Logger.log('Auto-refresh enabled');
  }
}

// ==================== UTILITY ====================

/**
 * Show error message
 */
function showError(message) {
  const container = document.getElementById('logsContainer');
  container.innerHTML = `
    <div style="
      background: rgba(239, 68, 68, 0.2);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 16px;
      color: #fca5a5;
      text-align: center;">
      ❌ ${escapeHtml(message)}
    </div>
  `;
}
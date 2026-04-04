/**
 * AI Safe Guard - Dashboard Script
 * Completely overhauled for reliability and explicit initialization
 */

<<<<<<< HEAD
(function() {
  'use strict';
=======
const LOGS_PER_PAGE = 25;
let allLogs = [];
let currentPage = 1;
let autoRefreshInterval = null;
let threatChart = null;
>>>>>>> e74b18a6c6e47e4346a033fa43a571441cc0185e

  const LOGS_PER_PAGE = 25;
  let allLogs = [];
  let currentPage = 1;
  let autoRefreshInterval = null;
  let threatChart = null;

<<<<<<< HEAD
  /**
   * Safe retrieval of global utilities
   */
  function getUtil(name) {
    if (window[name]) return window[name];
    if (typeof window[name] === 'function') return window[name];
    console.warn(`[Dashboard] Utility ${name} not found in global scope`);
    return null;
=======
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
    initChart();

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
    updateChart();
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
>>>>>>> e74b18a6c6e47e4346a033fa43a571441cc0185e
  }

  /**
   * Initialize everything
   */
  async function init() {
    console.log('[Dashboard] Initializing Dashboard...');
    
    try {
      // 1. Setup UI Elements
      const clearBtn = document.getElementById('clearBtn');
      const exportBtn = document.getElementById('exportBtn');
      const autoRefreshBtn = document.getElementById('autoRefreshBtn');
      
      if (clearBtn) clearBtn.onclick = handleClearLogs;
      if (exportBtn) exportBtn.onclick = handleExportLogs;
      if (autoRefreshBtn) autoRefreshBtn.onclick = toggleAutoRefresh;

      // 2. Load Initial Data
      await loadData();

      // 3. Initialize Chart
      initChart();
      updateChart();

      // 4. Start Refresh Loop
      setInterval(loadData, 5000);
      
      console.log('[Dashboard] Initialization complete');
    } catch (error) {
      console.error('[Dashboard] Initialization error:', error);
      showError('Initialization Error: ' + error.message);
    }
  }

  /**
   * Load data from storage
   */
  async function loadData() {
    const getLogsFn = getUtil('getLogs');
    if (!getLogsFn) return;

    try {
      const logs = await getLogsFn();
      allLogs = Array.isArray(logs) ? logs : [];
      console.log(`[Dashboard] Loaded ${allLogs.length} logs`);
      
      updateStatistics();
      renderTable();
      updateChart();
    } catch (error) {
      console.error('[Dashboard] Error loading data:', error);
    }
  }

  /**
   * Update stats cards
   */
  function updateStatistics() {
    const safe = allLogs.filter(l => (l.finalRisk || 0) < 35).length;
    const medium = allLogs.filter(l => (l.finalRisk || 0) >= 35 && (l.finalRisk || 0) < 60).length;
    const suspicious = allLogs.filter(l => (l.finalRisk || 0) >= 60 && (l.finalRisk || 0) < 85).length;
    const dangerous = allLogs.filter(l => (l.finalRisk || 0) >= 85).length;

    const set = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val.toLocaleString();
    };

    set('totalEvents', allLogs.length);
    set('safeCount', safe);
    set('mediumCount', medium);
    set('suspiciousCount', suspicious);
    set('dangerousCount', dangerous);
  }

  /**
   * Render the logs table
   */
  function renderTable() {
    const container = document.getElementById('logsContainer');
    if (!container) return;

    if (allLogs.length === 0) {
      container.innerHTML = '<div class="logs-empty">No security events recorded yet</div>';
      return;
    }

    const totalPages = Math.ceil(allLogs.length / LOGS_PER_PAGE);
    currentPage = Math.max(1, Math.min(currentPage, totalPages));
    const startIndex = (currentPage - 1) * LOGS_PER_PAGE;
    const pageLogs = allLogs.slice(startIndex, startIndex + LOGS_PER_PAGE);

    const esc = getUtil('escapeHtml') || (s => s);
    const fmt = getUtil('formatTime') || (t => new Date(t).toLocaleString());

    let html = `
      <table>
        <thead>
          <tr>
            <th style="width: 100px;">Risk</th>
            <th style="width: 180px;">Time</th>
            <th>URL</th>
            <th style="width: 80px;">Score</th>
            <th style="width: 60px;">Info</th>
          </tr>
        </thead>
        <tbody>
    `;

    pageLogs.forEach((log, idx) => {
      const risk = log.finalRisk || 0;
      let cls = 'safe';
      if (risk >= 85) cls = 'dangerous';
      else if (risk >= 60) cls = 'suspicious';
      else if (risk >= 35) cls = 'medium';

      const logId = `log-${startIndex + idx}`;
      const url = esc(log.url || 'Unknown');

      html += `
        <tr>
          <td><span class="risk-badge ${cls}">${risk}/100</span></td>
          <td class="time-cell">${fmt(log.ts)}</td>
          <td class="url-cell" title="${url}">${url}</td>
          <td>${log.aiScore || '-'}</td>
          <td style="text-align: center;">
            <button style="padding: 4px 8px; background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 4px; cursor: pointer;"
                    onclick="window.toggleDetails('${logId}')">▼</button>
          </td>
        </tr>
        <tr id="${logId}-details" class="details-row">
          <td colspan="5">
            <div class="detail-container">
              <div class="detail-item"><span>URL:</span><span style="color: #93c5fd; word-break: break-all;">${url}</span></div>
              <div class="detail-item"><span>AI Score:</span><span>${log.aiScore || 'N/A'}</span></div>
              ${log.reasons && log.reasons.length > 0 ? `
                <div class="detail-item" style="display: block; margin-top: 10px; border-top: 1px solid rgba(148, 163, 184, 0.1); padding-top: 10px;">
                  <div style="font-weight: 600; color: #fca5a5; margin-bottom: 5px;">Risk Reasons:</div>
                  <ul style="margin-left: 20px; color: #cbd5e1;">
                    ${log.reasons.map(r => `<li>${esc(r)}</li>`).join('')}
                  </ul>
                </div>
              ` : ''}
              <div class="detail-item"><span>Source:</span><span>${log.source || 'Unknown'}</span></div>
            </div>
          </td>
        </tr>
      `;
    });

    html += '</tbody></table>';

<<<<<<< HEAD
    if (totalPages > 1) {
      html += `
        <div class="page-info">Page ${currentPage} of ${totalPages}</div>
        <div class="pagination">
          <button ${currentPage === 1 ? 'disabled' : ''} onclick="window.goToPage(1)">First</button>
          <button ${currentPage === 1 ? 'disabled' : ''} onclick="window.goToPage(${currentPage - 1})">Prev</button>
          <button ${currentPage === totalPages ? 'disabled' : ''} onclick="window.goToPage(${currentPage + 1})">Next</button>
          <button ${currentPage === totalPages ? 'disabled' : ''} onclick="window.goToPage(${totalPages})">Last</button>
        </div>
      `;
    }
=======
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
          ${log.reasons && log.reasons.length > 0 ? `
          <div class="detail-item" style="display: block; margin-top: 10px; border-top: 1px solid rgba(148, 163, 184, 0.1); padding-top: 10px;">
            <div style="font-weight: 600; color: #fca5a5; margin-bottom: 5px;">Risk Reasons:</div>
            <ul style="margin-left: 20px; color: #cbd5e1;">
              ${log.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
            </ul>
          </div>` : ''}
          <div class="detail-item">
            <span>Source:</span>
            <span>${log.source || 'Unknown'}</span>
          </div>
        </td>
      </tr>
    `;
  });
>>>>>>> e74b18a6c6e47e4346a033fa43a571441cc0185e

    container.innerHTML = html;
  }

  /**
   * Initialize Chart.js
   */
  function initChart() {
    const ctx = document.getElementById('threatChart');
    if (!ctx || typeof Chart === 'undefined') return;

    threatChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'Threats',
          data: [],
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { color: '#94a3b8', stepSize: 1 } },
          x: { ticks: { color: '#94a3b8' } }
        }
      }
    });
  }

  /**
   * Update Chart data
   */
  function updateChart() {
    if (!threatChart || allLogs.length === 0) return;
    const threats = allLogs.filter(l => (l.finalRisk || 0) >= 60);
    const now = Date.now();
    const hourMs = 3600000;
    const labels = [];
    const data = [];

    for (let i = 11; i >= 0; i--) {
      const end = now - i * hourMs;
      const start = end - hourMs;
      const count = threats.filter(l => l.ts >= start && l.ts < end).length;
      labels.push(new Date(end).getHours().toString().padStart(2, '0') + ':00');
      data.push(count);
    }

    threatChart.data.labels = labels;
    threatChart.data.datasets[0].data = data;
    threatChart.update();
  }

  /**
   * Actions
   */
  async function handleClearLogs() {
    if (confirm('Clear all security logs?')) {
      const clearFn = getUtil('clearLogs');
      if (clearFn) {
        await clearFn();
        allLogs = [];
        renderTable();
        updateStatistics();
      }
    }
  }

  function handleExportLogs() {
    if (allLogs.length === 0) return;
    const blob = new Blob([JSON.stringify(allLogs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ai-safeguard-logs-${Date.now()}.json`;
    a.click();
  }

  function toggleAutoRefresh() {
    const btn = document.getElementById('autoRefreshBtn');
    if (autoRefreshInterval) {
      clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
      btn.style.background = '';
      btn.textContent = '🔄 Auto Refresh';
    } else {
      autoRefreshInterval = setInterval(loadData, 2000);
      btn.style.background = 'rgba(16, 185, 129, 0.2)';
      btn.textContent = '⏸ Stop Refresh';
    }
  }

  function showError(msg) {
    const container = document.getElementById('logsContainer');
    if (container) {
      container.innerHTML = `<div style="color: #ef4444; text-align: center; padding: 40px;">❌ ${msg}</div>`;
    }
  }

  // Global Helpers
  window.toggleDetails = (id) => {
    const el = document.getElementById(id + '-details');
    if (el) el.classList.toggle('shown');
  };

  window.goToPage = (p) => {
    currentPage = p;
    renderTable();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Run Init
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

<<<<<<< HEAD
})();
=======
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
/**
 * Initialize the threat activity chart
 */
function initChart() {
  const ctx = document.getElementById('threatChart');
  if (!ctx) return;

  threatChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Security Threats',
        data: [],
        borderColor: '#ef4444',
        backgroundColor: 'rgba(239, 68, 68, 0.1)',
        borderWidth: 2,
        fill: true,
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(148, 163, 184, 0.1)' },
          ticks: { color: '#94a3b8', stepSize: 1 }
        },
        x: {
          grid: { display: false },
          ticks: { color: '#94a3b8' }
        }
      }
    }
  });
}

/**
 * Update chart data based on logs
 */
function updateChart() {
  if (!threatChart || allLogs.length === 0) return;

  // Group logs by time (last 12 intervals)
  const threatsOnly = allLogs.filter(l => l.finalRisk >= 60);
  const now = Date.now();
  const hourMs = 3600000;
  const labels = [];
  const data = [];

  for (let i = 11; i >= 0; i--) {
    const timeStart = now - (i + 1) * hourMs;
    const timeEnd = now - i * hourMs;
    const count = threatsOnly.filter(l => l.ts >= timeStart && l.ts < timeEnd).length;
    
    const timeLabel = new Date(timeEnd).getHours() + ':00';
    labels.push(timeLabel);
    data.push(count);
  }

  threatChart.data.labels = labels;
  threatChart.data.datasets[0].data = data;
  threatChart.update();
}
>>>>>>> e74b18a6c6e47e4346a033fa43a571441cc0185e

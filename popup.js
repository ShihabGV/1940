/** AI Safe Guard - Popup Script */

document.addEventListener('DOMContentLoaded', async () => {
  try {
    // DOM Elements
    const protectionToggle = document.getElementById('protectionToggle');
    const statusBadge = document.getElementById('statusBadge');
    const vtEnable = document.getElementById('vtEnable');
    const vtKey = document.getElementById('vtKey');
    const saveBtn = document.getElementById('saveBtn');
    const feedback = document.getElementById('feedback');
    const eventCount = document.getElementById('eventCount');
    const riskCount = document.getElementById('riskCount');

    // Load current settings
    const settings = await getSettings();

    // Populate UI with settings
    protectionToggle.classList.toggle('disabled', !settings.protectionEnabled);
    vtEnable.checked = settings.vtEnable || false;
    vtKey.value = settings.vtKey || '';

    updateStatusUI(settings.protectionEnabled);
    updateStats();

    // Protection toggle
    protectionToggle.addEventListener('click', async () => {
      const newState = !settings.protectionEnabled;
      await saveSettings({ protectionEnabled: newState });
      settings.protectionEnabled = newState;
      protectionToggle.classList.toggle('disabled');
      updateStatusUI(newState);
      showFeedback('Protection ' + (newState ? 'enabled' : 'disabled'), 'success');
    });

    // Save VirusTotal settings
    saveBtn.addEventListener('click', async () => {
      try {
        const key = vtKey.value.trim();

        // Validation
        if (vtEnable.checked && !key) {
          showFeedback('Please enter a VirusTotal API key', 'error');
          return;
        }

        if (key && key.length < 20) {
          showFeedback('API key seems too short', 'error');
          return;
        }

        // Save to storage
        await saveSettings({
          vtEnable: vtEnable.checked,
          vtKey: key
        });

        // Update local settings
        settings.vtEnable = vtEnable.checked;
        settings.vtKey = key;

        showFeedback('✅ Settings saved successfully', 'success');
        Logger.info('Settings saved:', { vtEnabled: vtEnable.checked, keyLength: key.length });
      } catch (error) {
        Logger.error('Error saving settings', error);
        showFeedback('Error saving settings', 'error');
      }
    });

    // Show/hide API key
    vtKey.addEventListener('focus', function () {
      this.type = 'text';
    });

    vtKey.addEventListener('blur', function () {
      this.type = 'password';
    });

  } catch (error) {
    Logger.error('Popup initialization error', error);
    document.getElementById('feedback').textContent = 'Initialization error';
    document.getElementById('feedback').className = 'feedback-message error';
    document.getElementById('feedback').style.display = 'block';
  }
});

/**
 * Update status UI based on protection state
 */
function updateStatusUI(isEnabled) {
  const badge = document.getElementById('statusBadge');
  if (isEnabled) {
    badge.textContent = '✅ Protection Enabled';
    badge.classList.remove('disabled');
  } else {
    badge.textContent = '⚠️ Protection Disabled';
    badge.classList.add('disabled');
  }
}

/**
 * Update statistics display
 */
async function updateStats() {
  try {
    const logs = await getLogs();
    const totalEvents = logs.length;
    const threats = logs.filter(log => log.finalRisk && log.finalRisk >= 60).length;

    document.getElementById('eventCount').textContent = totalEvents;
    document.getElementById('riskCount').textContent = threats;
  } catch (error) {
    Logger.error('Error updating stats', error);
  }
}

/**
 * Show feedback message
 */
function showFeedback(message, type = 'success') {
  const feedback = document.getElementById('feedback');
  feedback.textContent = message;
  feedback.className = `feedback-message ${type}`;
  feedback.style.display = 'block';

  // Auto-hide success messages
  if (type === 'success') {
    setTimeout(() => {
      feedback.style.display = 'none';
    }, 2500);
  }
}
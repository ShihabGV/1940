================================================================================
                    AI SAFE GUARD - CHROME EXTENSION
                         Complete Documentation
================================================================================

WHAT IS THIS EXTENSION?
=======================
AI Safe Guard is a browser security extension that:
- Analyzes websites in REAL-TIME to detect threats
- Shows a color-coded security bar at the top of every website
- Detects vulnerabilities (XSS, SQL Injection, CSRF, Clickjacking)
- Integrates with VirusTotal to scan URLs for malware
- Provides encoding/decoding tools via right-click context menu
- Logs all security events to a dashboard
- Blocks dangerous websites automatically

HOW IT WORKS:
=============
When you visit a website:
1. The extension analyzes the URL
2. AI model checks for phishing/malware indicators
3. Vulnerability scanner checks for web security issues
4. Security bar appears at top showing threat level:
   - GREEN (🟩) = SAFE (Score 0-34)
   - YELLOW (🟨) = MEDIUM (Score 35-59)
   - ORANGE (🟧) = SUSPICIOUS (Score 60-84)
   - RED (🟥) = DANGEROUS (Score 85-100)
5. All results saved to dashboard logs

FILE STRUCTURE & WHAT EACH FILE DOES:
=====================================

📋 manifest.json
   WHAT IT DOES:
   - Extension configuration file (Chrome Manifest V3)
   - Tells Chrome what permissions the extension needs
   - Lists all scripts and resources
   - Configures the extension name, version, icons
   
   MAIN SECTIONS:
   - "manifest_version": 3 (latest Chrome standard)
   - "permissions": Allows access to tabs, storage, notifications, contextMenus, downloads
   - "background": Service worker that runs always (background.js)
   - "content_scripts": Scripts injected into websites (utils.js, ai_model.js, vuln_scanner.js, content.js)
   - "web_accessible_resources": Images and files accessible from websites

   KEY SETTINGS:
   - run_at: "document_idle" (waits for page to fully load before analyzing)
   - matches: ["<all_urls>"] (works on every website)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔧 utils.js
   WHAT IT DOES:
   - Shared utility functions used by all other scripts
   - Handles logging to storage
   - Sends browser notifications
   - Manages settings (VirusTotal API key, thresholds, etc)
   - Rate limiting for API calls
   
   MAIN FUNCTIONS:
   - addLog(entry) → Saves security event to storage (max 500 entries)
   - getLogs() → Retrieves all saved security events
   - clearLogs() → Deletes all logs
   - sendNotification(title, message) → Shows desktop notification
   - getSettings() → Gets extension settings from Chrome storage
   - Logger.log, Logger.warn, Logger.error, Logger.info → Console logging with prefixes

   HOW IT'S USED:
   - Background.js imports this first (before anything else)
   - Content scripts can call sendNotification() or addLog()
   - Dashboard reads logs via getLogs()

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧠 ai_model.js
   WHAT IT DOES:
   - Machine learning threat detection
   - Analyzes URLs to calculate risk score (0-100)
   - Checks for 10 different threat indicators
   
   THREAT INDICATORS (10 factors checked):
   1. has_ip (2.2 weight) → URL is direct IP address (phishing indicator)
   2. http_only (1.5 weight) → No HTTPS (data exposure risk)
   3. long_host (1.1 weight) → Very long hostname (obfuscation)
   4. many_dashes (1.4 weight) → Domain has many dashes (typosquatting)
   5. many_digits (1.4 weight) → Domain has many numbers (random-looking)
   6. risky_tld (1.5 weight) → Suspicious TLD (.zip, .click, .xyz)
   7. phishing_words (2.2 weight) → URL has phishing keywords (verify, login, confirm, etc)
   8. risky_ext (1.8 weight) → Executable files (.exe, .bat, .jar, .msi)
   9. suspicious_path (1.3 weight) → URL parameters look obfuscated
   10. looks_like_subdomain (0.9 weight) → Subdomain spoofing attempt
   
   MAIN FUNCTION:
   - aiPredictRisk(url) → Returns {prob: 0-1, score: 0-100, features: {...}}
   
   HOW IT WORKS:
   - Extracts features from URL (hostname, path, protocol, etc)
   - Multiplies each feature weight by its presence
   - Passes result through sigmoid function (converts to 0-1 probability)
   - Multiplies by 100 to get 0-100 score
   - Returns detailed analysis

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 vuln_scanner.js
   WHAT IT DOES:
   - Scans website code for vulnerabilities
   - Detects 4 types of web security issues
   
   VULNERABILITY TYPES DETECTED:
   1. XSS (Cross-Site Scripting)
      - Looks for: eval() usage, innerHTML manipulation, onerror handlers
      - Risk: Attacker can inject malicious code into page
   
   2. SQL Injection
      - Looks for: SQL keywords in input fields, suspicious query patterns
      - Risk: Attacker can access/modify database
   
   3. CSRF (Cross-Site Request Forgery)
      - Looks for: Missing CSRF tokens, cross-domain forms
      - Risk: Attacker can make you do things without your knowledge
   
   4. Clickjacking
      - Looks for: Hidden clickable elements, page layering tricks
      - Risk: Attacker makes you click something you don't intend
   
   MAIN FUNCTION:
   - scanPageVulnerabilities() → Returns {score: 0-100, vulnerabilities: {...}}
   
   HOW IT WORKS:
   - Scans page HTML and JavaScript
   - Counts vulnerability occurrences
   - Calculates risk score based on severity and count
   - Categorizes severity: low (1-30), medium (31-70), high (71-100)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📱 content.js
   WHAT IT DOES:
   - Injected into every website you visit
   - Creates the green/yellow/orange/red security bar
   - Analyzes the current URL using AI model
   - Scans page for vulnerabilities
   - Sends results to background.js for logging
   
   MAIN FUNCTIONS:
   - createBar() → Creates the security bar div
   - updateBar(score, url) → Updates bar color and threat level text
   - analyzeUrl(url) → Calls AI model to get threat score
   - scanVulnerabilities() → Calls vuln_scanner to find issues
   - reportFindings(score, url) → Sends results to background.js
   - analyze() → Main function, runs when page loads
   
   SECURITY BAR DISPLAY:
   - Position: Fixed at TOP of page (always visible)
   - Shows: Threat level emoji + risk score + threat name
   - Color codes:
     * GREEN = Safe (0-34 points)
     * YELLOW = Medium Risk (35-59 points)
     * ORANGE = Suspicious (60-84 points)
     * RED = Dangerous (85-100 points)
   - Buttons: Close button to hide bar
   
   DATA SENT TO BACKGROUND:
   - URL analyzed
   - AI risk score
   - Vulnerability data
   - Vulnerability score
   - Source of finding

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚙️ background.js (Service Worker)
   WHAT IT DOES:
   - Runs always in background (even when extension popup is closed)
   - Receives threat data from content.js and logs it
   - Handles right-click context menu actions
   - Scans URLs with VirusTotal API
   - Blocks dangerous downloads
   - Can block entire pages if threat level too high
   - Sends notifications about security threats
   
   MAIN FEATURES:
   
   1. CONTEXT MENU (Right-click actions):
      Parent Menu: "🔍 Security Tools"
      Sub-options:
      - 📝 Encode Base64 (select text, right-click, encode → alert shows result)
      - 📖 Decode Base64 (base64 string → decoded text)
      - 🔗 Encode URL (% encoding for URL parameters)
      - 🔓 Decode URL (decoding of URL-encoded text)
      - 🦠 Check on VirusTotal (scan current page/link)
   
   2. VIRUSTOTAL SCANNING:
      - Requires API key (set in popup settings)
      - Checks URL against VirusTotal database
      - Shows how many antivirus engines detected threats
      - Can be triggered by right-click menu
      - Also scanned automatically for risky downloads
   
   3. THREAT ALERTING:
      - If risk score > 35 (threshold) → notification sent
      - If risk score > 85 (high threshold) → blocks page (optional)
      - Notifications show threat level and URL
   
   4. DOWNLOAD PROTECTION:
      - Monitors all downloads
      - Blocks risky file extensions (.exe, .bat, etc)
      - Scans suspicious downloads with VirusTotal
      - Prevents malware infection
   
   5. MESSAGE LISTENER:
      - Receives "PAGE_FINDINGS" messages from content.js
      - Calculates composite risk score
      - Saves to logs
      - Sends notifications
      - Optionally blocks page
   
   KEY FUNCTIONS:
   - setupContextMenus() → Creates all context menu items on startup
   - handleBase64Encode/Decode(text) → Converts text, shows alert
   - handleURLEncode/Decode(text) → URL parameter encoding/decoding
   - checkUrlOnVirusTotal(url) → Scans URL against VirusTotal
   - handlePageFindings(msg, sender) → Processes threat data from content.js
   - calculateRiskScore(findings) → Blends AI + vulnerability + phishing scores
   - blockMaliciousPage(tabId, url, score) → Shows warning page

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎨 popup.html / popup.js
   WHAT IT DOES:
   - Shows extension popup when you click the extension icon
   - Displays quick statistics
   - Allows enabling/disabling protection
   - Lets you set VirusTotal API key
   - Links to dashboard and documentation
   
   POPUP CONTENTS:
   - Toggle: "Protection Enabled" (on/off switch)
   - Input: VirusTotal API Key (your scanning credentials)
   - Display: # of safe/risky sites visited
   - Buttons: Open Dashboard, API Docs, Settings

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 dashboard.html / dashboard.js
   WHAT IT DOES:
   - Comprehensive security event logging viewer
   - Shows all websites you've visited with threat analysis
   - Displays statistics (safe/medium/risky/dangerous sites)
   - Allows exporting data, clearing logs, auto-refresh
   - Pagination (25 events per page)
   
   STATISTICS SHOWN:
   - Total Events: # of sites analyzed
   - Safe: Sites with score 0-34
   - Medium: Sites with score 35-59
   - Suspicious: Sites with score 60-84
   - Dangerous: Sites with score 85-100
   
   LOG ENTRY CONTAINS:
   - URL visited
   - AI risk score (0-100 from ML model)
   - Vulnerability score (0-100 from web scanning)
   - Detected vulnerabilities (XSS, SQL, CSRF, Clickjacking counts)
   - Final risk score (composite of all factors)
   - Timestamp

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🧪 test.html
   WHAT IT DOES:
   - Test page for encoding/decoding features
   - Safe place to practice using context menus
   - Includes debug information
   - Has test text ready to encode/decode

STEP-BY-STEP: HOW TO USE THIS EXTENSION
========================================

1. INSTALL & ENABLE:
   ✓ Go to chrome://extensions/
   ✓ Find "AI Safe Guard"
   ✓ Make sure it's ENABLED (toggle switch ON)

2. BASIC USAGE - AUTOMATIC THREAT DETECTION:
   ✓ Just browse normally
   ✓ Security bar appears at top of every page
   ✓ Green = Safe, Yellow = OK, Orange = Suspicious, Red = Dangerous
   ✓ All results automatically logged to dashboard

3. SET UP VIRUSTOTAL (Optional but recommended):
   ✓ Go to https://www.virustotal.com/
   ✓ Create free account (or sign in)
   ✓ Click your account → API Key
   ✓ Copy your API key
   ✓ Click extension icon → Paste API key in field → Save
   ✓ Now right-click any page/link → "Check on VirusTotal"

4. USE ENCODING/DECODING TOOLS:
   ✓ Select any text on a website
   ✓ Right-click
   ✓ Look for "🔍 Security Tools" menu
   ✓ Choose:
     - "Encode Base64" if you want to convert text to Base64
     - "Decode Base64" if you have Base64 and want to read it
     - "Encode URL" if you want to escape URL characters
     - "Decode URL" if you want to unescape URL text
   ✓ Result appears in alert box (automatically copied to clipboard)
   ✓ Can also use test.html page as practice

5. VIEW SECURITY LOGS:
   ✓ Click extension icon → "Dashboard"
   ✓ See all websites analyzed with threat levels
   ✓ Includes AI score, vulnerability score, final risk score
   ✓ Can sort, export, or clear logs

HOW THE SCORING SYSTEM WORKS:
=============================

FINAL RISK SCORE (0-100):
- Is a blend of 3 threat vectors:
  
  1. AI Score (Machine Learning Model)
     - Analyzes URL for malware/phishing indicators
     - 10 different factors checked
     - Weight: 60% of final score
  
  2. Vulnerability Score (Web Application Scanning)
     - Checks page code for XSS, SQL Injection, CSRF, Clickjacking
     - Weight: 30% of final score
  
  3. VirusTotal Scan (External Malware Detection)
     - If enabled, checks against 70+ antivirus engines
     - Shows # of detections
     - Weight: 10% of final score

THRESHOLDS (What happens at different scores):
- 0-34 = GREEN (Safe) - Allow to continue
- 35-59 = YELLOW (Medium) - Show warning notification
- 60-84 = ORANGE (Suspicious) - Show warning notification
- 85-100 = RED (Dangerous) - Can block page (if enabled)

TROUBLESHOOTING:
================

PROBLEM: "No green bar appearing on websites"
SOLUTION:
  1. Reload extension (chrome://extensions → reload icon)
  2. Refresh the website
  3. Check if content scripts are injected:
     - Open F12 console
     - Check for messages starting with "[Content]"
  4. Some sites block extensions - that's normal
  5. Make sure extension is ENABLED in chrome://extensions

PROBLEM: "Right-click context menu doesn't show"
SOLUTION:
  1. Reload extension
  2. Check manifest.json has "contextMenus" permission
  3. Open F12 console and look for errors in "Extensions" tab
  4. Try restarting Chrome completely
  5. Make sure you're selecting text before right-clicking

PROBLEM: "Encoding/decoding doesn't work"
SOLUTION:
  1. Make sure you SELECTED text first
  2. Right-click should show "🔍 Security Tools"
  3. Result should appear in ALERT popup
  4. Check console if alert doesn't show
  5. Try test.html page with pre-made text

PROBLEM: "VirusTotal scanning not working"
SOLUTION:
  1. Did you set API key? (Click extension icon → paste key)
  2. API key must be valid - check at virustotal.com
  3. Check "Enable VirusTotal" toggle is ON
  4. Right-click → "Check on VirusTotal"
  5. Result shows as alert with detection count

PROBLEM: "Dashboard shows 0 events"
SOLUTION:
  1. Visit some websites first (page needs to be analyzed)
  2. Check F12 console → Extensions tab
  3. Look for "[Dashboard] Number of logs in storage: X"
  4. If 0, data not being saved - check chrome.storage permissions
  5. Clear logs, visit website again, check dashboard

PROBLEM: "Getting Chrome API errors"
SOLUTION:
  1. Make sure extension is properly installed
  2. Go to chrome://extensions → Details
  3. Check "Allow in Incognito" if testing in private mode
  4. Reload extension
  5. If using development version, may need to allow in settings

SECURITY NOTES:
===============
This extension:
✓ NEVER sends your browsing data to external servers (except VirusTotal if you enable it)
✓ NEVER downloads or executes code
✓ NEVER accesses your passwords or logins
✓ Stores all logs LOCALLY on your computer
✓ Respects your privacy by default
✓ Only needs permissions for features you actually use

TECHNICAL SPECIFICATIONS:
=========================
Extension Type: Chrome Manifest V3 (Latest standard)
Version: 2.2.0
Storage: Chrome Local Storage (max 500 log entries)
Threat database: ML-based AI model + VirusTotal API (optional)
UI Framework: Vanilla HTML/CSS/JavaScript (no dependencies)
File Size: ~400KB
Performance: Minimal CPU/Memory impact

PERMISSIONS USED:
- tabs: Read current tab URL
- storage: Save logs and settings
- notifications: Show security alerts
- downloads: Monitor download threats
- scripting: Inject content script into pages
- contextMenus: Add right-click menu options
- alarms: Internal cleanup (optional)

API INTEGRATIONS:
- VirusTotal API (Optional - requires free account and API key)
- Chrome Extension APIs only

FILES IN THIS PACKAGE:
======================
manifest.json        - Extension configuration
background.js        - Service worker (always running)
content.js           - Injected into every webpage
utils.js             - Shared utilities and storage
ai_model.js          - ML-based threat detection
vuln_scanner.js      - Web vulnerability detector
popup.html           - Extension popup UI
popup.js             - Popup functionality
dashboard.html       - Security logs viewer
dashboard.js         - Dashboard functionality
test.html            - Testing page for context menus
images/              - Extension icons (16px, 48px, 128px)
README.txt           - This file

SUPPORT & FEEDBACK:
==================
This is a demonstration security tool showing:
- How to build Chrome extensions
- URL-based threat detection
- Web vulnerability scanning
- Context menu integration
- Storage and logging

For improvements or bug reports:
1. Check the console (F12) for error messages
2. Check this README for troubleshooting
3. Try reloading the extension
4. Reset to defaults and try again

================================================================================
                           END OF DOCUMENTATION
                 Thank you for using AI Safe Guard Extension!
================================================================================

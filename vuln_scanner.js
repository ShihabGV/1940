/**
 * AI Safe Guard - Vulnerability Scanner
 * Detects XSS, SQL Injection, CSRF, and other vulnerabilities
 */

// ==================== VULNERABILITY DETECTION ====================

/**
 * Detect XSS (Cross-Site Scripting) vulnerabilities
 */
function detectXSS() {
  try {
    const xssIndicators = [];

    // Check for eval() usage
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      if (script.textContent.includes('eval(') || script.textContent.includes('Function(')) {
        xssIndicators.push('eval_detected');
      }
      if (script.textContent.match(/innerHTML\s*=|document\.write/)) {
        xssIndicators.push('unsafe_dom_write');
      }
    });

    // Check for innerHTML usage
    const hasInnerHTML = Array.from(document.querySelectorAll('*')).some(el => {
      return el.innerHTML && el.innerHTML.match(/<script|onerror|onload/i);
    });
    if (hasInnerHTML) xssIndicators.push('inline_script_detected');

    // Check for suspicious event handlers
    const allElements = document.querySelectorAll('*');
    allElements.forEach(el => {
      for (let attr of el.attributes || []) {
        if (attr.name.startsWith('on') && (attr.value.includes('<') || attr.value.includes('javascript:'))) {
          xssIndicators.push('suspicious_event_handler');
        }
      }
    });

    return {
      vulnerable: xssIndicators.length > 0,
      indicators: xssIndicators,
      severity: xssIndicators.length > 2 ? 'high' : (xssIndicators.length > 0 ? 'medium' : 'low')
    };
  } catch (error) {
    console.error('[Vuln Scanner] XSS detection error:', error);
    return { vulnerable: false, indicators: [], severity: 'unknown' };
  }
}

/**
 * Detect SQL Injection patterns in forms
 */
function detectSQLInjection() {
  try {
    const sqlIndicators = [];

    // Check form submissions
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const action = form.action || '';
      
      // Check for SQL-like patterns in action/method
      if (action.match(/sql|select|insert|update|delete|drop|union|where/i)) {
        sqlIndicators.push('sql_in_form_action');
      }

      // Check for hidden inputs that might be tokens
      const inputs = form.querySelectorAll('input[type="hidden"]');
      inputs.forEach(input => {
        if (input.value.includes(';') || input.value.includes('--') || input.value.includes('/*')) {
          sqlIndicators.push('suspicious_hidden_value');
        }
      });
    });

    // Check for database-like queries in scripts
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
      if (script.textContent.match(/SELECT\s+|INSERT\s+|UPDATE\s+|DELETE\s+|DROP\s+/i)) {
        sqlIndicators.push('sql_query_in_script');
      }
    });

    return {
      vulnerable: sqlIndicators.length > 0,
      indicators: sqlIndicators,
      severity: sqlIndicators.length > 1 ? 'high' : (sqlIndicators.length > 0 ? 'medium' : 'low')
    };
  } catch (error) {
    console.error('[Vuln Scanner] SQL Injection detection error:', error);
    return { vulnerable: false, indicators: [], severity: 'unknown' };
  }
}

/**
 * Detect CSRF (Cross-Site Request Forgery) vulnerabilities
 */
function detectCSRF() {
  try {
    const csrfIndicators = [];

    // Check for CSRF token presence
    const forms = document.querySelectorAll('form[method="POST"], form[method="post"]');
    forms.forEach(form => {
      const hasCSRFToken = form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="nonce"]');
      if (!hasCSRFToken) {
        csrfIndicators.push('missing_csrf_token');
      }

      // Check if form targets different domain
      const action = form.action || '';
      if (action && new URL(action, location.href).hostname !== location.hostname) {
        csrfIndicators.push('cross_domain_form');
      }
    });

    // Check for SameSite cookie meta tags
    const hasSameSite = document.querySelector('meta[http-equiv="Set-Cookie"][content*="SameSite"]');
    if (!hasSameSite && forms.length > 0) {
      csrfIndicators.push('no_samesite_cookie');
    }

    return {
      vulnerable: csrfIndicators.length > 0,
      indicators: csrfIndicators,
      severity: csrfIndicators.length > 1 ? 'high' : (csrfIndicators.length > 0 ? 'medium' : 'low')
    };
  } catch (error) {
    console.error('[Vuln Scanner] CSRF detection error:', error);
    return { vulnerable: false, indicators: [], severity: 'unknown' };
  }
}

/**
 * Detect Clickjacking vulnerabilities
 */
function detectClickjacking() {
  try {
    const clickjackIndicators = [];

    // Check for X-Frame-Options header in meta tag
    const hasFrameOptions = document.querySelector('meta[http-equiv="X-UA-Compatible"]');
    
    // Check if page could be framed
    if (window.self !== window.top) {
      clickjackIndicators.push('page_is_framed');
    }

    // Check for CSS that could hide elements
    const styles = document.querySelectorAll('style');
    styles.forEach(style => {
      if (style.textContent.match(/display\s*:\s*none|opacity\s*:\s*0|visibility\s*:\s*hidden/) && 
          style.textContent.match(/button|input|form|click/i)) {
        clickjackIndicators.push('hidden_clickable_elements');
      }
    });

    return {
      vulnerable: clickjackIndicators.length > 0,
      indicators: clickjackIndicators,
      severity: clickjackIndicators.length > 1 ? 'high' : (clickjackIndicators.length > 0 ? 'medium' : 'low')
    };
  } catch (error) {
    console.error('[Vuln Scanner] Clickjacking detection error:', error);
    return { vulnerable: false, indicators: [], severity: 'unknown' };
  }
}

/**
 * Scan page for all vulnerabilities
 */
function scanPageVulnerabilities() {
  try {
    const vulnerabilities = {
      xss: detectXSS(),
      sqlInjection: detectSQLInjection(),
      csrf: detectCSRF(),
      clickjacking: detectClickjacking()
    };

    // Calculate vulnerability score
    let vulnScore = 0;
    Object.values(vulnerabilities).forEach(vuln => {
      if (vuln.severity === 'high') vulnScore += 25;
      else if (vuln.severity === 'medium') vulnScore += 15;
      else if (vuln.severity === 'low') vulnScore += 5;
    });

    console.log('[Vuln Scanner] Page vulnerabilities:', vulnerabilities);
    console.log('[Vuln Scanner] Vulnerability score:', vulnScore);

    return {
      vulnerabilities,
      score: Math.min(100, vulnScore),
      hasVulnerabilities: vulnScore > 0
    };
  } catch (error) {
    console.error('[Vuln Scanner] Page scan error:', error);
    return {
      vulnerabilities: {},
      score: 0,
      hasVulnerabilities: false
    };
  }
}

// Expose to window for content script
window.scanPageVulnerabilities = scanPageVulnerabilities;
window.detectXSS = detectXSS;
window.detectSQLInjection = detectSQLInjection;
window.detectCSRF = detectCSRF;
window.detectClickjacking = detectClickjacking;

console.log('[Vuln Scanner] Vulnerability scanner loaded');

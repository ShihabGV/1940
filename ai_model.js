/**
 * AI Safe Guard - Threat Detection AI Model
 * 
 * ML Model using sigmoid activation with feature-based threat assessment
 * All computations are local - no data sent to external servers
 */

const AI_MODEL = {
  // Model bias term - affects baseline risk score
  bias: -0.8,

  // Feature weights - higher values = stronger indicator of malicious content
  weights: {
    has_ip: 2.2,           // Direct IP address (common in phishing)
    http_only: 1.5,        // Non-HTTPS protocol (data exposure risk)
    long_host: 1.1,        // Unusually long hostname (obfuscation)
    many_dashes: 1.4,      // Multiple dashes in domain (typosquatting)
    many_digits: 1.4,      // Many digits (hard to remember)
    risky_tld: 1.5,        // Known risky TLDs (.zip, .click, etc)
    phishing_words: 2.2,   // Common phishing keywords
    risky_ext: 1.8,        // Executable file extensions
    suspicious_path: 1.3,  // Suspicious URL patterns
    looks_like_subdomain: 0.9 // Subdomain spoofing
  }
};

/**
 * Sigmoid activation function: converts linear score to 0-1 probability
 * Formula: 1 / (1 + e^-x)
 */
function sigmoid(x) {
  return 1 / (1 + Math.exp(-x));
}

/**
 * Extract security-relevant features from URL
 * Returns a feature vector for ML model input
 */
function extractUrlFeatures(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = (u.hostname || '').toLowerCase();
    const path = (u.pathname || '').toLowerCase();
    const query = (u.search || '').toLowerCase();
    const full = (host + path + query).toLowerCase();

    // ==================== HIGH-RISK KEYWORDS ====================
    // These commonly appear in phishing and credential-theft pages
    const phishingWords = [
      'login', 'verify', 'account', 'update', 'secure', 'bank', 'wallet',
      'signin', 'password', 'confirm', 'billing', 'support', 'auth',
      'authenticate', 'authorization', 'identity'
    ];

    // ==================== RISKY TLDs ====================
    // Top-level domains commonly abused for malicious purposes
    const riskyTlds = [
      '.zip', '.mov', '.xyz', '.top', '.click', '.lol', '.gq', '.tk',
      '.ml', '.cf', '.ga', '.online', '.site', '.space', '.bid'
    ];

    // ==================== EXECUTABLE/RISKY EXTENSIONS ====================
    // File types commonly delivered as malware
    const riskyExtensions = [
      '.exe', '.msi', '.apk', '.scr', '.bat', '.ps1', '.jar', '.com',
      '.pif', '.cmd', '.vbs', '.js', '.jse', '.vbe', '.wsf'
    ];

    // ==================== FEATURE EXTRACTION ====================
    return {
      // Direct IP address: strong phishing indicator
      has_ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? 1 : 0,

      // HTTP instead of HTTPS: data exposure risk
      http_only: u.protocol !== 'https:' ? 1 : 0,

      // Unusually long hostname: often used for obfuscation
      long_host: host.length > 30 ? 1 : 0,

      // Multiple dashes: typosquatting technique
      many_dashes: (host.match(/-/g) || []).length >= 3 ? 1 : 0,

      // Excessive digits: makes domain harder to remember/type
      many_digits: (host.match(/\d/g) || []).length >= 5 ? 1 : 0,

      // Known high-risk TLDs
      risky_tld: riskyTlds.some(tld => host.endsWith(tld)) ? 1 : 0,

      // Phishing-related keywords in URL
      phishing_words: phishingWords.some(word => full.includes(word)) ? 1 : 0,

      // Suspicious file extension in path
      risky_ext: riskyExtensions.some(ext => path.endsWith(ext)) ? 1 : 0,

      // Suspicious URL patterns (encoded params, obfuscation)
      suspicious_path: /(%|&#|\\x|eval|exec|script)/i.test(path + query) ? 1 : 0,

      // Subdomain spoofing detection (google.com.attackersite.com)
      looks_like_subdomain: (host.match(/\./g) || []).length >= 3 && !host.includes('aws') && !host.includes('azure') ? 1 : 0
    };
  } catch (error) {
    console.error('[AI Model] Feature extraction error:', error);
    // Return neutral features on error
    return Object.keys(AI_MODEL.weights).reduce((acc, key) => {
      acc[key] = 0;
      return acc;
    }, {});
  }
}

/**
 * Predict malicious risk using ML model
 * 
 * Algorithm:
 * 1. Extract URL features (8 indicators)
 * 2. Compute weighted sum: z = bias + Σ(weight_i * feature_i)
 * 3. Apply sigmoid: probability = 1 / (1 + e^-z)
 * 4. Scale to 0-100: score = probability * 100
 * 
 * @param {string} urlStr - URL to analyze
 * @returns {object} - { probability (0-1), score (0-100), features }
 */
function aiPredictRisk(urlStr) {
  try {
    // Input validation
    if (!urlStr || typeof urlStr !== 'string') {
      return { prob: 0.5, score: 50, features: {} };
    }

    // Extract features from URL
    const features = extractUrlFeatures(urlStr);

    // Compute weighted sum (linear combination)
    let z = AI_MODEL.bias;
    for (const [key, weight] of Object.entries(AI_MODEL.weights)) {
      z += weight * (features[key] || 0);
    }

    // Apply sigmoid activation: convert to probability [0, 1]
    const probability = sigmoid(z);

    // Scale to percentage [0, 100]
    const score = Math.round(probability * 100);

    // Return predictions
    return {
      prob: Number(probability.toFixed(3)),
      score: Math.max(0, Math.min(100, score)), // Clamp to [0, 100]
      features: features
    };
  } catch (error) {
    // Fail-safe: return neutral risk
    console.error('[AI Model] Prediction error:', error);
    return { prob: 0.5, score: 50, features: {} };
  }
}

// ==================== UTILITY: BATCH PREDICTION ====================

/**
 * Analyze multiple URLs in batch
 * Useful for analyzing links on a page
 */
function batchPredictRisk(urls) {
  if (!Array.isArray(urls)) return [];
  
  return urls
    .map(url => ({
      url,
      prediction: aiPredictRisk(url)
    }))
    .sort((a, b) => b.prediction.score - a.prediction.score); // Sort by risk
}

// ==================== UTILITY: THRESHOLD CLASSIFICATION ====================

/**
 * Classify risk into categories
 */
function classifyRisk(score) {
  if (score >= 85) return { level: 'DANGEROUS', color: '#dc2626', emoji: '🟥' };
  if (score >= 60) return { level: 'SUSPICIOUS', color: '#f97316', emoji: '🟧' };
  if (score >= 35) return { level: 'MEDIUM', color: '#eab308', emoji: '🟨' };
  return { level: 'SAFE', color: '#16a34a', emoji: '🟩' };
}

// ==================== EXPORT / LOGGING ====================

// Expose to window for content script access
window.aiPredictRisk = aiPredictRisk;
window.batchPredictRisk = batchPredictRisk;
window.classifyRisk = classifyRisk;
window.extractUrlFeatures = extractUrlFeatures;

// Log model initialization
console.log('[AI Safe Guard] Threat detection model loaded');
console.log('[AI Safe Guard] Model version:', '2.2.0');
console.log('[AI Safe Guard] Features:', Object.keys(AI_MODEL.weights).length);
console.log('[AI Safe Guard] Thresholds: Safe<35, Medium<60, Suspicious<85, Dangerous>=85');
console.log('[AI Safe Guard] AI functions exposed:', typeof window.aiPredictRisk);
/**
 * AI Safe Guard - Threat Detection AI Model
 * 
 * ML Model using sigmoid activation with feature-based threat assessment
 * All computations are local - no data sent to external servers
 */

(function(root) {
  'use strict';

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
   */
  function sigmoid(x) {
    return 1 / (1 + Math.exp(-x));
  }

  /**
   * Extract security-relevant features from URL
   */
  function extractUrlFeatures(urlStr) {
    try {
      const u = new URL(urlStr);
      const host = (u.hostname || '').toLowerCase();
      const path = (u.pathname || '').toLowerCase();
      const query = (u.search || '').toLowerCase();
      const full = (host + path + query).toLowerCase();

      const phishingWords = ['login', 'verify', 'account', 'update', 'secure', 'bank', 'wallet', 'signin', 'password', 'confirm', 'billing', 'support', 'auth', 'authenticate', 'authorization', 'identity'];
      const riskyTlds = ['.zip', '.mov', '.xyz', '.top', '.click', '.lol', '.gq', '.tk', '.ml', '.cf', '.ga', '.online', '.site', '.space', '.bid'];
      const riskyExtensions = ['.exe', '.msi', '.apk', '.scr', '.bat', '.ps1', '.jar', '.com', '.pif', '.cmd', '.vbs', '.js', '.jse', '.vbe', '.wsf'];

      return {
        has_ip: /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? 1 : 0,
        http_only: u.protocol !== 'https:' ? 1 : 0,
        long_host: host.length > 30 ? 1 : 0,
        many_dashes: (host.match(/-/g) || []).length >= 3 ? 1 : 0,
        many_digits: (host.match(/\d/g) || []).length >= 5 ? 1 : 0,
        risky_tld: riskyTlds.some(tld => host.endsWith(tld)) ? 1 : 0,
        phishing_words: phishingWords.some(word => full.includes(word)) ? 1 : 0,
        risky_ext: riskyExtensions.some(ext => path.endsWith(ext)) ? 1 : 0,
        suspicious_path: /(%|&#|\\x|eval|exec|script)/i.test(path + query) ? 1 : 0,
        looks_like_subdomain: (host.match(/\./g) || []).length >= 3 && !host.includes('aws') && !host.includes('azure') ? 1 : 0
      };
    } catch (error) {
      return Object.keys(AI_MODEL.weights).reduce((acc, key) => { acc[key] = 0; return acc; }, {});
    }
  }

  /**
   * Predict malicious risk using ML model
   */
  function aiPredictRisk(urlStr) {
    try {
      if (!urlStr || typeof urlStr !== 'string') return { prob: 0.5, score: 50, features: {} };
      const features = extractUrlFeatures(urlStr);
      let z = AI_MODEL.bias;
      for (const [key, weight] of Object.entries(AI_MODEL.weights)) {
        z += weight * (features[key] || 0);
      }
      const probability = sigmoid(z);
      const score = Math.round(probability * 100);
      const reasons = [];
      if (features.has_ip) reasons.push('Direct IP address usage');
      if (features.http_only) reasons.push('Non-HTTPS connection');
      if (features.long_host) reasons.push('Unusually long hostname');
      if (features.many_dashes) reasons.push('Typosquatting indicator (many dashes)');
      if (features.many_digits) reasons.push('Suspicious domain (many digits)');
      if (features.risky_tld) reasons.push('Known risky TLD');
      if (features.phishing_words) reasons.push('Phishing-related keywords found');
      if (features.risky_ext) reasons.push('Risky file extension in URL');
      if (features.suspicious_path) reasons.push('Obfuscated URL path');
      if (features.looks_like_subdomain) reasons.push('Subdomain spoofing attempt');

      return {
        prob: Number(probability.toFixed(3)),
        score: Math.max(0, Math.min(100, score)),
        features: features,
        reasons: reasons
      };
    } catch (error) {
      return { prob: 0.5, score: 50, features: {} };
    }
<<<<<<< HEAD
=======

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

    // Generate human-readable reasons
    const reasons = [];
    if (features.has_ip) reasons.push('Direct IP address usage');
    if (features.http_only) reasons.push('Non-HTTPS connection');
    if (features.long_host) reasons.push('Unusually long hostname');
    if (features.many_dashes) reasons.push('Typosquatting indicator (many dashes)');
    if (features.many_digits) reasons.push('Suspicious domain (many digits)');
    if (features.risky_tld) reasons.push('Known risky TLD');
    if (features.phishing_words) reasons.push('Phishing-related keywords found');
    if (features.risky_ext) reasons.push('Risky file extension in URL');
    if (features.suspicious_path) reasons.push('Obfuscated URL path');
    if (features.looks_like_subdomain) reasons.push('Subdomain spoofing attempt');

    // Return predictions
    return {
      prob: Number(probability.toFixed(3)),
      score: Math.max(0, Math.min(100, score)), // Clamp to [0, 100]
      features: features,
      reasons: reasons
    };
  } catch (error) {
    // Fail-safe: return neutral risk
    console.error('[AI Model] Prediction error:', error);
    return { prob: 0.5, score: 50, features: {} };
>>>>>>> e74b18a6c6e47e4346a033fa43a571441cc0185e
  }

  function classifyRisk(score) {
    if (score >= 85) return { level: 'DANGEROUS', color: '#dc2626', emoji: '🟥' };
    if (score >= 60) return { level: 'SUSPICIOUS', color: '#f97316', emoji: '🟧' };
    if (score >= 35) return { level: 'MEDIUM', color: '#eab308', emoji: '🟨' };
    return { level: 'SAFE', color: '#16a34a', emoji: '🟩' };
  }

  // Expose to global scope
  root.aiPredictRisk = aiPredictRisk;
  root.classifyRisk = classifyRisk;
  root.extractUrlFeatures = extractUrlFeatures;

  console.log('[AI Model] Loaded and exposed functions');

<<<<<<< HEAD
})(typeof self !== 'undefined' ? self : (typeof window !== 'undefined' ? window : this));
=======
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

// Expose to window/global for content script and background access
if (typeof window !== 'undefined') {
  window.aiPredictRisk = aiPredictRisk;
  window.batchPredictRisk = batchPredictRisk;
  window.classifyRisk = classifyRisk;
  window.extractUrlFeatures = extractUrlFeatures;
} else if (typeof self !== 'undefined') {
  self.aiPredictRisk = aiPredictRisk;
  self.batchPredictRisk = batchPredictRisk;
  self.classifyRisk = classifyRisk;
  self.extractUrlFeatures = extractUrlFeatures;
}

// Log model initialization
console.log('[AI Safe Guard] Threat detection model loaded');
console.log('[AI Safe Guard] Model version:', '2.2.0');
console.log('[AI Safe Guard] Features:', Object.keys(AI_MODEL.weights).length);
console.log('[AI Safe Guard] Thresholds: Safe<35, Medium<60, Suspicious<85, Dangerous>=85');
console.log('[AI Safe Guard] AI functions exposed:', typeof window.aiPredictRisk);
>>>>>>> e74b18a6c6e47e4346a033fa43a571441cc0185e

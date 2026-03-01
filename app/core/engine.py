import joblib
import os
import pandas as pd
from app.core.url_features import extractor
from app.core.threat_intel import threat_intel

class IntelligenceEngine:
    def __init__(self):
        self.model_path = 'app/models/phishing_model.pkl'
        self.model = None
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)

    async def analyze_url(self, url):
        # 1. Feature Extraction
        features = extractor.extract_features(url)
        
        # 2. ML Prediction
        classification = "Unknown"
        confidence = 0.0
        
        if self.model:
            feat_df = pd.DataFrame([features])
            prediction = self.model.predict(feat_df)[0]
            probabilities = self.model.predict_proba(feat_df)[0]
            
            classification = "Malicious" if prediction == 1 else "Safe"
            confidence = probabilities[prediction] * 100
        
        # 3. Threat Intel Layer (Async)
        gsb_result = await threat_intel.check_google_safe_browsing(url)
        vt_result = await threat_intel.check_virustotal(url)
        
        # 4. Hybrid Risk Scoring
        risk_score = self._calculate_risk_score(features, classification, confidence, gsb_result)
        
        # 5. Explainable Reasoning
        explanation = self._generate_explanation(features, classification, risk_score, gsb_result)
        
        final_classification = classification
        if risk_score > 70:
            final_classification = "Malicious"
        elif risk_score > 40:
            final_classification = "Suspicious"
        else:
            final_classification = "Safe"
            
        return {
            "url": url,
            "classification": final_classification,
            "confidence_score": f"{confidence:.2f}%",
            "risk_score": risk_score,
            "explanation": explanation,
            "raw_features": features,
            "threat_intel_reports": {
                "google_safe_browsing": gsb_result,
                "virustotal": vt_result
            }
        }

    def _calculate_risk_score(self, features, ml_class, confidence, gsb):
        score = 0
        # ML Weight (40%)
        if ml_class == "Malicious":
            score += (confidence * 0.4)
        
        # Feature Anomaly Weight (30%)
        if features['is_ip_address']: score += 15
        if features['has_homoglyph']: score += 15
        if features['url_length'] > 100: score += 5
        if features['subdomain_count'] > 3: score += 5
        if not features['has_https']: score += 10
        if features['domain_age_days'] < 30: score += 10
        
        # Threat Intel Weight (30%)
        if gsb and 'matches' in gsb:
            score += 30
            
        return min(100, score)

    def _generate_explanation(self, features, ml_class, risk_score, gsb):
        reasons = []
        if ml_class == "Malicious":
            reasons.append(f"AI model classified as potentially malicious based on structural patterns.")
        
        if features['is_ip_address']:
            reasons.append("The URL uses an IP address instead of a domain name, a common phishing tactic.")
        
        if features['has_homoglyph']:
            reasons.append("Homoglyphs detected (characters that look like others), likely a spoofing attempt.")
            
        if not features['has_https']:
            reasons.append("Connection is not secure (HTTP), which is atypical for modern sensitive sites.")
            
        if features['domain_age_days'] > 0 and features['domain_age_days'] < 30:
            reasons.append("The domain was registered very recently, which is common for short-lived phishing sites.")
            
        if gsb and 'matches' in gsb:
            reasons.append("Flagged by Google Safe Browsing as a known threat.")
            
        if not reasons:
            reasons.append("No significant anomalies detected in URL structure or threat databases.")
            
        return reasons

intelligence_engine = IntelligenceEngine()

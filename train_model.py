import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from app.core.url_features import extractor

def generate_synthetic_data(n_samples=500):
    data = []
    # Safe URLs patterns
    for _ in range(n_samples // 2):
        url = f"https://google.com/search?q={np.random.randint(100, 1000)}"
        features = extractor.extract_features(url, skip_whois=True)
        features['label'] = 0 # Safe
        data.append(features)
        
    # Malicious URLs patterns
    for _ in range(n_samples // 2):
        url = f"http://secure-login-update{np.random.randint(10, 99)}.com/verify?id={np.random.randint(10000, 99999)}"
        features = extractor.extract_features(url, skip_whois=True)
        features['label'] = 1 # Malicious
        data.append(features)
        
    return pd.DataFrame(data)

def train_model():
    print("Generating training data...")
    df = generate_synthetic_data(1000)
    
    X = df.drop('label', axis=1)
    y = df['label']
    
    print("Training Random Forest model...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    os.makedirs('app/models', exist_ok=True)
    joblib.dump(model, 'app/models/phishing_model.pkl')
    print("Model saved to app/models/phishing_model.pkl")

if __name__ == "__main__":
    train_model()

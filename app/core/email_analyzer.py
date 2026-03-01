import re
import os
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

class EmailAnalyzer:
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.client = OpenAI(api_key=self.api_key) if self.api_key else None
        self.suspicious_keywords = [
            'urgent', 'immediate action', 'account suspended', 'verify identity',
            'unauthorized access', 'click here', 'login to secure', 'gift card',
            'tax refund', 'lottery winner'
        ]

    def analyze_text(self, text):
        # 1. Local NLP Keyword Detection
        found_keywords = [kw for kw in self.suspicious_keywords if kw.lower() in text.lower()]
        keyword_score = len(found_keywords) * 10
        
        # 2. Semantic Analysis using OpenAI
        ai_analysis = "AI Analysis skipped: No API Key provided."
        if self.client:
            try:
                response = self.client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a cyber security expert. Analyze the following email content for phishing attempts. Provide a phishing probability (0-100), risk level, and a concise explanation."},
                        {"role": "user", "content": f"Email Content: {text}"}
                    ]
                )
                ai_analysis = response.choices[0].message.content
            except Exception as e:
                ai_analysis = f"AI Analysis failed: {str(e)}"
        
        # 3. Urgency Tone Check (Simple Regex)
        urgency_markers = [r'!{2,}', r'NOW', r'immediately', r'within \d+ hours']
        has_urgency = any(re.search(marker, text, re.IGNORECASE) for marker in urgency_markers)
        
        return {
            "keyword_matches": found_keywords,
            "keyword_score": min(keyword_score, 100),
            "urgency_detected": has_urgency,
            "ai_semantic_analysis": ai_analysis
        }

email_analyzer = EmailAnalyzer()

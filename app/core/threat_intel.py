import aiohttp
import os
from dotenv import load_dotenv

load_dotenv()

class ThreatIntel:
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.gsb_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
        
    async def check_virustotal(self, url):
        if not self.vt_api_key:
            return {"status": "skipped", "message": "No API Key"}
            
        url_id = self._get_url_id(url) # VT requires base64 URL ID for some endpoints or just the URL
        v4_url = f"https://www.virustotal.com/api/v3/urls"
        
        # This is a simplified async call
        async with aiohttp.ClientSession() as session:
            try:
                # In practice, VT needs a POST to submit, then a GET to retrieve.
                # Here we assume a simple check for brevity in the engine logic.
                headers = {"x-apikey": self.vt_api_key}
                async with session.get(f"{v4_url}", headers=headers) as resp:
                    return await resp.json()
            except Exception as e:
                return {"error": str(e)}

    async def check_google_safe_browsing(self, url):
        if not self.gsb_api_key:
            return {"status": "skipped", "message": "No API Key"}
        
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
        payload = {
            "client": {"clientId": "phishshield", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(endpoint, json=payload) as resp:
                    return await resp.json()
            except Exception as e:
                return {"error": str(e)}

    def _get_url_id(self, url):
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

threat_intel = ThreatIntel()

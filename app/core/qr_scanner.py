import cv2
import numpy as np
from pyzbar.pyzbar import decode
from app.core.url_features import extractor
import requests

class QRScanner:
    def scan_image(self, image_bytes):
        # Convert bytes to numpy array
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if img is None:
            return {"error": "Could not decode image"}
        
        decoded_objects = decode(img)
        
        results = []
        for obj in decoded_objects:
            url = obj.data.decode('utf-8')
            results.append({
                "type": obj.type,
                "data": url,
                "rect": obj.rect._asdict()
            })
            
        return results

qr_scanner = QRScanner()

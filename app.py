from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from fastapi.responses import JSONResponse

# URL + File model
import joblib
from url_scanner import extract_features, check_whois_safety, is_definitely_malicious_url
from urllib.parse import urlparse
import numpy as np
from file import scan_file 
import os

import shutil
import uuid
import re

app = FastAPI()

# Load ML model
model = joblib.load("phishing_xgboost_model.pkl")

# === URL Prediction Model ===
class URLRequest(BaseModel):
    url: str

feature_names = [
    "URL Length", "Dots in URL", "Repeated Digits in URL", "Digits in URL",
    "Special Chars in URL", "Hyphens in URL", "Underscores in URL", "Slashes in URL",
    "Question Marks in URL", "Equals in URL", "At Signs in URL", "Dollar Signs in URL",
    "Exclamations in URL", "Hashtags in URL", "Percent Signs in URL",
    "Domain Length", "Dots in Domain", "Hyphens in Domain", "Special Chars in Domain (bool)",
    "Special Chars in Domain (count)", "Digits in Domain (bool)", "Digits in Domain (count)",
    "Repeated Digits in Domain", "Subdomains", "Dot in Subdomain", "Hyphen in Subdomain",
    "Avg Subdomain Length", "Avg Dots in Subdomain", "Avg Hyphens in Subdomain",
    "Special Chars in Subdomain (bool)", "Special Chars in Subdomain (count)",
    "Digits in Subdomain (bool)", "Digits in Subdomain (count)",
    "Repeated Digits in Subdomain", "Has Path", "Path Length", "Has Query",
    "Has Fragment", "Has Anchor", "Entropy of URL", "Entropy of Domain"
]

@app.post("/predict/url")
async def predict_url(request: URLRequest):
    url = request.url
    if not url:
        raise HTTPException(status_code=400, detail="No URL provided")

    # Rule-based early detection
    if is_definitely_malicious_url(url):
        return JSONResponse(content={
            "result": "Malicious",
            "reason": "Detected by rule-based system",
            "features": None
        })

    try:
        # Extract features & run model prediction
        features = extract_features(url)[0]
        prediction = model.predict([features])[0]
        confidence = float(np.max(model.predict_proba([features])[0])) if hasattr(model, "predict_proba") else None
        parsed_domain = urlparse(url).netloc

        # WHOIS logic – skip if model is confident it's legitimate
        skip_whois = prediction == 0 and confidence is not None and confidence >= 0.65
        whois_safe = True if skip_whois else check_whois_safety(parsed_domain)

        # -------------------------
        # Safety Score Calculation
        # -------------------------
        # Trust the model if it predicts legitimate with high enough confidence

        if prediction == 0 and confidence and confidence >= 0.55:
            # Trustworthy legitimate → full score
            safety_score = 100
        else:
            if prediction == 1:  # model thinks it's malicious
                base_score = 20
                if confidence:
                    base_score += int((1 - confidence) * 30)
                if whois_safe:
                    base_score += 20
                else:
                    base_score -= 10
            else:  # prediction == 0 but confidence < 0.55
                base_score = 70
                if confidence:
                    base_score += int(confidence * 20)
                if not whois_safe:
                    base_score -= 20

            safety_score = min(max(base_score, 1), 100)

        # -------------------------
        # Determine final result from score
        # -------------------------
        if safety_score > 65:
            result = "Safe"
        elif 45 <= safety_score <= 65:
            result = "Suspicious"
        else:
            result = "Not Safe"

        # Reasoning for output
        def get_reason(result, confidence, whois_safe, safety_score):
            base = f"Safety score: {safety_score} — "
            if result == "Suspicious":
                if confidence and 0.61 <= confidence <= 0.79:
                    return base + "Confidence score is moderate."
                elif not whois_safe:
                    return base + "WHOIS data shows domain is likely unsafe."
                return base + "Detected as borderline suspicious."
            elif result == "Not Safe":
                return base + "Model or WHOIS indicates high risk."
            elif result == "Safe":
                if skip_whois:
                    return base + "Model confidently predicted as legitimate (>65%)."
                return base + "Model and WHOIS check both passed."
            return base + "Detected by rule-based system."

        return JSONResponse(content={
            "result": result,
            "safety_score": safety_score,
            "model_prediction": "Malicious" if prediction == 1 else "Legitimate",
            "confidence": f"{round(confidence * 100, 2)}%" if confidence is not None else None,
            "whois_safe": whois_safe,
            "features": dict(zip(feature_names, features.tolist())),
            "reason": get_reason(result, confidence, whois_safe, safety_score)
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/file")
async def predict_file(file: UploadFile = File(...)):
    file_path = f"/tmp/{file.filename}"
    try:
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

        scan_result = scan_file(file_path)
        if "error" in scan_result:
            raise HTTPException(status_code=400, detail=scan_result["error"])

        file_info = scan_result["file_info"]
        indicators = scan_result["indicators"]

        def get_indicator(indicators, key):
            return next((i["value"] for i in indicators if i["type"] == key), None)

        return JSONResponse(content={
            "result": scan_result["classification"],
            "threat_score": scan_result["threat_score"],
            "features": {
                "filename": file_info.get("path", file.filename),
                "file_size": file_info.get("size"),
                "file_type": file_info.get("file_type"),
                "md5": file_info.get("md5"),
                "sha1": file_info.get("sha1"),
                "sha256": file_info.get("sha256"),
                "entropy": get_indicator(indicators, "entropy"),
                "non_ascii_ratio": get_indicator(indicators, "non_ascii_ratio"),
                "sandbox_detected": get_indicator(indicators, "sandbox"),
                "embedded_urls_ips": get_indicator(indicators, "url/ip"),
                "suspicious_api_calls": [i["value"] for i in indicators if i["type"] == "api"],
                "strings_sample": file_info.get("strings_found", [])
            },
            "indicators": indicators,
            "verdicts": scan_result["verdicts"]
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

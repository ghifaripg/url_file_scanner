import joblib
import numpy as np
import re
from urllib.parse import urlparse
from collections import Counter
import math
import sys
from datetime import datetime
import whois
import tldextract


def entropy(string):
    if not string:
        return 0
    probs = [count / len(string) for count in Counter(string).values()]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    parsed = urlparse(url)

    url_length = len(url)
    number_of_dots_in_url = url.count('.')
    number_of_hyphens_in_url = url.count('-')
    number_of_underline_in_url = url.count('_')
    number_of_slash_in_url = url.count('/')
    number_of_questionmark_in_url = url.count('?')
    number_of_equal_in_url = url.count('=')
    number_of_at_in_url = url.count('@')
    number_of_dollar_in_url = url.count('$')
    number_of_exclamation_in_url = url.count('!')
    number_of_hashtag_in_url = url.count('#')
    number_of_percent_in_url = url.count('%')
    number_of_special_char_in_url = (
        number_of_exclamation_in_url + number_of_at_in_url +
        number_of_dollar_in_url + number_of_hashtag_in_url +
        number_of_percent_in_url
    )

    digits = re.findall(r'\d', url)
    number_of_digits_in_url = len(digits)
    having_repeated_digits_in_url = int(any(url[i] == url[i+1] and url[i].isdigit() for i in range(len(url)-1)))

    domain = parsed.netloc
    domain_length = len(domain)
    number_of_dots_in_domain = domain.count('.')
    number_of_hyphens_in_domain = domain.count('-')
    digits_domain = re.findall(r'\d', domain)
    number_of_digits_in_domain = len(digits_domain)
    having_digits_in_domain = int(number_of_digits_in_domain > 0)
    having_repeated_digits_in_domain = int(any(domain[i] == domain[i+1] and domain[i].isdigit() for i in range(len(domain)-1)))
    special_characters_in_domain = re.findall(r'[^a-zA-Z0-9.-]', domain)
    having_special_characters_in_domain = int(bool(special_characters_in_domain))
    number_of_special_characters_in_domain = len(special_characters_in_domain)

    subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
    number_of_subdomains = len(subdomains)
    having_dot_in_subdomain = int(any('.' in sub for sub in subdomains))
    having_hyphen_in_subdomain = int(any('-' in sub for sub in subdomains))
    average_subdomain_length = (sum(len(sub) for sub in subdomains) / number_of_subdomains) if number_of_subdomains > 0 else 0

    average_number_of_dots_in_subdomain = 0
    average_number_of_hyphens_in_subdomain = 0
    having_special_characters_in_subdomain = 0
    number_of_special_characters_in_subdomain = 0
    having_digits_in_subdomain = 0
    number_of_digits_in_subdomain = 0
    having_repeated_digits_in_subdomain = 0

    having_path = int(bool(parsed.path))
    path_length = len(parsed.path)
    having_query = int(bool(parsed.query))
    having_fragment = int(bool(parsed.fragment))
    having_anchor = 0

    entropy_of_url = entropy(url)
    entropy_of_domain = entropy(domain)

    features = [
        url_length,
        number_of_dots_in_url,
        having_repeated_digits_in_url,
        number_of_digits_in_url,
        number_of_special_char_in_url,
        number_of_hyphens_in_url,
        number_of_underline_in_url,
        number_of_slash_in_url,
        number_of_questionmark_in_url,
        number_of_equal_in_url,
        number_of_at_in_url,
        number_of_dollar_in_url,
        number_of_exclamation_in_url,
        number_of_hashtag_in_url,
        number_of_percent_in_url,
        domain_length,
        number_of_dots_in_domain,
        number_of_hyphens_in_domain,
        having_special_characters_in_domain,
        number_of_special_characters_in_domain,
        having_digits_in_domain,
        number_of_digits_in_domain,
        having_repeated_digits_in_domain,
        number_of_subdomains,
        having_dot_in_subdomain,
        having_hyphen_in_subdomain,
        average_subdomain_length,
        average_number_of_dots_in_subdomain,
        average_number_of_hyphens_in_subdomain,
        having_special_characters_in_subdomain,
        number_of_special_characters_in_subdomain,
        having_digits_in_subdomain,
        number_of_digits_in_subdomain,
        having_repeated_digits_in_subdomain,
        having_path,
        path_length,
        having_query,
        having_fragment,
        having_anchor,
        entropy_of_url,
        entropy_of_domain
    ]

    return np.array(features).reshape(1, -1)

def check_whois_safety(full_domain):
    try:
        # Use base domain for WHOIS
        extracted = tldextract.extract(full_domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"

        w = whois.whois(base_domain)
        creation_date = w.creation_date
        country = w.country

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        is_new = not creation_date or (datetime.now() - creation_date).days < 180
        no_country = not country

        if is_new:
            print(f"[WHOIS] Domain is too new: {base_domain} (Created: {creation_date})")
        if no_country:
            print(f"[WHOIS] No country info for: {base_domain}")

        return not (is_new or no_country)
    
    except Exception as e:
        print(f"[WHOIS ERROR] Failed to lookup {full_domain} → {e}")
        return False

def is_definitely_malicious_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    scheme = parsed.scheme.lower()
    path = parsed.path
    query = parsed.query

    # Rule 1: Dangerous schemes
    if scheme in ["javascript", "data", "vbscript", "file", "smb", "ftp"]:
        return True

    # Rule 2: Embedded user credentials
    if '@' in domain and re.match(r".+@.+\..+", domain):
        return True

    # New Rule: suspicious keywords like "php" inside domain or subdomain
    if "php" in domain:
        return True

    # Rule 5: Punycode domain
    if "xn--" in domain:
        return True

    # Rule 6: Non-standard port
    if parsed.port and parsed.port not in [80, 443]:
        return True


    return False

#  === Main Script ===
# if __name__ == "__main__":
#     try:
#         model = joblib.load("phishing_xgboost_model.pkl")
#     except Exception as e:
#         print(f"Error loading model: {e}")
#         sys.exit(1)

#     url = input("Enter URL to test: ").strip()

#     if is_definitely_malicious_url(url):
#         print(" Not Safe (Pattern Matched - Skipped ML Model)")
#         print("\nThreat Score: 100/100\nRisk Level: High\nReason: Matched known malicious pattern")
#         sys.exit(0)

#     features = extract_features(url)

#     try:
#         pred = model.predict(features)[0]
#         parsed = urlparse(url)
#         domain = parsed.netloc

#         threat_score = 0
#         key_indicators = []

#         if hasattr(model, "predict_proba"):
#             proba = model.predict_proba(features)[0]
#             confidence = max(proba)

#             print(f"\nModel Prediction: {'Malicious' if pred == 1 else 'Legitimate'} (Confidence: {confidence:.2%})")

#             if pred == 1:
#                 threat_score += 50
#                 key_indicators.append(f"Model flagged as malicious with {confidence:.2%} confidence")

#                 if 0.61 <= confidence <= 0.79:
#                     key_indicators.append("Confidence is in uncertain range (61%-79%)")
#                 whois_flag = check_whois_safety(domain)
#                 if whois_flag:
#                     threat_score += 20
#                     key_indicators.append(whois_flag)
#                 else:
#                     key_indicators.append("WHOIS check passed")
#             else:
#                 key_indicators.append("Model flagged as legitimate")

#         else:
#             print(f"Model Prediction: {'Malicious' if pred == 1 else 'Legitimate'}")
#             key_indicators.append("Confidence score not available.")

#         # Rule-based check again for scoring
#         if is_definitely_malicious_url(url):
#             threat_score += 30
#             key_indicators.append("URL pattern matched known malicious characteristics")

#         # Feature-based key flags
#         if features[0][0] > 150:
#             key_indicators.append("URL length is very long")
#         if features[0][-2] > 4.0:
#             key_indicators.append("High entropy in URL - looks obfuscated")
#         if features[0][-1] > 3.5:
#             key_indicators.append("High entropy in domain - suspicious")

#         # Final Report
#         print("\n--- THREAT REPORT ---")
#         print(f"Threat Score: {threat_score}/100")
#         if threat_score >= 80:
#             print("Risk Level: High")
#         elif threat_score >= 50:
#             print("Risk Level: Medium")
#         else:
#             print("Risk Level: Low")

#         print("\nKey Indicators:")
#         for indicator in key_indicators:
#             print(f"- {indicator}")

#     except Exception as e:
#         print(f"Prediction error: {e}")

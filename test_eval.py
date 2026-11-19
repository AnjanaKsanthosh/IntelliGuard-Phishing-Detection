import sys
from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parent
sys.path.append(str(ROOT))
from threat_engine import evaluate_url_threat

model = joblib.load(ROOT / "models" / "url_model.joblib")

test_urls = [
    "https://paypal-login.com",
    "https://amazon-security.com",
    "https://apple-id-verify.com",
    "https://secure-login-attempt.com",
    "https://online-banking-check.com",
    "https://netflix-payment.com",
    "https://crypto-airdrop-claim.com",
    "https://test-link.com",
    "https://random-site-123.com",
    "https://my-school-portal.org",
    "https://flipkart.com",
    "https://instagram.com",
    "http://example.com/login"
]

print("=" * 80)
for u in test_urls:
    res = evaluate_url_threat(model, u)
    print(f"{u:<35} | {res['risk_score']:>3}/100 | {res['risk_tier']:<12} | {res['phishing_probability']*100:5.1f}%")
print("=" * 80)

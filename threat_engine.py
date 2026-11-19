"""
IntelliGuard Threat Intelligence & Link Safety Engine
Analyzes website links using domain reputation, brand spoofing radar, structural signals, and machine learning.
Provides 4 easy-to-understand risk tiers: Safe, Low Risk, Suspicious, and Dangerous.
"""
from urllib.parse import urlparse
import ipaddress
import math
import re
from typing import Dict, Any, Tuple

# Multi-part Top-Level Domains (e.g. .co.uk, .gov.in)
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "net.br", "org.br",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "net.tw", "org.tw", "gov.tw",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "net.za", "org.za", "gov.za",
    "com.mx", "org.mx", "edu.mx", "gob.mx",
    "com.tr", "org.tr", "edu.tr", "gov.tr",
    "com.ru", "net.ru", "org.ru", "pp.ru",
}

# Authoritative & Trusted Root Domains (Reputation Knowledge Base)
TRUSTED_AUTHORITY_DOMAINS = {
    # Search & Cloud Giants
    "google.com", "google.co.in", "google.co.uk", "google.de", "google.fr", "google.ca", "google.com.au",
    "youtube.com", "gmail.com", "android.com", "chrome.com",
    "microsoft.com", "live.com", "office.com", "outlook.com", "azure.com", "bing.com", "msn.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "aws.amazon.com",
    # Developer & Tech Platforms
    "github.com", "github.io", "gitlab.com", "bitbucket.org", "stackoverflow.com", "stackexchange.com",
    "python.org", "pypi.org", "npmjs.com", "docker.com", "kubernetes.io",
    "render.com", "vercel.com", "vercel.app", "netlify.com", "netlify.app", "heroku.com",
    "cloudflare.com", "fastly.com", "akamai.com",
    "openai.com", "anthropic.com", "huggingface.co",
    # Everyday Social & Productivity
    "linkedin.com", "wikipedia.org", "wikimedia.org", "reddit.com", "twitter.com", "x.com",
    "facebook.com", "instagram.com", "whatsapp.com", "threads.net", "messenger.com",
    "telegram.org", "slack.com", "discord.com", "zoom.us", "zoom.com",
    "spotify.com", "netflix.com", "twitch.tv", "pinterest.com", "tumblr.com", "quora.com",
    "dropbox.com", "box.com", "salesforce.com", "adobe.com", "canva.com", "medium.com",
    # E-commerce, Utilities & Edu
    "flipkart.com", "walmart.com", "ebay.com", "target.com",
    "mozilla.org", "w3.org", "archive.org", "coursera.org", "edx.org", "khanacademy.org",
    "mit.edu", "stanford.edu", "harvard.edu", "nih.gov", "cdc.gov", "nasa.gov",
    "duckduckgo.com", "proton.me", "protonmail.com"
}

# Known Target Brands for Impersonation Defense
TARGET_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "twitter": "x.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citi.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "steam": "steampowered.com",
    "roblox": "roblox.com",
    "spotify": "spotify.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "render": "render.com",
    "dropbox": "dropbox.com",
    "bank": None,
    "crypto": None
}

# High-Abuse / Disposable TLDs commonly seen in mass phishing
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "icu", "cam",
    "work", "rest", "click", "live", "loan", "racing", "download",
    "monster", "fit", "surf", "casa", "country", "link", "gdn", "date"
}

# Known URL Shorteners that hide destinations
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "v.gd"
}

# Dangerous executable files
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".apk", ".vbs", ".iso", ".cmd", ".ps1",
    ".jar", ".msi", ".pif", ".hta", ".wsf", ".cpl"
}

# High-Severity Phishing Lures (Directly targeting credentials, banking, or prizes)
HIGH_RISK_LURES = [
    "login", "signin", "sign-in", "sign_in", "log-in", "log_in",
    "verify", "verification", "secure-login", "security-check",
    "account-update", "update-billing", "billing", "invoice",
    "banking", "bank", "ebanking", "password", "passcode", "credential",
    "wallet", "seed-phrase", "recovery", "recover", "authenticate",
    "authorization", "authorize", "confirm-identity", "suspended",
    "unusual-activity", "2fa", "mfa", "claim", "reward",
    "winner", "airdrop", "payment", "pay-online"
]

# Medium-Severity Contextual Lures
MEDIUM_RISK_LURES = [
    "secure", "security", "portal", "support", "helpdesk",
    "account", "update", "service", "center", "auth", "alert"
]

def calculate_shannon_entropy(text: str) -> float:
    """Computes character randomness in bits."""
    if not text:
        return 0.0
    freq = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in freq)

def parse_domain_structure(hostname: str) -> Dict[str, Any]:
    """Extracts clean website address parts."""
    raw_host = hostname.strip().lower().rstrip(".")
    if ":" in raw_host and not raw_host.startswith("["):
        raw_host = raw_host.split(":")[0]

    try:
        ip = ipaddress.ip_address(raw_host.strip("[]"))
        return {
            "hostname": raw_host,
            "is_ip": True,
            "ip_version": ip.version,
            "subdomain": "",
            "root_domain": raw_host,
            "tld": ""
        }
    except ValueError:
        pass

    if raw_host.isdigit() and len(raw_host) >= 7:
        return {
            "hostname": raw_host,
            "is_ip": True,
            "ip_version": 4,
            "subdomain": "",
            "root_domain": raw_host,
            "tld": ""
        }

    parts = raw_host.split(".")
    if len(parts) <= 1:
        return {
            "hostname": raw_host,
            "is_ip": False,
            "subdomain": "",
            "root_domain": raw_host,
            "tld": ""
        }

    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        tld = last_two
        root_domain = parts[-3] + "." + tld
        subdomain = ".".join(parts[:-3])
    else:
        tld = parts[-1]
        root_domain = parts[-2] + "." + tld
        subdomain = ".".join(parts[:-2])

    return {
        "hostname": raw_host,
        "is_ip": False,
        "subdomain": subdomain,
        "root_domain": root_domain,
        "tld": tld
    }

def detect_typosquatting(root_domain: str) -> Tuple[bool, str, str]:
    """Detects lookalike spelling tricks designed to deceive humans."""
    clean_domain = root_domain.split(".")[0].lower()
    
    substitutions = [
        ("0", "o"), ("1", "l"), ("1", "i"), ("vv", "w"),
        ("rn", "m"), ("cl", "d"), ("3", "e"), ("5", "s")
    ]
    
    normalized = clean_domain
    for char, rep in substitutions:
        normalized = normalized.replace(char, rep)
        
    for brand, legit_dom in TARGET_BRANDS.items():
        if legit_dom and (root_domain == legit_dom or root_domain.endswith("." + legit_dom)):
            continue

        if normalized == brand and clean_domain != brand:
            return True, brand, f"Uses lookalike spelling ('{clean_domain}') to trick you into thinking it is '{brand.capitalize()}'"

        if len(brand) >= 5 and abs(len(clean_domain) - len(brand)) <= 1:
            dist = levenshtein_distance(clean_domain, brand)
            if dist == 1 and clean_domain != brand:
                return True, brand, f"Misspelled domain name ('{clean_domain}') designed to mimic '{brand.capitalize()}'"

    return False, "", ""

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]

def analyze_brand_impersonation(dom_info: Dict[str, Any], url: str) -> Dict[str, Any]:
    """Checks if the link pretends to be a well-known brand."""
    root_domain = dom_info["root_domain"]
    subdomain = dom_info["subdomain"]
    clean_domain = root_domain.split(".")[0].lower()
    
    is_typo, brand_name, explanation = detect_typosquatting(root_domain)
    if is_typo:
        return {
            "is_impersonating": True,
            "targeted_brand": brand_name.capitalize(),
            "legitimate_domain": TARGET_BRANDS.get(brand_name, ""),
            "explanation": explanation,
            "risk_weight": 60
        }

    for brand, legit_dom in TARGET_BRANDS.items():
        if legit_dom and (root_domain == legit_dom or root_domain.endswith("." + legit_dom)):
            continue

        # Case 1: Brand name in subdomain (e.g. paypal.com.verify-user.ru)
        if brand in subdomain:
            return {
                "is_impersonating": True,
                "targeted_brand": brand.capitalize(),
                "legitimate_domain": legit_dom or "Official portal",
                "explanation": f"The link puts '{brand.capitalize()}' in the address to deceive you, but actually takes you to '{root_domain}'.",
                "risk_weight": 65
            }

        # Case 2: Brand name combined in unregistered root domain (e.g. amazon-security.com, netflix-payment.com)
        if brand in clean_domain:
            if len(clean_domain) > len(brand):
                return {
                    "is_impersonating": True,
                    "targeted_brand": brand.capitalize(),
                    "legitimate_domain": legit_dom or "Official portal",
                    "explanation": f"Combines the brand name '{brand.capitalize()}' with extra words in an unauthorized website address ('{root_domain}').",
                    "risk_weight": 60
                }

        # Case 3: Brand name in path with login/account keywords on untrusted domain
        if brand in url.lower() and root_domain not in TRUSTED_AUTHORITY_DOMAINS:
            for kw in ["login", "signin", "verify", "account", "secure", "wallet", "banking", "payment"]:
                if kw in url.lower():
                    return {
                        "is_impersonating": True,
                        "targeted_brand": brand.capitalize(),
                        "legitimate_domain": legit_dom or "Official portal",
                        "explanation": f"Mentions '{brand.capitalize()}' alongside a login/account request on an unofficial website.",
                        "risk_weight": 55
                    }

    return {
        "is_impersonating": False,
        "targeted_brand": None,
        "legitimate_domain": None,
        "explanation": "No known brand impersonation detected.",
        "risk_weight": 0
    }

def inspect_url_features(url: str) -> Dict[str, Any]:
    """Extracts human-understandable safety signals from the link."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    raw_host = parsed.netloc.lower()
    host_no_port = raw_host.split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""
    
    dom_info = parse_domain_structure(host_no_port)
    root_domain = dom_info["root_domain"]
    subdomain = dom_info["subdomain"]
    tld = dom_info["tld"]
    is_ip = dom_info["is_ip"]

    indicators = []
    
    is_trusted_authority = (root_domain in TRUSTED_AUTHORITY_DOMAINS)
    is_shortener = (root_domain in URL_SHORTENERS) or (host_no_port in URL_SHORTENERS)
    is_suspicious_tld = (tld in SUSPICIOUS_TLDS)
    entropy = calculate_shannon_entropy(host_no_port)
    brand_analysis = analyze_brand_impersonation(dom_info, url)
    
    domain_score = 0
    lexical_score = 0
    protocol_score = 0
    
    # 1. Official vs Fake Website Check
    if is_trusted_authority and not brand_analysis["is_impersonating"]:
        indicators.append({
            "severity": "safe",
            "title": "Verified Official Website",
            "description": f"'{root_domain}' is an established, verified official website."
        })
        domain_score = 0
    else:
        if is_ip:
            domain_score += 50
            indicators.append({
                "severity": "critical",
                "title": "Uses Numbers Instead of Website Name",
                "description": f"The link uses a raw number address ({host_no_port}) instead of a real company name. Scammers often use this trick."
            })
            
        if brand_analysis["is_impersonating"]:
            domain_score += brand_analysis["risk_weight"]
            indicators.append({
                "severity": "critical",
                "title": f"Fake {brand_analysis['targeted_brand']} Imitation",
                "description": brand_analysis["explanation"]
            })
            
        if is_suspicious_tld:
            domain_score += 35
            indicators.append({
                "severity": "warning",
                "title": f"Unusual Website Ending (.{tld})",
                "description": f"The website ends in '.{tld}', which is frequently used for throwaway scam websites."
            })
            
        if is_shortener:
            domain_score += 35
            indicators.append({
                "severity": "warning",
                "title": "Hidden Destination Link",
                "description": f"This is a shortened link ({host_no_port}). It hides where you will actually be taken."
            })
            
        if entropy > 3.85:
            domain_score += 25
            indicators.append({
                "severity": "warning",
                "title": "Random Gibberish Name",
                "description": "The website name looks scrambled or randomly generated, commonly seen in automated scam setups."
            })

    # 2. Check for Credential / Scam Lures in Domain, Subdomain, Path, and Query
    full_url_lower = url.lower()
    host_lower = host_no_port.lower()
    
    # Check High-Risk Lures
    high_lures_found = [kw for kw in HIGH_RISK_LURES if kw in host_lower or kw in full_url_lower]
    med_lures_found = [kw for kw in MEDIUM_RISK_LURES if kw in host_lower or kw in full_url_lower]
    
    if high_lures_found and not is_trusted_authority:
        lexical_score += min(len(high_lures_found) * 25, 60)
        indicators.append({
            "severity": "critical" if len(high_lures_found) >= 2 or brand_analysis["is_impersonating"] else "warning",
            "title": "Asks for Login, Banking, or Account Info",
            "description": f"The link contains sensitive credential/banking keywords ({', '.join(high_lures_found[:3])}) on an unverified site."
        })
    elif med_lures_found and not is_trusted_authority:
        lexical_score += min(len(med_lures_found) * 10, 25)
        indicators.append({
            "severity": "info",
            "title": "Contains Service or Portal Keywords",
            "description": f"The link mentions keywords ({', '.join(med_lures_found[:3])})."
        })
    elif (high_lures_found or med_lures_found) and is_trusted_authority:
        indicators.append({
            "severity": "info",
            "title": "Official Portal / Login Page",
            "description": "This is an official login/service portal on a verified website."
        })

    # Dangerous automatic file download
    path_lower = path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if path_lower.endswith(ext):
            lexical_score += 55
            indicators.append({
                "severity": "critical",
                "title": "Automatic File Download",
                "description": f"This link immediately downloads a program file ({ext}) to your device, which could be harmful."
            })
            break

    # Tricky @ symbol
    if "@" in url:
        lexical_score += 40
        indicators.append({
            "severity": "critical",
            "title": "Misleading Address Trick (@)",
            "description": "The link contains an '@' symbol, which can hide the real website you will visit."
        })

    # Lookalike characters (Punycode)
    if "xn--" in host_no_port:
        lexical_score += 35
        indicators.append({
            "severity": "warning",
            "title": "Deceptive Lookalike Letters",
            "description": "Uses foreign lookalike letters to visually mimic a real website address."
        })

    # Consecutive // in path
    if path.count("//") > 0:
        lexical_score += 20
        indicators.append({
            "severity": "warning",
            "title": "Double Slash Redirect Trick",
            "description": "Contains double slashes ('//') inside the link, often used to silently redirect you to an unsafe site."
        })

    # Multiple hyphens in domain
    if host_no_port.count("-") >= 2 and not is_trusted_authority:
        lexical_score += 15
        indicators.append({
            "severity": "warning",
            "title": "Multiple Hyphens in Address",
            "description": f"The domain contains multiple hyphens ({host_no_port.count('-')}), a pattern common in phishing setups."
        })

    # Long complicated URL
    if len(url) > 180 and not is_trusted_authority:
        lexical_score += 15
        indicators.append({
            "severity": "info",
            "title": "Unusually Long Link",
            "description": f"This link is very long ({len(url)} characters), often used to hide misleading text on phone screens."
        })

    # 3. Secure Connection (HTTPS) Check
    if scheme != "https":
        if is_ip or not is_trusted_authority:
            protocol_score += 30
            indicators.append({
                "severity": "warning",
                "title": "Not Secure (No HTTPS Lock)",
                "description": "This website is not encrypted. Any information or passwords you type could be intercepted."
            })
    else:
        indicators.append({
            "severity": "safe",
            "title": "Secure Connection (HTTPS)",
            "description": "The connection to this website is securely encrypted."
        })

    domain_score = min(100, domain_score)
    lexical_score = min(100, lexical_score)
    protocol_score = min(100, protocol_score)

    heuristic_combined = int(
        (0.50 * domain_score) + (0.35 * lexical_score) + (0.15 * protocol_score)
    )

    return {
        "url": url,
        "scheme": scheme,
        "hostname": host_no_port,
        "subdomain": subdomain,
        "root_domain": root_domain,
        "tld": tld,
        "path": path,
        "query": query,
        "is_ip": is_ip,
        "is_trusted_authority": is_trusted_authority,
        "is_shortener": is_shortener,
        "is_suspicious_tld": is_suspicious_tld,
        "brand_analysis": brand_analysis,
        "domain_score": domain_score,
        "lexical_score": lexical_score,
        "protocol_score": protocol_score,
        "heuristic_combined": min(100, heuristic_combined),
        "indicators": indicators
    }

def evaluate_url_threat(model, url: str) -> Dict[str, Any]:
    """
    Evaluates the link and provides an everyday human verdict.
    """
    features = inspect_url_features(url)
    is_trusted = features["is_trusted_authority"]
    brand_impersonation = features["brand_analysis"]["is_impersonating"]
    heuristic_score = features["heuristic_combined"]

    # Raw model probability
    raw_ml_prob = 0.5
    if model is not None:
        try:
            probs = model.predict_proba([url])[0]
            classes = list(model.named_steps["classifier"].classes_)
            if 0 in classes:
                raw_ml_prob = float(probs[classes.index(0)])
            else:
                raw_ml_prob = 0.5
        except Exception:
            raw_ml_prob = 0.5

    # Calibrate probability:
    # 1. Trusted authority domain (e.g. google.com, github.com, render.com, apple.com):
    if is_trusted and not brand_impersonation:
        calibrated_ml_prob = min(raw_ml_prob * 0.05, 0.05)
        final_risk = min(12, int(round(0.30 * (calibrated_ml_prob * 100) + 0.70 * heuristic_score)))
    else:
        # Untrusted domain:
        calibrated_ml_prob = raw_ml_prob
        calibrated_ml_score = int(round(calibrated_ml_prob * 100))
        
        # Calculate overall risk score
        if brand_impersonation:
            # Active brand spoofing is critical
            final_risk = max(78, int(round(0.40 * calibrated_ml_score + 0.60 * heuristic_score)))
        elif features["is_ip"]:
            # Raw number IP address is critical
            final_risk = max(75, int(round(0.40 * calibrated_ml_score + 0.60 * heuristic_score)))
        elif features["is_shortener"]:
            # Shortened link
            final_risk = max(45, int(round(0.40 * calibrated_ml_score + 0.60 * heuristic_score)))
        elif features["is_suspicious_tld"] or features["lexical_score"] >= 30:
            # High-risk TLD or sensitive credential lures
            final_risk = max(65, int(round(0.45 * calibrated_ml_score + 0.55 * heuristic_score)))
        elif features["domain_score"] >= 25 or features["lexical_score"] >= 15:
            # Notable suspicious patterns
            final_risk = max(45, int(round(0.45 * calibrated_ml_score + 0.55 * heuristic_score)))
        else:
            # General unknown domain with no suspicious markers
            final_risk = int(round(0.20 * calibrated_ml_score + 0.80 * heuristic_score))

    # General scoring calculation completed

    final_risk = max(0, min(100, final_risk))

    # Everyday human risk tiers
    if final_risk >= 70:
        tier = "High Risk"
        tier_label = "DANGEROUS"
        tier_color = "#EF4444"      # Clear vibrant red
        tier_bg = "rgba(239, 68, 68, 0.12)"
        tier_border = "#EF4444"
        tier_icon = "🚨"
        simple_title = "Dangerous — Likely a scam or fake website"
        simple_summary = "Do not open this link. It looks designed to steal your account, password, or financial information."
        action_advice = "🚨 WHAT TO DO: Delete or ignore this link. Never type your password or credit card details here."
    elif final_risk >= 40:
        tier = "Suspicious"
        tier_label = "SUSPICIOUS"
        tier_color = "#F59E0B"      # Clear warm amber/orange
        tier_bg = "rgba(245, 158, 11, 0.12)"
        tier_border = "#F59E0B"
        tier_icon = "⚠️"
        simple_title = "Suspicious — Proceed with caution"
        simple_summary = "This link uses unusual patterns or hides where it leads (such as a link shortener). Verify who sent it before clicking."
        action_advice = "⚠️ WHAT TO DO: Only proceed if you completely trust the sender. Do not enter personal or payment details."
    elif final_risk >= 20:
        tier = "Low Risk"
        tier_label = "LOW RISK"
        tier_color = "#3B82F6"      # Clear friendly blue
        tier_bg = "rgba(59, 130, 246, 0.12)"
        tier_border = "#3B82F6"
        tier_icon = "ℹ️"
        simple_title = "Low Risk — Generally safe"
        simple_summary = "This website appears normal and doesn't show common scam patterns. Standard browsing caution applies."
        action_advice = "ℹ️ WHAT TO DO: Safe for standard browsing. As always, keep your browser updated."
    else:
        tier = "Safe"
        tier_label = "SAFE TO VISIT"
        tier_color = "#10B981"      # Clear emerald green
        tier_bg = "rgba(16, 185, 129, 0.12)"
        tier_border = "#10B981"
        tier_icon = "✅"
        simple_title = "Safe — Verified legitimate website"
        simple_summary = "This link belongs to a recognized, genuine service with a secure connection. No scam signs found."
        action_advice = "✅ WHAT TO DO: You can safely visit this website."

    return {
        "url": url,
        "risk_score": final_risk,
        "risk_tier": tier,
        "tier_label": tier_label,
        "tier_color": tier_color,
        "tier_bg": tier_bg,
        "tier_border": tier_border,
        "tier_icon": tier_icon,
        "simple_title": simple_title,
        "simple_summary": simple_summary,
        "action_advice": action_advice,
        "phishing_probability": round(calibrated_ml_prob, 4),
        "features": features,
        "indicators": features["indicators"]
    }

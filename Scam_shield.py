import re
from datetime import datetime


def analyze_message(message):
    message = message.lower().strip()

    red_flags = {
        "urgent": 15,
        "immediately": 15,
        "you won": 20,
        "prize": 20,
        "pay": 25,
        "otp": 30,
        "pin": 30,
        "cvv": 30,
        "password": 30,
        "click here": 20,
        "verify": 15,
        "blocked": 20,
        "kyc": 20
    }

    risk_score = 0
    detected_flags = []

    for flag, score in red_flags.items():
        if flag in message:
            risk_score += score
            detected_flags.append(flag)

    if risk_score <= 25:
        risk_level = "LOW"
    elif risk_score <= 50:
        risk_level = "MEDIUM"
    elif risk_score <= 75:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    patterns = []

    if "account" in message and "blocked" in message:
        patterns.append("Account Threat")

    if "urgent" in message and ("click here" in message or "http" in message):
        patterns.append("Urgency + Suspicious Link")

    if ("pay" in message or "payment" in message) and (
        "you won" in message or "prize" in message or "reward" in message
    ):
        patterns.append("Prize + Payment Request")

    if "otp" in message and ("click here" in message or "http" in message):
        patterns.append("OTP Request + Suspicious Link")

    if "kyc" in message and ("verify" in message or "update" in message):
        patterns.append("KYC Verification Request")

    if "http://" in message:
        patterns.append("Insecure HTTP Link")

    if "https://" in message:
        patterns.append("Link Detected")

    # Scam classification
    if (
        "upi" in message
        or "payment" in message
        or "transfer" in message
        or "upi id" in message
    ):
        scam_type = "UPI / Payment Scam"

    elif (
        "job" in message
        or "work from home" in message
        or "salary" in message
    ) and (
        "pay" in message
        or "registration" in message
        or "fee" in message
    ):
        scam_type = "Job / Recruitment Scam"

    elif (
        "prize" in message
        or "you won" in message
        or "lottery" in message
        or "reward" in message
    ):
        scam_type = "Prize / Lottery Scam"

    elif (
        "investment" in message
        or "profit" in message
        or "returns" in message
        or "double your money" in message
    ):
        scam_type = "Investment Scam"

    elif (
        "delivery" in message
        or "parcel" in message
        or "courier" in message
    ):
        scam_type = "Delivery Scam"

    elif (
        "kyc" in message
        or "bank account" in message
        or "bank" in message
        or "account" in message
    ):
        scam_type = "Banking / KYC Scam"

    elif (
        "click here" in message
        or "verify your bank account" in message
        or "login" in message
        or "http://" in message
        or "https://" in message
    ):
        scam_type = "Phishing"

    elif (
        "official" in message
        or "customer care" in message
        or "support team" in message
        or "representative" in message
    ):
        scam_type = "Impersonation"

    else:
        scam_type = "Unknown"

    source_info = analyze_source(message)
    coverage = analyze_coverage(message, source_info)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "scam_type": scam_type,
        "detected_flags": detected_flags,
        "patterns": patterns,
        "source": source_info,
        "coverage": coverage
    }


def get_recommendation(message, result):
    message = message.lower()

    recommendations = []

    if any(flag in result["detected_flags"] for flag in ["otp", "pin", "cvv", "password"]):
        recommendations.append("Do not share OTP, PIN, CVV or password.")

    if any(word in message for word in ["pay", "payment", "transfer", "upi"]):
        recommendations.append("Do not send money until the request is verified.")

    if "click here" in message or "http://" in message or "https://" in message:
        recommendations.append("Do not click suspicious links.")

    if any(word in message for word in ["prize", "reward", "lottery", "you won"]):
        recommendations.append("Verify the prize or reward through an official source.")

    if "account" in message and (
        "blocked" in message or "verify" in message or "kyc" in message
    ):
        recommendations.append("Verify account or KYC status through the official app or website.")

    if not recommendations:
        recommendations.append("Verify the sender before taking any action.")

    return " ".join(recommendations)


def analyze_source(message):
    source = {
        "sender": "Not detected",
        "identifier": "Not detected",
        "category": "Unknown",
        "links": [],
        "domains": [],
        "financial_info": [],
        "sensitive_info": []
    }

    # Phone number
    phone = re.search(r"(?:\+91[\s-]?)?[6-9]\d{9}", message)
    if phone:
        source["identifier"] = phone.group()

    # URL
    links = re.findall(r"https?://[^\s]+", message)
    source["links"] = links

    for link in links:
        domain_match = re.search(r"https?://([^/\s]+)", link)
        if domain_match:
            source["domains"].append(domain_match.group(1))

    # Financial information
    amounts = re.findall(
        r"(?:₹|rs\.?|inr)\s?[\d,]+(?:\.\d+)?",
        message,
        flags=re.IGNORECASE
    )

    if amounts:
        source["financial_info"].extend(amounts)

    if "upi" in message:
        source["financial_info"].append("UPI")

    if any(word in message for word in ["payment", "pay", "transfer", "bank"]):
        source["financial_info"].append("Payment/Banking")

    # Sensitive information
    sensitive_words = ["otp", "pin", "cvv", "password", "kyc"]
    for word in sensitive_words:
        if word in message:
            source["sensitive_info"].append(word.upper())

    # Source category
    if "whatsapp" in message:
        source["category"] = "Messaging App"
    elif "sms" in message:
        source["category"] = "SMS"
    elif "email" in message or "@" in message:
        source["category"] = "Email"
    elif source["links"]:
        source["category"] = "Web Link"
    elif source["financial_info"]:
        source["category"] = "Financial"
    else:
        source["category"] = "Text Message"

    return source


def analyze_coverage(message, source_info):
    message_available = bool(message.strip())
    sender_available = source_info["sender"] != "Not detected"
    identifier_available = source_info["identifier"] != "Not detected"

    if message_available and sender_available and identifier_available:
        coverage = "HIGH"
    elif message_available and (sender_available or identifier_available):
        coverage = "MEDIUM"
    elif message_available:
        coverage = "PARTIAL"
    else:
        coverage = "LOW"

    return {
        "message_available": message_available,
        "sender_available": sender_available,
        "identifier_available": identifier_available,
        "coverage": coverage
    }


def get_analysis_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

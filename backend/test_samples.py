"""TruthShield – Sample Test Inputs
Run: python test_samples.py (requires OPENAI_API_KEY in .env)
"""

from analyzer import analyze_text

SAMPLES = {
    "Job Scam": (
        "Congratulations! You have been selected for a work-from-home job. "
        "Earn ₹50,000/month. Pay ₹499 registration fee to start. "
        "Limited slots available — join our Telegram channel now!"
    ),
    "Bank Phishing": (
        "Dear Customer, your SBI account has been temporarily blocked due to "
        "incomplete KYC update. Click here to verify your account immediately. "
        "Share your Aadhaar and PAN card details along with OTP to reactivate. "
        "Your debit card blocked — call this number within 24 hours."
    ),
    "Safe Content": (
        "The quarterly report shows steady growth across all departments. "
        "Revenue increased by 12% compared to last quarter, driven primarily "
        "by expansion in the Southeast Asian market. The board has approved "
        "the new product roadmap for Q3 2026."
    ),
    "Lottery Scam": (
        "You have won $5,000,000 in the international lottery! "
        "Wire transfer processing fee of $500 required. "
        "Contact our beneficiary department urgently to claim your prize."
    ),
    "AI Generated Text": (
        "In today's world, it's important to note that navigating the complexities "
        "of digital security has become multifaceted. Moreover, leveraging "
        "comprehensive strategies can facilitate groundbreaking outcomes."
    ),
}


def main():
    print("=" * 70)
    print("TruthShield — Sample Test Results")
    print("=" * 70)

    for name, text in SAMPLES.items():
        result = analyze_text(text)
        print(f"\n{'─' * 60}")
        print(f"📋 {name}")
        print(f"   Score: {result.risk_score}/100  |  Class: {result.classification}")
        print(f"   Type: {result.scam_type}  |  Emotional: {result.emotional_manipulation}")
        print(f"   Phrases: {result.suspicious_phrases[:5]}")
        print(f"   Summary: {result.summary[:100]}...")

        # Validate scoring
        if "Scam" in name or "Phishing" in name:
            assert result.risk_score >= 70, f"FAIL: {name} scored only {result.risk_score}"
            print(f"   ✅ PASS (score >= 70)")
        elif name == "Safe Content":
            assert result.risk_score <= 30, f"FAIL: {name} scored {result.risk_score}"
            print(f"   ✅ PASS (score <= 30)")

    print(f"\n{'=' * 70}")
    print("All tests passed!")


if __name__ == "__main__":
    main()

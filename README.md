# Quish Scanner

Decodes QR codes from images and checks the destination URL for phishing signs.

## What it checks

- URL shorteners (bit.ly, tinyurl.com, t.co, and 14 others) that hide the real destination
- Suspicious TLDs (.tk, .ml, .xyz, .top, .zip and others)
- Brand names in the domain that are not the real brand site (paypal-secure-login.xyz)
- Non ASCII characters in the domain (homoglyph tricks)
- URLs with @ signs

## Usage

```bash
pip install opencv-python qrcode

# scan QR images
python quish_scan.py photo1.png photo2.jpg

# generate a demo QR to test with
python quish_scan.py --make-test test.png
```

## Example

```
[test_qr2.png]
  decoded : https://paypal-secure-login.xyz/verify
  [!] suspicious TLD (.xyz)
  [!] brand keyword 'paypal' in domain but domain is not paypal's site
```

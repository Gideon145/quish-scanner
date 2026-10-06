"""Quish Scanner: decode QR codes and check the destination for phishing signs.

Usage:
    python quish_scan.py image.png [image2.jpg ...]
    python quish_scan.py --make-test test.png   (generate a demo QR)
"""
import argparse
import re
import sys
from urllib.parse import urlsplit

import cv2

# Common URL shorteners that hide the real destination.
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "qr.ae",
]

# TLDs that are cheap or commonly abused in phishing.
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".zip", ".click", ".icu"]

# Brands attackers impersonate most, checked against the domain.
KEYWORDS = ["paypal", "apple", "microsoft", "amazon", "hsbc", "barclays", "halifax",
            "natwest", "lloyds", "santander", "monzo", "revolut", "netflix", "google",
            "facebook", "instagram", "whatsapp", "gov", "hmrc", "dvla", "nhs"]


def analyze(url: str) -> list[str]:
    flags = []
    host = urlsplit(url).netloc.lower()

    if not url.startswith("http"):
        flags.append("no http scheme")

    for s in SHORTENERS:
        if host.endswith(s):
            flags.append(f"shortened link ({s}), real destination hidden")
            break

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            flags.append(f"suspicious TLD ({tld})")
            break

    for kw in KEYWORDS:
        if kw in host:
            # brand name in domain but domain is not the real brand site
            if not (host == kw or host.endswith("." + kw + ".com") or
                    host.endswith("." + kw + ".co.uk") or host.endswith("." + kw + ".org")):
                flags.append(f"brand keyword '{kw}' in domain but domain is not {kw}'s site")
            break

    if re.search(r"[^\x00-\x7F]", host):
        flags.append("non ascii characters in domain (possible homoglyph)")

    if url.count("@") > 0:
        flags.append("contains @ (possible credential trick)")

    return flags


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="*")
    ap.add_argument("--make-test")
    args = ap.parse_args()

    if args.make_test:
        import qrcode
        img = qrcode.make("https://bit.ly/example-redirect")
        img.save(args.make_test)
        print(f"wrote test QR to {args.make_test}")
        return 0

    if not args.images:
        print("usage: python quish_scan.py <image files>")
        return 2

    detector = cv2.QRCodeDetector()
    for path in args.images:
        frame = cv2.imread(path)
        if frame is None:
            print(f"[!] could not read {path}")
            continue
        data, pts, _ = detector.detectAndDecode(frame)
        print(f"\n[{path}]")
        if not data:
            print("  no QR code found")
            continue
        print(f"  decoded : {data}")
        flags = analyze(data)
        if flags:
            for f in flags:
                print(f"  [!] {f}")
        else:
            print("  [ok] nothing suspicious")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

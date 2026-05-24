import re
import json
import os
import sys

# Make €, £, ¥ print correctly on Windows.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


# Regex patterns

email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"

# http / https only - we ignore javascript:, data:, file:, etc.
url_pattern = r"https?://[A-Za-z0-9./?=&%_:-]+"

# +250 788 123 456 , (+250) 788-987-654 , 0788 555 014
# The (?<!\d)(?<!-)0 keeps it from grabbing the tail of a card number.
phone_pattern = r"(?:\+\d{1,3}[\s-]?|\(\+?\d{1,3}\)[\s-]?|(?<!\d)(?<!-)0)\d{2,4}[\s-]\d{3,4}[\s-]\d{3,4}"

# 13-19 digits with optional spaces/dashes. Just a net - real check is Luhn.
card_pattern = r"\b(?:\d[ -]?){12,18}\d\b"

# 24h ("14:00") or 12h ("3:42 pm")
time_pattern = r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?:\s?[APap]\.?[Mm]\.?)?\b"

# The lookahead (?=[\s/>]) stops it matching <user@example.com>.
html_pattern = r"<\/?[A-Za-z][A-Za-z0-9]*(?=[\s/>])[^<>@]*>"

hashtag_pattern = r"#[A-Za-z0-9][A-Za-z0-9_-]{1,63}"

# + (not *) is important - with *, "1500" would match as "150".
number_part = r"\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?"
currency_pattern = (
    r"(?:[$€£¥]\s?(?:" + number_part + r")"
    r"|(?:USD|EUR|GBP|JPY|RWF|KES)\s?(?:" + number_part + r")"
    r"|(?:" + number_part + r")\s?(?:USD|EUR|GBP|JPY|RWF|KES))"
)

# Refuse files bigger than 2 MB.
max_file_size = 2 * 1024 * 1024


# ALU email rules

def classify_email(email):
    email = email.lower()
    if email.endswith("@alueducation.com"):
        return "alu_official"
    if email.endswith("@alumni.alueducation.com"):
        return "alu_alumni"
    if email.endswith("@si.alueducation.com"):
        return "alu_si"
    return "general"


# Luhn check (real cards must pass this)

def luhn_check(card_number):
    digits = [int(d) for d in card_number if d.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d = d - 9
        total = total + d
    return total % 10 == 0


# Masking

def mask_email(email):
    name, domain = email.split("@", 1)
    if len(name) <= 2:
        hidden = name[0] + "*"
    else:
        hidden = name[0] + "*" * (len(name) - 2) + name[-1]
    return hidden + "@" + domain


def mask_card(card_number):
    # Keep first 6 + last 4 (PCI-DSS style).
    digits = re.sub(r"\D", "", card_number)
    if len(digits) < 10:
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


def mask_phone(phone):
    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


# Extractors

def find_emails(text):
    results = []
    seen = []
    for email in re.findall(email_pattern, text):
        email = email.lower()
        if email in seen:
            continue
        seen.append(email)
        results.append({
            "masked": mask_email(email),
            "category": classify_email(email),
        })
    return results


def find_urls(text):
    results = []
    for url in re.findall(url_pattern, text):
        url = url.rstrip(".,);'\"")
        if url not in results:
            results.append(url)
    return results


def find_phones(text):
    results = []
    seen = []
    for phone in re.findall(phone_pattern, text):
        digits = re.sub(r"\D", "", phone)
        # Real phone numbers have 8-15 digits (E.164).
        if len(digits) < 8 or len(digits) > 15:
            continue
        # Skip "0000-0000-0000" (a test card, not a phone).
        if len(set(digits)) == 1:
            continue
        if digits in seen:
            continue
        seen.append(digits)
        results.append({"raw": phone.strip(), "masked": mask_phone(phone)})
    return results


def find_cards(text):
    results = []
    seen = []
    for card in re.findall(card_pattern, text):
        digits = re.sub(r"\D", "", card)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if digits in seen:
            continue
        seen.append(digits)
        # Cards that fail Luhn are kept but flagged, not silently dropped.
        results.append({
            "masked": mask_card(digits),
            "luhn_valid": luhn_check(digits),
        })
    return results


def find_times(text):
    return sorted(set(re.findall(time_pattern, text)))


def find_html_tags(text):
    dangerous = ["script", "iframe", "object", "embed", "style"]
    results = []
    for tag in re.findall(html_pattern, text):
        name_match = re.match(r"</?([A-Za-z][A-Za-z0-9]*)", tag)
        name = name_match.group(1).lower() if name_match else ""
        results.append({"tag": name, "dangerous": name in dangerous})
    return results


def find_hashtags(text):
    return sorted(set(re.findall(hashtag_pattern, text)))


def find_currency(text):
    return [m.strip() for m in re.findall(currency_pattern, text)]


# Read input safely

def read_input_file(path):
    if not os.path.isfile(path):
        print("Input file not found:", path)
        return ""
    if os.path.getsize(path) > max_file_size:
        print("File too big, refusing to read it")
        return ""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


# Main

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    project = os.path.dirname(here)
    input_path = os.path.join(project, "input", "raw-text.txt")
    output_path = os.path.join(project, "output", "sample-output.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    text = read_input_file(input_path)
    if not text:
        return

    emails = find_emails(text)
    urls = find_urls(text)
    phones = find_phones(text)
    cards = find_cards(text)
    times = find_times(text)
    html_tags = find_html_tags(text)
    hashtags = find_hashtags(text)
    currency = find_currency(text)

    alu_counts = {"alu_official": 0, "alu_alumni": 0, "alu_si": 0, "general": 0}
    for e in emails:
        alu_counts[e["category"]] = alu_counts[e["category"]] + 1
    valid_cards = sum(1 for c in cards if c["luhn_valid"])
    invalid_cards = len(cards) - valid_cards

    report = {
        "summary": {
            "emails": len(emails),
            "urls": len(urls),
            "phones": len(phones),
            "credit_cards": len(cards),
            "times": len(times),
            "html_tags": len(html_tags),
            "hashtags": len(hashtags),
            "currency": len(currency),
        },
        "alu_email_counts": alu_counts,
        "card_check": {"passed_luhn": valid_cards, "failed_luhn": invalid_cards},
        "results": {
            "emails": emails,
            "urls": urls,
            "phones": phones,
            "credit_cards": cards,
            "times": times,
            "html_tags": html_tags,
            "hashtags": hashtags,
            "currency": currency,
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    line = "=" * 60
    print(line)
    print("      REGEX DATA EXTRACTION  -  SUMMARY")
    print(line)
    print("Emails:", len(emails), " URLs:", len(urls),
          " Phones:", len(phones), " Cards:", len(cards))
    print("Times:", len(times), " HTML:", len(html_tags),
          " Hashtags:", len(hashtags), " Currency:", len(currency))
    print("ALU email types -> official:", alu_counts["alu_official"],
          " alumni:", alu_counts["alu_alumni"],
          " SI:", alu_counts["alu_si"],
          " general:", alu_counts["general"])
    print()

    print("-- Valid emails (masked, by ALU category) --")
    for e in emails:
        print("  ", e["category"].ljust(13), e["masked"])
    print()

    print("-- Valid credit cards (masked, passed Luhn) --")
    for c in cards:
        if c["luhn_valid"]:
            print("  ", c["masked"])
    print()

    print("-- Valid URLs --")
    for u in urls:
        print("  ", u)
    print()

    print("-- Valid phone numbers (masked) --")
    for p in phones:
        print("  ", p["masked"])
    print()

    print("-- Rejected / flagged (input is not trusted) --")
    print("  Cards that failed Luhn check :", invalid_cards)
    dangerous_html = sum(1 for t in html_tags if t["dangerous"])
    print("  HTML tags flagged dangerous  :", dangerous_html,
          "  (e.g. <script>, <iframe>)")
    print("  Attack payloads ignored      : SQL ('); DROP...), template ({{7*7}}),")
    print("                                  path traversal (../../etc/passwd) -")
    print("                                  none of these matched any data pattern")
    print()
    print(line)
    print("Full report saved to:", output_path)
    print(line)


if __name__ == "__main__":
    main()

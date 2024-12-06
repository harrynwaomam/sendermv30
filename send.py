import os
import smtplib
import dns.resolver
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
import configparser
import random
from datetime import datetime, timedelta
import re
import time
import base64
import dkim
import socket
import requests
from colorama import Fore, Style, init
import contextlib
import threading
from queue import Queue

init(autoreset=True)

# === CONFIGURATION HANDLING ===
config = configparser.ConfigParser()
config.read("config.ini")

letters_dir = "letters"
randomizers_dir = "randomizers"
victims_file = "victims.txt"
frommail_file = "frommail.txt"
fromname_file = "fromname.txt"
subject_file = "subject.txt"
link_file = "link.txt"
reply_to = config.get("SETTINGS", "reply-to", fallback="replyto@[[smtpdomain]]").strip()
priority = config.getint("SETTINGS", "priority", fallback=1)
return_path = config.get("SETTINGS", "return-path", fallback="bounce@[[smtpdomain]]").strip()
boundary_template = config.get("SETTINGS", "boundary", fallback="[[Uchar5]][[random4]][[char9]][[random4]][[Uchar5]][[char6]][[random5]]==").strip()
msg_id_template = config.get("SETTINGS", "MSG_ID", fallback="[[Uchar5]][[random4]][[Uchar5]][[random4]][[random4]]@[[random4]][[Uchar5]].[[smtpdomain]]").strip()
dkim_enabled = config.getboolean("SETTINGS", "SignEmail_With_DKim", fallback=False)
dkim_folder = "dkim"
dkim_log_file = "dkimfile.log"
sleep_enabled = config.getboolean("SETTINGS", "sleep", fallback=True)
sleep_seconds = config.getint("SETTINGS", "sleep_seconds", fallback=5)
mails_before_sleep = config.getint("SETTINGS", "mails_before_sleep", fallback=150)
hostname_mode = config.get("SETTINGS", "hostname", fallback="smtp").lower()
manual_hostname = config.get("SETTINGS", "manual_hostname", fallback="example.com")
helo_template = config.get("SETTINGS", "HELO", fallback="[[smtpdomain]]").strip()
letter_format = config.get("SETTINGS", "letter_format", fallback="txt").lower()
specific_letter = config.get("SETTINGS", "specific_letter", fallback="").strip()
send_html_letter = config.getboolean("SETTINGS", "send_html_letter", fallback=True)
threads_count = config.getint("SETTINGS", "threads_count", fallback=10)

# === LOGGING FUNCTIONS ===
def log_dkim(message):
    with open(dkim_log_file, "a") as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")

def log_general(message, success=True):
    color = Fore.GREEN if success else Fore.RED
    print(f"{color}{datetime.now()} - {message}{Style.RESET_ALL}")

def log_to_file(message, filename):
    with open(filename, "a") as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")

# === HOSTNAME DETERMINATION ===
def determine_hostname(mode, smtp_domain, manual_hostname):
    if mode == "":
        try:
            public_ip = requests.get("https://api.ipify.org?format=text").text
            reverse_dns = socket.gethostbyaddr(public_ip)[0]
            return reverse_dns
        except Exception:
            log_general(f"Failed to resolve RDNS for IP. Defaulting to manual hostname {manual_hostname}")
            return manual_hostname
    elif mode == "smtp":
        return smtp_domain
    elif mode == "manual":
        return manual_hostname
    return manual_hostname

# === RANDOMIZER AND CUSTOMIZER HANDLING ===
randomizer_files = {
    f"random_{key}": [line.strip() for line in open(os.path.join(randomizers_dir, f"random_{key}.txt"))]
    for key in ["city", "browser", "state", "hostname", "firstname", "lastname", "surname", "address", "country", "continent"]
    if os.path.exists(os.path.join(randomizers_dir, f"random_{key}.txt"))
}

customizer_files = {
    f"custom_{key}": [line.strip() for line in open(os.path.join(randomizers_dir, f"custom_{key}.txt"))]
    for key in ["city", "browser", "state", "hostname", "firstname", "lastname", "surname", "address", "country", "continent"]
    if os.path.exists(os.path.join(randomizers_dir, f"custom_{key}.txt"))
}

# === FILE HANDLING FUNCTIONS ===
def load_file_lines(file_path):
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        log_general(f"Error: {file_path} not found.", success=False)
        return []

def get_random_line(file_path):
    lines = load_file_lines(file_path)
    return random.choice(lines) if lines else ""

# === LETTER SELECTION ===
def select_letter():
    if specific_letter:
        specific_path = os.path.join(letters_dir, specific_letter)
        if os.path.exists(specific_path):
            with open(specific_path, "r") as file:
                return file.read()
        log_general(f"Error: Specific letter '{specific_letter}' not found.", success=False)
        return None
    else:
        files = [f for f in os.listdir(letters_dir) if f.endswith(f".{letter_format}")]
        if files:
            with open(os.path.join(letters_dir, random.choice(files)), "r") as file:
                return file.read()
        log_general(f"No {letter_format} files found in {letters_dir}.", success=False)
        return None

# === PLACEHOLDER REPLACEMENT ===
def replace_placeholders(text, email, sender_email, recipient_index):
    if not text:
        return ""
    current_date = datetime.now().strftime("%B %d, %Y")
    recipient_domain = email.split("@")[1] if email else ""
    sender_domain = sender_email.split("@")[1] if sender_email else ""
    user = email.split("@")[0] if email else ""

    def extract_company_name(domain):
        parts = domain.split(".")
        if len(parts) == 1:
            return parts[0].capitalize()
        elif len(parts) == 2:
            return parts[0].capitalize()
        elif len(parts[-2]) < 4:
            return parts[-3].capitalize()
        return f"{parts[-3].capitalize()}-{parts[-2].capitalize()}"

    replacements = {
        "email": email,
        "Email": email.capitalize(),
        "EMAIL": email.upper(),
        "user": user,
        "User": user.capitalize(),
        "USER": user.upper(),
        "domain": recipient_domain,
        "Domain": recipient_domain.capitalize(),
        "DOMAIN": recipient_domain.upper(),
        "sender": sender_email,
        "Sender": sender_email.capitalize(),
        "SENDER": sender_email.upper(),
        "smtpdomain": sender_domain,
        "Smtpdomain": sender_domain.capitalize(),
        "SMTPDOMAIN": sender_domain.upper(),
        "company": extract_company_name(recipient_domain).lower(),
        "Company": extract_company_name(recipient_domain).capitalize(),
        "COMPANY": extract_company_name(recipient_domain).upper(),
        "date": current_date,
        "emailbase64": base64.b64encode(email.encode()).decode(),
        "emailbase64=": base64.b64encode(email.encode()).decode().rstrip("="),
        "link": get_random_line(link_file),
        "linkbase64": base64.b64encode(get_random_line(link_file).encode()).decode(),
    }

    for n in range(1, 10):
        replacements[f"random{n}"] = str(random.randint(10 ** (n - 1), 10 ** n - 1))
        replacements[f"char{n}"] = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=n))
        replacements[f"Uchar{n}"] = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=n))

    replacements.update({
        key: random.choice(values)
        for key, values in randomizer_files.items()
    })
    replacements.update({
        key: customizer_files[key][recipient_index % len(customizer_files[key])]
        for key in customizer_files
    })

    return re.sub(r"\[\[(.*?)\]\]", lambda m: replacements.get(m.group(1), f"[[{m.group(1)}]]"), text)

# === DKIM HANDLING ===
def ensure_pem_file(sender_domain):
    pem_file = os.path.join(dkim_folder, f"{sender_domain}.pem")
    if os.path.exists(pem_file):
        return pem_file

    txt_file = os.path.join(dkim_folder, f"{sender_domain}.txt")
    if os.path.exists(txt_file):
        try:
            os.system(f"openssl rsa -in {txt_file} -out {pem_file}")
            log_dkim(f"Generated PEM file for {sender_domain}.")
        except Exception as e:
            log_dkim(f"Failed to generate PEM file for {sender_domain}: {e}")
        return pem_file
    return None

def dkim_sign_message(msg, sender_email):
    sender_domain = sender_email.split('@')[1]
    pem_file = ensure_pem_file(sender_domain)
    if not pem_file:
        log_dkim(f"No PEM file available for {sender_domain}, skipping DKIM.")
        return None

    try:
        with open(pem_file, "rb") as key_file:
            private_key = key_file.read()
        dkim_headers = [b"from", b"to", b"subject"]
        sig = dkim.sign(
            message=msg.as_bytes(),
            selector=b"default",
            domain=sender_domain.encode(),
            privkey=private_key,
            include_headers=dkim_headers
        )
        return sig
    except Exception as e:
        log_dkim(f"Failed to sign message for {sender_domain}: {e}")
        return None

# === EMAIL SENDING ===
total_sent = 0
total_failed = 0

def send_email(sender_email, sender_name, recipient_email, subject, body, recipient_index, total_victims):
    global total_sent, total_failed
    try:
        recipient_domain = recipient_email.split('@')[1]
        mx_records = dns.resolver.resolve(recipient_domain, 'MX')
        mx_record = sorted(mx_records, key=lambda r: r.preference)[0].exchange.to_text()

        hostname = determine_hostname(hostname_mode, sender_email.split('@')[1], manual_hostname)
        helo = replace_placeholders(helo_template, recipient_email, sender_email, recipient_index)

        msg = MIMEMultipart()
        msg["Message-ID"] = f"<" + replace_placeholders(msg_id_template, recipient_email, sender_email, recipient_index) + ">"
        msg["From"] = replace_placeholders(f"{sender_name} <{sender_email}>", recipient_email, sender_email, recipient_index)
        msg["To"] = recipient_email
        msg["Date"] = formatdate(localtime=True)
        msg["Subject"] = replace_placeholders(subject, recipient_email, sender_email, recipient_index)
        msg["Reply-To"] = replace_placeholders(reply_to, recipient_email, sender_email, recipient_index)
        msg["X-Priority"] = str(priority)
        msg["Return-Path"] = replace_placeholders(return_path, recipient_email, sender_email, recipient_index)
        
        # Add custom header to include hostname
        msg["X-Hostname"] = hostname

        boundary = replace_placeholders(boundary_template, recipient_email, sender_email, recipient_index)
        msg.set_boundary(boundary)

        msg.attach(MIMEText(body, "html" if send_html_letter else "plain"))

        if dkim_enabled:
            dkim_signature = dkim_sign_message(msg, sender_email)
            if dkim_signature:
                # Ensure there are no existing DKIM-Signature headers
                if "DKIM-Signature" in msg:
                    del msg["DKIM-Signature"]
                msg.add_header("DKIM-Signature", dkim_signature.decode().replace("DKIM-Signature: ", ""))

        with contextlib.suppress(Exception):
            with smtplib.SMTP(mx_record, 25, local_hostname=hostname, timeout=config.getint("SETTINGS", "email_timeout", fallback=20)) as server:
                server.helo(helo)
                server.mail(replace_placeholders(return_path, recipient_email, sender_email, recipient_index))
                server.rcpt(recipient_email)
                server.data(msg.as_string())
                log_general(f"Email sent successfully to {recipient_email} [{recipient_index + 1}/{total_victims}].")
                total_sent += 1
                return

        log_general(f"Failed to send email to {recipient_email} [{recipient_index + 1}/{total_victims}].", success=False)
        total_failed += 1
    except Exception as e:
        if any(substr in str(e).lower() for substr in ["user not found", "not found", "user does not exist"]):
            log_to_file(f"Invalid email {recipient_email}: {e}", "invalid_emails.txt")
        log_general(f"Failed to send email to {recipient_email} [{recipient_index + 1}/{total_victims}]: {e}", success=False)
        total_failed += 1

# === THREAD HANDLING ===
def worker(queue, total_victims):
    while True:
        item = queue.get()
        if item is None:
            break
        send_email(*item, total_victims)
        queue.task_done()

# === MAIN FUNCTION ===
def main():
    start_time = datetime.now()

    victims = load_file_lines(victims_file)
    if not victims:
        log_general("No victims found.", success=False)
        return

    email_body = select_letter()
    if not email_body:
        log_general("No email body found.", success=False)
        return

    total_victims = len(victims)
    queue = Queue()

    threads = []
    for _ in range(threads_count):
        thread = threading.Thread(target=worker, args=(queue, total_victims))
        thread.start()
        threads.append(thread)

    for i, victim in enumerate(victims):
        from_email = get_random_line(frommail_file)
        from_name = get_random_line(fromname_file)
        subject = get_random_line(subject_file)

        if not from_email:
            log_general("No sender email found.", success=False)
            return

        personalized_body = replace_placeholders(email_body, victim, from_email, i)
        queue.put((from_email, from_name, victim, subject, personalized_body, i))

        if sleep_enabled and (i + 1) % mails_before_sleep == 0:
            time.sleep(sleep_seconds)

    queue.join()

    for _ in range(threads_count):
        queue.put(None)
    for thread in threads:
        thread.join()

    end_time = datetime.now()
    total_time = end_time - start_time
    days, remainder = divmod(total_time.total_seconds(), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    log_general(f"Summary: Total Emails Sent: {total_sent}, Total Failed: {total_failed}")
    log_general(f"Total Time Taken: {int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds")

if __name__ == "__main__":
    main()
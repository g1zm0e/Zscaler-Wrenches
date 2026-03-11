#!/usr/bin/env python3
"""
fix_chatgpt_ssl_no_move.py — ChatGPT Desktop SSL Fix for SSL Inspection Proxies (macOS)

BACKGROUND
----------
ChatGPT Desktop (com.openai.chat) is a native Swift/macOS application. It implements
SPKI-hash-based certificate pinning via a URLSession authentication challenge delegate.
Every TLS connection checks the server's root certificate public key against a compiled-in
allowlist of SHA-256/SPKI hashes. When an SSL inspection proxy (e.g. Zscaler,
Netskope, Palo Alto Prisma, Cisco Umbrella) intercepts the connection and re-signs the
certificate, the root CA presented is the proxy CA — whose SPKI hash does not
appear in the compiled list. The app displays:

  "Looks like '<Proxy CA Name>' is the wrong SSL certificate..."

FIX MECHANISM
-------------
The ChatGPT.framework binary contains a UserDefaults key reference:
  com.openai.pinned_cert_hash_list

If the app reads this key from NSUserDefaults (domain: com.openai.chat) at startup,
it can be used to supply an override or supplemental hash list. This script:

  1. Probes the TLS connection to api.openai.com to detect SSL interception
     (or searches the macOS Keychain if --ca-name is provided)
  2. Exports the SSL inspection proxy Root CA PEM
  3. Computes its SPKI SHA-256 hash (base64-encoded)
  4. Writes that hash + all known OpenAI production hashes to NSUserDefaults
     under the key com.openai.pinned_cert_hash_list
  5. Verifies the written defaults

USAGE
-----
  python3 fix_chatgpt_ssl_no_move.py [--ca-name NAME] [--cert-path PATH] [--app-path PATH] [--dry-run]

OPTIONS
-------
  --ca-name   NAME   Bypass TLS probe and search the macOS Keychain by CN instead.
                     Examples: "Zscaler", "Netskope", "Cisco Umbrella".
  --cert-path PATH   Path to an existing inspection CA PEM file.
                     If provided, skips both TLS probe and keychain export.
  --app-path  PATH   Path to ChatGPT.app (default: /Applications/ChatGPT.app).
  --dry-run          Show what would be done without making changes.
"""

import argparse
import hashlib
import base64
import plistlib
import re
import subprocess
import sys
from pathlib import Path

# Bootstrap fallback — used only on first run when NSUserDefaults has no existing list.
# Subsequent runs read and preserve whatever is already stored.
KNOWN_OPENAI_HASHES = [
    "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
    "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
    "x+C0kJ2uYxDLS5lLqDkAFQRmwWLeak0Kk1WsiuDRnZ4=",
    "Y9mvm0exBk1JoQ57f9Vm28jKo5lFm/woKcVxrYxu80o=",
    "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=",
    "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=",
    "uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=",
    "NfU84SZGEeAzQP434ex9TMmGxWE9ynD9BKpEVF8tryg=",
    "svcpi1K/LDysTd/nLeTWgqxYlXWVmC8rYjAa9ZfGmcU=",
    "I/Lt/z7ekCWanjD0Cvj5EqXls2lOaThEA0H2Bg4BT/o=",
    "8ca6Zwz8iOTfUpc8rkIPCgid1HQUT+WAbEIAZOFZEik=",
    "Fe7TOVlLME+M+Ee0dzcdjW/sYfTbKwGvWJ58U7Ncrkw=",
    "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=",
    "Wd8xe/qfTwq3ylFNd3IpaqLHZbh2ZNCLluVzmeNkcpw=",
    "K87oWBWM9UZfyddvDfoxL+8lpNyoUB2ptGtn0fv6G2Q=",
    "cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A=",
    "fg6tdrtoGdwvVFEahDVPboswe53YIFjqbABPAdndpd8=",
]

PROBE_HOST      = "api.openai.com"
PROBE_PORT      = 443
BUNDLE_ID       = "com.openai.chat"
DEFAULTS_KEY    = "com.openai.pinned_cert_hash_list"
SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"

APP_DEFAULT_PATH = Path("/Applications/ChatGPT.app")

PEM_RE = re.compile(
    r"(-----BEGIN CERTIFICATE-----\s.+?\s-----END CERTIFICATE-----)",
    re.DOTALL,
)


def _c(code, text): return f"\033[{code}m{text}\033[0m"
def green(t):  return _c("32", t)
def yellow(t): return _c("33", t)
def red(t):    return _c("31", t)
def cyan(t):   return _c("36", t)
def bold(t):   return _c("1",  t)

def step(msg):
    print(f"\n{cyan('─'*62)}")
    print(f"  {bold(msg)}")
    print(f"{cyan('─'*62)}")

def ok(msg):   print(f"  {green('[OK]')}   {msg}")
def info(msg): print(f"  {cyan('[INFO]')} {msg}")
def warn(msg): print(f"  {yellow('[WARN]')} {msg}")
def fail(msg): print(f"  {red('[FAIL]')} {msg}")


def run(cmd, capture=True, dry_run=False):
    if dry_run:
        info(f"[DRY RUN] {' '.join(str(c) for c in cmd) if isinstance(cmd, list) else cmd}")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    return subprocess.run(cmd, capture_output=capture, text=True)


def split_pem_certs(pem_text):
    return PEM_RE.findall(pem_text)


def find_chatgpt_app(hint):
    if hint:
        p = Path(hint)
        if p.exists(): return p
        fail(f"Provided app path does not exist: {p}")
        return None

    if APP_DEFAULT_PATH.exists():
        return APP_DEFAULT_PATH

    fail(f"ChatGPT.app not found at {APP_DEFAULT_PATH}.")
    return None


def compute_spki_hash_from_pem(pem_text):
    pubkey = subprocess.run(
        ["openssl", "x509", "-noout", "-pubkey"],
        input=pem_text, capture_output=True, text=True,
    )
    if pubkey.returncode != 0:
        return None

    pkey_der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pubkey.stdout.encode(), capture_output=True,
    )
    if pkey_der.returncode != 0:
        return None

    return base64.b64encode(hashlib.sha256(pkey_der.stdout).digest()).decode()


def get_cert_subject(pem_text):
    result = subprocess.run(
        ["openssl", "x509", "-noout", "-subject"],
        input=pem_text, capture_output=True, text=True,
    )
    if result.returncode != 0:
        return "Unknown CA"
    # Extract CN from subject line like "subject=CN = Zscaler Root CA"
    subj = result.stdout.strip()
    cn_match = re.search(r"CN\s*=\s*(.+?)(?:\s*/|$)", subj)
    return cn_match.group(1).strip() if cn_match else subj.replace("subject=", "").strip()


def probe_tls(dry_run):
    step(f"Step 2 — Probe TLS connection to {PROBE_HOST}:{PROBE_PORT}")
    info(f"Connecting to {PROBE_HOST}:{PROBE_PORT} to detect SSL interception...")

    if dry_run:
        info("[DRY RUN] Would probe TLS connection")
        return None, None

    try:
        result = subprocess.run(
            ["openssl", "s_client", "-connect", f"{PROBE_HOST}:{PROBE_PORT}", "-showcerts"],
            input="", capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        fail(f"Connection to {PROBE_HOST}:{PROBE_PORT} timed out.")
        fail("Use --ca-name to search the macOS Keychain instead.")
        return None, None

    if result.returncode != 0 and not result.stdout.strip():
        fail(f"Could not connect to {PROBE_HOST}:{PROBE_PORT}.")
        fail(f"  stderr: {result.stderr.strip()[:200]}")
        fail("Use --ca-name to search the macOS Keychain instead.")
        return None, None

    certs = split_pem_certs(result.stdout)
    if not certs:
        fail("No certificates found in TLS handshake output.")
        fail("Use --ca-name to search the macOS Keychain instead.")
        return None, None

    # The last cert in the chain is the root (or highest intermediate)
    root_pem = certs[-1]
    root_hash = compute_spki_hash_from_pem(root_pem)

    if not root_hash:
        fail("Failed to compute SPKI hash from the root certificate.")
        fail("Use --ca-name to search the macOS Keychain instead.")
        return None, None

    ca_name = get_cert_subject(root_pem)

    if root_hash in KNOWN_OPENAI_HASHES:
        ok(f"Root CA: {ca_name}")
        ok(f"SPKI hash: {root_hash}")
        info("This hash matches a known OpenAI production CA — no SSL interception detected.")
        info("If you believe interception IS active, use --ca-name to search the Keychain directly.")
        return None, None

    ok(f"SSL interception detected!")
    ok(f"Intercepting CA: {ca_name}")
    ok(f"SPKI hash: {root_hash}")
    info(f"Found {len(certs)} certificate(s) in chain")

    return root_pem, ca_name


def export_inspection_cert_from_keychain(dest_pem, ca_name, dry_run):
    step(f"Step 2 — Export '{ca_name}' Root CA from Keychain")
    info(f"Searching keychain: {SYSTEM_KEYCHAIN}")
    info(f"Certificate CN filter: '{ca_name}'")

    result = run(["security", "find-certificate", "-c", ca_name, "-a", "-p", SYSTEM_KEYCHAIN])

    if result.returncode != 0 or not result.stdout.strip():
        warn("Not found in System keychain, searching all keychains...")
        result = run(["security", "find-certificate", "-c", ca_name, "-a", "-p"])

    if not result.stdout.strip():
        fail(f"No certificate matching '{ca_name}' found in any keychain.")
        fail("Ensure your SSL inspection client is installed and connected, then re-run.")
        return False

    certs = split_pem_certs(result.stdout)
    count = len(certs)
    ok(f"Found {count} certificate(s) matching '{ca_name}'")

    # If multiple certs matched, find the self-signed root (subject == issuer)
    if count > 1:
        info("Multiple certs found — looking for the self-signed root CA...")
        for pem in certs:
            subj = subprocess.run(
                ["openssl", "x509", "-noout", "-subject", "-issuer"],
                input=pem, capture_output=True, text=True,
            )
            if subj.returncode == 0:
                lines = subj.stdout.strip().splitlines()
                if len(lines) == 2:
                    s = lines[0].replace("subject=", "").strip()
                    i = lines[1].replace("issuer=", "").strip()
                    if s == i:
                        info(f"  Root CA identified: {s}")
                        root_pem = pem
                        break
        else:
            warn("Could not identify self-signed root — using last certificate in chain")
            root_pem = certs[-1]
    else:
        root_pem = certs[0]

    if not dry_run:
        dest_pem.parent.mkdir(parents=True, exist_ok=True)
        dest_pem.write_text(root_pem)
        ok(f"Saved to {dest_pem}")

        verify = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates"],
            input=root_pem, capture_output=True, text=True,
        )
        if verify.returncode == 0:
            for line in verify.stdout.strip().splitlines():
                info(f"  {line}")
    else:
        info(f"[DRY RUN] Would save cert to {dest_pem}")

    return True


def compute_spki_hash(cert_pem, ca_name):
    step(f"Step 3 — Compute SPKI SHA-256 hash of '{ca_name}' Root CA")
    info("Extracting public key from certificate...")

    pem_text = cert_pem.read_text()
    certs = split_pem_certs(pem_text)
    if not certs:
        fail(f"No PEM certificate found in {cert_pem}")
        return None

    spki_hash = compute_spki_hash_from_pem(certs[0])
    if not spki_hash:
        fail("Failed to compute SPKI hash from certificate.")
        return None

    ok(f"SPKI SHA-256 hash: {spki_hash}")
    return spki_hash


def read_existing_hashes(target_user=None):
    cmd = ["defaults", "export", BUNDLE_ID, "-"]
    if target_user:
        cmd = ["sudo", "-u", target_user] + cmd
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0 or not result.stdout:
        return None
    try:
        plist = plistlib.loads(result.stdout)
        hashes = plist.get(DEFAULTS_KEY)
        return hashes if isinstance(hashes, list) and hashes else None
    except Exception:
        return None


def write_defaults(inspection_cert_hash, ca_name, dry_run, target_user=None):
    step("Step 4 — Write hash list to NSUserDefaults")

    existing_hashes = read_existing_hashes(target_user)

    if existing_hashes is not None:
        if inspection_cert_hash in existing_hashes:
            ok(f"'{ca_name}' CA hash already present in NSUserDefaults — no update needed")
            return True
        info(f"Found {len(existing_hashes)} existing hash(es) in NSUserDefaults — will preserve them")
        base_hashes = existing_hashes
    else:
        info("No existing hash list found — using built-in OpenAI hashes as base")
        base_hashes = KNOWN_OPENAI_HASHES

    all_hashes = [inspection_cert_hash] + base_hashes
    info(f"Writing {len(all_hashes)} hashes to {BUNDLE_ID} → {DEFAULTS_KEY}")
    info(f"  Inspection CA hash (prepended): {inspection_cert_hash}")
    info(f"  Base hashes preserved: {len(base_hashes)}")

    cmd = ["defaults", "write", BUNDLE_ID, DEFAULTS_KEY, "-array"] + all_hashes
    if target_user:
        cmd = ["sudo", "-u", target_user] + cmd

    result = run(cmd, dry_run=dry_run)
    if dry_run:
        return True

    if result.returncode != 0:
        fail(f"defaults write failed: {result.stderr.strip()}")
        return False

    verify_cmd = ["defaults", "read", BUNDLE_ID, DEFAULTS_KEY]
    if target_user:
        verify_cmd = ["sudo", "-u", target_user] + verify_cmd
    verify = run(verify_cmd)

    if inspection_cert_hash in (verify.stdout or ""):
        ok(f"'{ca_name}' CA hash confirmed in NSUserDefaults")
        return True

    warn("Could not confirm hash in defaults — app may still work if it reads the key at startup")
    return True


def verify_defaults(inspection_cert_hash, ca_name, target_user=None):
    step("Step 5 — Verification")
    cmd = ["defaults", "read", BUNDLE_ID, DEFAULTS_KEY]
    if target_user:
        cmd = ["sudo", "-u", target_user] + cmd
    result = run(cmd)
    if result.returncode == 0 and inspection_cert_hash in result.stdout:
        ok(f"NSUserDefaults: {DEFAULTS_KEY} contains '{ca_name}' CA hash")
        return True
    fail(f"NSUserDefaults: {DEFAULTS_KEY} does NOT contain '{ca_name}' CA hash")
    return False


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--ca-name",     metavar="NAME", default=None,
                        help="Bypass TLS probe; search the macOS Keychain by this CN instead")
    parser.add_argument("--cert-path",   metavar="PATH",
                        help="Path to existing inspection CA PEM (skips probe and keychain export)")
    parser.add_argument("--app-path",    metavar="PATH",
                        help="Path to ChatGPT.app (skips auto-detection)")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Print what would be done without making changes")
    parser.add_argument("--target-user", metavar="USER", help=argparse.SUPPRESS)
    args = parser.parse_args()

    ca_name = args.ca_name or "SSL Inspection Proxy"

    print()
    print(bold(cyan("=" * 62)))
    print(bold(cyan(f"  ChatGPT Desktop SSL Fix (macOS)")))
    print(bold(cyan("=" * 62)))

    if args.dry_run:
        print(yellow("\n  ** DRY RUN MODE — no changes will be made **\n"))

    # Step 1 — Locate ChatGPT.app
    step("Step 1 — Locate ChatGPT.app")
    app_path = find_chatgpt_app(args.app_path)
    if not app_path:
        fail("ChatGPT.app not found. Install it first, or pass --app-path.")
        sys.exit(1)
    ok(f"Found: {app_path}")

    ver_result = run(["defaults", "read", str(app_path / "Contents/Info.plist"), "CFBundleShortVersionString"])
    if ver_result.returncode == 0:
        info(f"Version: {ver_result.stdout.strip()}")

    cert_dir = Path.home() / "ca_certs"
    spki_hash = None

    # Step 2 — Get the inspection CA certificate
    if args.cert_path:
        cert_pem = Path(args.cert_path)
        step("Step 2 — Using provided certificate")
        if not cert_pem.exists():
            fail(f"Cert not found: {cert_pem}")
            sys.exit(1)
        ok(f"Using {cert_pem}")
        ca_name = get_cert_subject(cert_pem.read_text())

    elif args.ca_name:
        ca_name = args.ca_name
        safe_name = ca_name.replace(" ", "_")
        cert_pem = cert_dir / f"{safe_name}_CA.pem"
        if not export_inspection_cert_from_keychain(cert_pem, ca_name, args.dry_run):
            sys.exit(1)

    else:
        # TLS probe — primary method
        root_pem, detected_ca_name = probe_tls(args.dry_run)

        if root_pem is None and not args.dry_run:
            sys.exit(1)

        if args.dry_run:
            spki_hash = "DRY_RUN_HASH_PLACEHOLDER="
            ca_name = "DRY_RUN_CA"
        else:
            ca_name = detected_ca_name
            safe_name = ca_name.replace(" ", "_")
            cert_pem = cert_dir / f"{safe_name}_CA.pem"
            cert_pem.parent.mkdir(parents=True, exist_ok=True)
            cert_pem.write_text(root_pem)
            ok(f"Saved CA cert to {cert_pem}")

    # Step 3 — Compute SPKI hash (skip if TLS probe already computed it)
    if spki_hash is None and not args.dry_run:
        spki_hash = compute_spki_hash(cert_pem, ca_name)
        if not spki_hash:
            sys.exit(1)

    # Step 4 — Write to NSUserDefaults
    if not write_defaults(spki_hash, ca_name, args.dry_run, args.target_user):
        sys.exit(1)

    # Step 5 — Verify
    all_ok = verify_defaults(spki_hash, ca_name, args.target_user) if not args.dry_run else True

    print()
    print(bold(cyan("=" * 62)))
    if all_ok:
        print(bold(green("  Fix applied successfully!")))
    else:
        print(bold(yellow("  Fix applied with warnings — review output above.")))
    print(bold(cyan("=" * 62)))
    print()
    print(cyan("  NEXT STEPS:"))
    print("  1. Quit ChatGPT Desktop completely  (Cmd+Q)")
    print("  2. Reopen ChatGPT.app")
    print("  3. Sign in — the SSL error should no longer appear")
    print()
    print(cyan("  NOTE: If the error persists, the app may not read the"))
    print(cyan("  UserDefaults key at runtime. Confirm the key name in"))
    print(cyan("  ChatGPT.framework with: strings ChatGPT.framework/ChatGPT | grep pinned"))
    print()


if __name__ == "__main__":
    main()

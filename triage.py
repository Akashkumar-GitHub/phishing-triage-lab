"""Investigate saved emails and correlate evidence with offline DNS observations."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from hashlib import sha256
from html.parser import HTMLParser
from ipaddress import ip_address
from io import StringIO
import json
from pathlib import Path, PurePosixPath
import re
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit


MAX_MESSAGE_BYTES = 10 * 1024 * 1024
DNS_WINDOW = timedelta(minutes=30)
AUTH_METHODS = ("spf", "dkim", "dmarc")
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
URL = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)
EXECUTABLES = {".bat", ".cmd", ".exe", ".hta", ".js", ".lnk", ".msi", ".ps1", ".scr", ".vbs"}
CONTAINERS = {".7z", ".gz", ".img", ".iso", ".rar", ".tar", ".zip"}
PRIORITIES = ("High", "Review", "Low")


def normalize_host(value: str) -> str:
    value = value.strip().rstrip(".")
    try:
        return str(ip_address(value))
    except ValueError:
        pass
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    if len(domain) > 253 or not all(LABEL.fullmatch(label) for label in domain.split(".")):
        return ""
    return domain


def literal_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def defang(host: str) -> str:
    return host.replace(".", "[.]").replace(":", "[:]")


def url_host(url: str) -> str:
    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme not in ("http", "https") or parsed.hostname is None:
            return ""
        return normalize_host(parsed.hostname)
    except ValueError:
        return ""


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.href = None
        self.label = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.finish_link()
            self.href = next((value for name, value in attrs if name == "href"), None)

    def handle_data(self, data):
        if self.href is not None:
            self.label.append(data)

    def handle_endtag(self, tag):
        if tag == "a":
            self.finish_link()

    def finish_link(self):
        if self.href is not None:
            self.links.append((self.href, "".join(self.label).strip()))
        self.href = None
        self.label.clear()

    def close(self):
        super().close()
        self.finish_link()


def auth_segments(value: str) -> list[str]:
    """Split result clauses outside comments and quoted header values."""
    segments, buffer = [], []
    quoted, escaped, depth = False, False, 0
    for char in value:
        if escaped:
            if not depth:
                buffer.append(char)
            escaped = False
        elif char == "\\" and (quoted or depth):
            escaped = True
        elif depth:
            depth += (char == "(") - (char == ")")
        elif char == '"':
            quoted = not quoted
            buffer.append(char)
        elif char == "(" and not quoted:
            depth = 1
            buffer.append(" ")
        elif char == ";" and not quoted:
            segments.append("".join(buffer).strip())
            buffer.clear()
        else:
            buffer.append(char)
    if depth or quoted or escaped:
        return []
    return [*segments, "".join(buffer).strip()]


def authentication(message, trusted_servers: set[str]) -> dict:
    matches = []
    for header in message.get_all("Authentication-Results", []):
        segments = auth_segments(str(header))
        if not segments:
            continue
        service = re.fullmatch(r'("[^"]+"|[^\s"]+)(?:\s+\d+)?', segments[0])
        if service and service[1].strip('"').lower() in trusted_servers:
            matches.append((service[1].strip('"').lower(), segments[1:]))

    results = {method: [] for method in AUTH_METHODS}
    if len(matches) != 1:
        status = "Unavailable" if not matches else "Ambiguous"
        return {"status": status, "service": None, "results": results}

    service, clauses = matches[0]
    for clause in clauses:
        match = re.match(r"^(spf|dkim|dmarc)(?:/\d+)?\s*=\s*([a-z][a-z0-9_-]*)\b",
                         clause, re.IGNORECASE)
        if match:
            method, outcome = (value.lower() for value in match.groups())
            if outcome not in results[method]:
                results[method].append(outcome)
    status = "Reported" if any(results.values()) else "Unavailable"
    if {"pass", "fail"}.issubset(results["dmarc"]):
        status = "Ambiguous"
    return {"status": status, "service": service, "results": results}


def message_address(message, name: str) -> dict | None:
    headers = message.get_all(name, [])
    if len(headers) != 1 or len(headers[0].addresses) != 1:
        return None
    addr = headers[0].addresses[0]
    domain = normalize_host(addr.domain)
    return {"address": addr.addr_spec, "domain": domain} if addr.username and domain else None


def message_date(message) -> datetime | None:
    headers = message.get_all("Date", [])
    if len(headers) != 1:
        return None
    try:
        value = parsedate_to_datetime(str(headers[0]))
        return value.astimezone(timezone.utc) if value.utcoffset() is not None else None
    except (ValueError, OverflowError):
        return None


def text_content(part) -> str:
    try:
        return part.get_content()
    except LookupError:
        return (part.get_payload(decode=True) or b"").decode("utf-8", errors="replace")


def scan_parts(message) -> tuple[dict, set, list]:
    destinations = defaultdict(set)
    mismatches = set()
    attachments = []

    def visit(part):
        filename = part.get_filename()
        mime = part.get_content_type()
        if filename or part.get_content_disposition() == "attachment" or mime == "message/rfc822":
            name = filename or "(unnamed attachment)"
            suffix = PurePosixPath(name).suffix.lower()
            kind = "Executable or script" if suffix in EXECUTABLES else "Archive or disk image" if suffix in CONTAINERS else "Other"
            attachments.append({"filename": name, "mime": mime, "kind": kind})
        elif part.is_multipart():
            for child in part.iter_parts():
                visit(child)
        elif mime == "text/plain":
            for match in URL.finditer(text_content(part)):
                url = match[0].rstrip(".,;!?)")
                if url.endswith("]") and "[" not in url:
                    url = url[:-1]
                host = url_host(url)
                if host:
                    destinations[host].add("Plain text")
        elif mime == "text/html":
            parser = LinkParser()
            parser.feed(text_content(part))
            parser.close()
            for href, label in parser.links:
                host = url_host(href)
                if not host:
                    continue
                destinations[host].add("HTML link")
                shown = url_host(label) or normalize_host(label)
                if shown != host and ("." in shown or literal_ip(shown)):
                    mismatches.add((shown, host))

    visit(message)
    return destinations, mismatches, attachments


def score_message(sender, reply_to, auth, destinations, mismatches, attachments) -> list[dict]:
    findings = []

    def add(label, detail, points):
        findings.append({"label": label, "detail": detail, "points": points})

    if not sender:
        add("Sender unclear", "The message does not have one usable From address.", 2)
    if sender and reply_to and sender["domain"] != reply_to["domain"]:
        add("Different reply domain", "From and Reply-To use different domains.", 2)
    if auth["status"] != "Reported":
        add("Authentication needs review", "The configured mail service did not provide an unambiguous result.", 2)
    else:
        results = auth["results"]
        if "fail" in results["dmarc"]:
            add("DMARC reported failure", "The mail service reported a DMARC alignment failure.", 4)
        elif "pass" not in results["dmarc"]:
            add("DMARC result needs review", "The mail service did not report a DMARC pass or fail.", 2)
        if "pass" not in results["dmarc"]:
            spf = results["spf"]
            if spf and all(result in ("fail", "softfail") for result in spf):
                add("SPF reported failure", "The reported SPF outcomes were fail or softfail.", 2)
            if results["dkim"] == ["fail"]:
                add("DKIM reported failure", "The mail service reported only DKIM failures.", 1)
    if mismatches:
        detail = "; ".join(f"{defang(shown)} leads to {defang(actual)}" for shown, actual in sorted(mismatches))
        add("Displayed link differs from destination", detail, 3)
    ips = sorted(defang(host) for host in destinations if literal_ip(host))
    if ips:
        add("Link uses a direct IP", ", ".join(ips), 2)
    if any(item["kind"] == "Executable or script" for item in attachments):
        add("Executable or script filename", "The filename extension warrants review.", 4)
    if any(item["kind"] == "Archive or disk image" for item in attachments):
        add("Archive or disk image filename", "Review the need for this type of attachment.", 2)
    return findings


def time_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def load_dns(path: Path) -> dict:
    index = defaultdict(set)
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not {"timestamp", "client", "domain"}.issubset(reader.fieldnames or []):
            raise ValueError("DNS CSV needs timestamp, client, and domain columns")
        for row in reader:
            try:
                raw_time, client, domain = ((row.get(key) or "").strip() for key in ("timestamp", "client", "domain"))
                observed = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
                domain = normalize_host(domain)
                if observed.utcoffset() is None or not domain or not client:
                    raise ValueError("expected a timestamp with offset, a client, and a domain")
                observed = observed.astimezone(timezone.utc)
            except (ValueError, OverflowError) as error:
                raise ValueError(f"{path}:{reader.line_num}: {error}") from error
            index[domain].add((observed, client))
    return {domain: sorted(observations) for domain, observations in index.items()}


def scan_message(raw: bytes, filename: str, trusted_servers: set[str], dns: dict) -> dict:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    sender = message_address(message, "From")
    reply_to = message_address(message, "Reply-To")
    timestamp = message_date(message)
    auth = authentication(message, trusted_servers)
    hosts, mismatches, attachments = scan_parts(message)
    findings = score_message(sender, reply_to, auth, hosts, mismatches, attachments)
    score = sum(finding["points"] for finding in findings)
    priority = "High" if score >= 5 else "Review" if score >= 2 else "Low"
    matches = []
    if timestamp:
        for host in hosts:
            for observed, client in dns.get(host, ()):
                if timedelta(0) <= observed - timestamp <= DNS_WINDOW:
                    matches.append({"timestamp": time_text(observed), "client": client, "indicator": defang(host)})
    matches.sort(key=lambda record: (record["timestamp"], record["indicator"], record["client"]))
    return {
        "id": f"MAIL-{sha256(raw).hexdigest()[:12].upper()}",
        "file": filename,
        "subject": str(message["Subject"] or "(no subject)"),
        "sender": sender,
        "reply_to": reply_to,
        "date": time_text(timestamp) if timestamp else None,
        "authentication": auth,
        "attachments": attachments,
        "indicators": [{"host": defang(host), "sources": sorted(hosts[host])} for host in sorted(hosts)],
        "dns_matches": matches,
        "findings": findings,
        "score": score,
        "priority": priority,
    }


def email_files(path: Path) -> list[Path]:
    paths = sorted(path.iterdir()) if path.is_dir() else [path]
    files = [message for message in paths if message.is_file() and message.suffix.lower() == ".eml"]
    if not files:
        raise ValueError(f"{path}: no .eml messages found")
    return files


def analyze(paths: list[Path], trusted_servers: set[str], dns: dict | None, *, synthetic: bool) -> dict:
    cases = {}
    for message in paths:
        with message.open("rb") as source:
            raw = source.read(MAX_MESSAGE_BYTES + 1)
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError(f"{message}: exceeds the 10 MiB message size limit")
        try:
            case = scan_message(raw, message.name, trusted_servers, dns or {})
        except (TypeError, ValueError, RecursionError) as error:
            raise ValueError(f"{message}: {error}") from error
        cases.setdefault(case["id"], case)
    if not cases:
        raise ValueError("no .eml messages found")

    ordered = sorted(cases.values(), key=lambda item: (
        PRIORITIES.index(item["priority"]), -item["score"], item["file"],
    ))
    counts = Counter(case["priority"] for case in ordered)
    indicators = {indicator["host"] for case in ordered for indicator in case["indicators"]}
    return {
        "schema_version": 1,
        "synthetic": synthetic,
        "dns_supplied": dns is not None,
        "summary": {"messages": len(ordered), "high": counts["High"], "review": counts["Review"],
                    "low": counts["Low"], "indicators": len(indicators),
                    "dns_correlated": sum(bool(case["dns_matches"]) for case in ordered)},
        "cases": ordered,
    }


def write_report(output: Path, report: dict) -> None:
    template = Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")
    embedded = json.dumps(report).replace("<", r"\u003c")
    domains = defaultdict(set)
    for case in report["cases"]:
        for indicator in case["indicators"]:
            domains[indicator["host"]].add(case["id"])
    stream = StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(("indicator", "message_count", "case_ids"))
    for indicator, ids in sorted(domains.items()):
        writer.writerow((indicator, len(ids), " ".join(sorted(ids))))
    files = {
        "analysis.json": json.dumps(report, indent=2) + "\n",
        "indicators.csv": stream.getvalue(),
        "dashboard.html": template.replace("__TRIAGE_JSON__", embedded, 1),
    }
    output.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        temporary = None
        try:
            with NamedTemporaryFile("w", encoding="utf-8", newline="", dir=output, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(content)
            temporary.replace(output / name)
        finally:
            if temporary:
                temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    demo = modes.add_parser("demo", help="generate and investigate the synthetic inbox")
    custom = modes.add_parser("analyze", help="investigate an .eml file or directory")
    custom.add_argument("input", type=Path)
    custom.add_argument("--trusted-authserv-id", action="append", default=[], metavar="SERVICE")
    custom.add_argument("--dns", type=Path, help="optional CSV of offline DNS observations")
    for mode in (demo, custom):
        mode.add_argument("--out", type=Path, default=Path("output"))
    args = parser.parse_args()
    synthetic = args.mode == "demo"
    try:
        if synthetic:
            from demo_data import build_demo

            paths, dns_file, trusted = build_demo(args.out / "fixtures")
        else:
            paths, dns_file = email_files(args.input), args.dns
            trusted = {value.strip().lower() for value in args.trusted_authserv_id if value.strip()}
        if dns_file and dns_file.resolve() in {
            (args.out / name).resolve() for name in ("analysis.json", "indicators.csv", "dashboard.html")
        }:
            raise ValueError("the DNS input path collides with a report file")
        report = analyze(paths, trusted, load_dns(dns_file) if dns_file else None, synthetic=synthetic)
        write_report(args.out, report)
    except (OSError, ValueError) as error:
        parser.exit(1, f"error: {error}\n")
    counts = report["summary"]
    print(f"Reviewed {counts['messages']} emails: {counts['high']} high, "
          f"{counts['review']} review, {counts['low']} low.")
    print(f"Extracted {counts['indicators']} unique destinations and found DNS evidence for "
          f"{counts['dns_correlated']} cases.")
    print(f"Open {(args.out / 'dashboard.html').resolve()}")


if __name__ == "__main__":
    main()

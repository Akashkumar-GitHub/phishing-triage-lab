"""Generate inert, deterministic email fixtures for an analyst exercise."""

from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.utils import format_datetime
import csv
from pathlib import Path


START = datetime(2026, 11, 20, 9, tzinfo=timezone.utc)
SERVICE = "mx.lab.test"
FIXTURE_TYPES = (
    # The expected follow-up priorities describe the planted signals in this exercise.
    ("link-display", "High", "Link display sample"),
    ("auth-failure", "High", "Authentication failure sample"),
    ("script-reply", "High", "Attachment and reply sample"),
    ("ip-link-display", "High", "IP destination sample"),
    ("external-reply", "Review", "External reply sample"),
    ("archive", "Review", "Archive attachment sample"),
    ("missing-auth", "Review", "Unverified authentication sample"),
    ("ip-only", "Review", "Direct IP reference sample"),
    ("routine-text", "Low", "Routine text sample"),
    ("routine-html", "Low", "Routine HTML sample"),
    ("aligned-dkim", "Low", "Aligned DKIM sample"),
    ("routine-attachment", "Low", "Routine attachment sample"),
)


def fixture(kind: str, label: str, number: int, timestamp: datetime) -> EmailMessage:
    msg = EmailMessage(policy=policy.SMTP)
    msg["From"] = "Fixture sender <records@office.test>"
    msg["To"] = "triage@lab.test"
    msg["Subject"] = f"{label} {number:02}"
    msg["Date"] = format_datetime(timestamp)
    msg["Message-ID"] = f"<fixture-{number:02}@office.test>"
    msg.set_content("Local analyst training fixture. Sample content for indicator extraction.")

    spf = "fail" if kind in {"auth-failure", "aligned-dkim"} else "pass"
    dmarc = "fail" if kind in {"link-display", "auth-failure"} else "pass"
    service = "unverified.relay.test" if kind == "missing-auth" else SERVICE
    msg["Authentication-Results"] = f"{service}; spf={spf}; dkim=pass; dmarc={dmarc}"

    if kind in {"external-reply", "script-reply"}:
        msg["Reply-To"] = "records@partner.test"
    if kind == "link-display":
        msg.add_alternative(f'<p>Fixture link <a href="https://review-{number:02}.test/item">portal.office.test</a></p>',
                            subtype="html")
    elif kind == "ip-link-display":
        msg.add_alternative('<p>Fixture link <a href="http://192.0.2.18/item">portal.office.test</a></p>', subtype="html")
    elif kind == "ip-only":
        msg.set_content("Fixture reference http://192.0.2.22/item")
    elif kind == "auth-failure":
        msg.set_content(f"Fixture reference https://reference-{number:02}.test/note")
    elif kind in {"routine-text", "aligned-dkim"}:
        msg.set_content("Fixture reference https://portal.office.test/schedule")
    elif kind == "routine-html":
        msg.add_alternative('<p>Fixture reference <a href="https://portal.office.test/schedule">Schedule</a></p>',
                            subtype="html")
    if kind in {"archive", "script-reply", "routine-attachment"}:
        suffix = {"archive": "zip", "script-reply": "js", "routine-attachment": "txt"}[kind]
        msg.add_attachment(b"Static training marker. No active attachment content.\r\n",
                           maintype="application", subtype="octet-stream", filename=f"marker.{suffix}")

    for index, part in enumerate(msg.walk()):
        if part.is_multipart():
            part.set_boundary(f"fixture-{number:02}-mime-{index}")
    return msg


def build_demo(folder: Path) -> tuple[list[Path], Path, set[str]]:
    inbox = folder / "mail"
    inbox.mkdir(parents=True, exist_ok=True)
    observations = []
    paths = []
    for number, (kind, _, label) in enumerate(FIXTURE_TYPES * 2, start=1):
        timestamp = START + timedelta(minutes=40 * (number - 1))
        path = inbox / f"mail-{number:02}.eml"
        path.write_bytes(fixture(kind, label, number, timestamp).as_bytes())
        paths.append(path)
        if kind == "link-display":
            observations.append((timestamp + timedelta(minutes=3), "training-workstation", f"review-{number:02}.test"))
        if kind == "auth-failure":
            observations.append((timestamp + timedelta(minutes=9), "training-workstation", f"reference-{number:02}.test"))
        if kind == "routine-html":
            observations.append((timestamp + timedelta(minutes=2), "training-workstation", "portal.office.test"))
    observations.extend((
        (START - timedelta(seconds=1), "training-workstation", "review-01.test"),
        (START + timedelta(minutes=31), "training-workstation", "review-01.test"),
        (START + timedelta(minutes=5), "training-workstation", "unrelated.lab.test"),
    ))
    dns_path = folder / "dns_observations.csv"
    with dns_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("timestamp", "client", "domain"))
        for timestamp, client, domain in sorted(observations):
            writer.writerow((timestamp.isoformat(), client, domain))
    return paths, dns_path, {SERVICE}

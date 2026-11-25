from datetime import timedelta
from email.message import EmailMessage
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from demo_data import FIXTURE_TYPES, SERVICE, START, build_demo, fixture
from triage import analyze, load_dns, scan_message, write_report


def sample(kind="routine-text"):
    return fixture(kind, "Test sample", 1, START)


def inspect(message, servers=None, dns=None):
    return scan_message(message.as_bytes(), "sample.eml", {SERVICE} if servers is None else servers, dns or {})


class AuthenticationTests(unittest.TestCase):
    def test_requires_configured_service(self):
        case = inspect(sample(), servers=set())
        self.assertEqual(case["priority"], "Review")
        self.assertEqual(case["authentication"]["status"], "Unavailable")
        self.assertEqual(case["authentication"]["results"]["dmarc"], [])

    def test_multiple_selected_headers_are_ambiguous(self):
        message = sample()
        message["Authentication-Results"] = f"{SERVICE}; dmarc=fail"
        case = inspect(message)
        self.assertEqual(case["authentication"]["status"], "Ambiguous")
        self.assertEqual([finding["label"] for finding in case["findings"]], ["Authentication needs review"])

    def test_quoted_values_and_comments_do_not_split_method_clauses(self):
        message = sample()
        message.replace_header(
            "Authentication-Results",
            f'{SERVICE} (training comment; note); spf=pass reason="fixture; note"; dkim=pass; dmarc=pass',
        )
        case = inspect(message)
        self.assertEqual(case["authentication"]["results"], {"spf": ["pass"], "dkim": ["pass"], "dmarc": ["pass"]})
        self.assertEqual(case["priority"], "Low")

    def test_dmarc_pass_with_spf_failure_can_be_low(self):
        case = inspect(sample("aligned-dkim"))
        self.assertEqual(case["authentication"]["results"]["spf"], ["fail"])
        self.assertEqual(case["priority"], "Low")


class EvidenceTests(unittest.TestCase):
    def test_domains_deduplicate_and_export_without_paths(self):
        message = sample()
        message.set_content("Read https://PORTAL.OFFICE.TEST./item?local=sample and http://[2001:db8::1]")
        message.add_alternative('<a href="https://portal.office.test/different">portal.office.test</a>', subtype="html")
        case = inspect(message)
        self.assertEqual(case["indicators"], [
            {"host": "2001[:]db8[:][:]1", "sources": ["Plain text"]},
            {"host": "portal[.]office[.]test", "sources": ["HTML link", "Plain text"]},
        ])
        self.assertNotIn("local=sample", json.dumps(case))

    def test_attached_email_is_metadata_only(self):
        wrapper = sample()
        forwarded = EmailMessage()
        forwarded.set_content("Reference https://attached-message.test")
        wrapper.add_attachment(forwarded, filename="forwarded.eml")
        case = inspect(wrapper)
        self.assertEqual([item["filename"] for item in case["attachments"]], ["forwarded.eml"])
        self.assertEqual([item["host"] for item in case["indicators"]], ["portal[.]office[.]test"])

    def test_dns_requires_exact_domain_and_time_window(self):
        observations = {
            "portal.office.test": [
                (START - timedelta(seconds=1), "before"),
                (START + timedelta(minutes=3), "desktop"),
                (START + timedelta(minutes=30), "boundary"),
                (START + timedelta(minutes=31), "after"),
            ],
            "other.office.test": [(START + timedelta(minutes=5), "elsewhere")],
        }
        matches = inspect(sample(), dns=observations)["dns_matches"]
        self.assertEqual([item["client"] for item in matches], ["desktop", "boundary"])

    def test_dns_parser_reports_invalid_line(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "dns.csv"
            path.write_text("timestamp,client,domain\n2026-11-20T09:05:00,client,host.test\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"dns\.csv:2"):
                load_dns(path)


class DemoTests(unittest.TestCase):
    def test_fixture_priorities_and_report_outputs(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            messages, dns_path, servers = build_demo(root / "fixtures")
            duplicate = root / "duplicate.eml"
            duplicate.write_bytes(messages[-1].read_bytes())
            report = analyze([*messages, duplicate], servers, load_dns(dns_path), synthetic=True)
            self.assertEqual(report["summary"], {
                "messages": 24, "high": 8, "review": 8, "low": 8, "indicators": 7, "dns_correlated": 6,
            })
            actual = {case["file"]: case["priority"] for case in report["cases"]}
            for number, (_, expected, _) in enumerate(FIXTURE_TYPES * 2, 1):
                self.assertEqual(actual[f"mail-{number:02}.eml"], expected)
            write_report(root, report)
            self.assertEqual(len((root / "indicators.csv").read_text().splitlines()), 8)
            self.assertEqual(json.loads((root / "analysis.json").read_text())["summary"], report["summary"])
            self.assertNotIn("__TRIAGE_JSON__", (root / "dashboard.html").read_text(encoding="utf-8"))
            self.assertEqual(messages[0].read_bytes(), build_demo(root / "other")[0][0].read_bytes())


if __name__ == "__main__":
    unittest.main()

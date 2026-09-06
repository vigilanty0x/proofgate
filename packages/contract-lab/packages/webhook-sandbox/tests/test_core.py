import hashlib
import hmac
import unittest

from webhook_sandbox import inspect_webhook, probe


def signed_event(timestamp="1000", event_id="evt-1", body="{}", key=b"trusted"):
    message = f"{timestamp}.{event_id}.{body}".encode()
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()
    return {"method": "POST", "path": "/hook", "body": body,
            "headers": {"X-Webhook-Timestamp": timestamp, "X-Webhook-ID": event_id,
                        "X-Webhook-Signature": f"sha256={signature}"}}


class Tests(unittest.TestCase):
    def test_offline_accept_is_structural_only(self):
        result = inspect_webhook({"method": "POST", "path": "/hook", "headers": {}, "body": "ok"})
        self.assertTrue(result["accepted"])
        self.assertEqual(result["assurance"], "structural_only")

    def test_hmac_and_replay_store(self):
        seen = set()
        self.assertTrue(inspect_webhook(signed_event(), trusted_key=b"trusted", now=1000,
                                        seen_ids=seen)["accepted"])
        self.assertFalse(inspect_webhook(signed_event(), trusted_key=b"trusted", now=1000,
                                         seen_ids=seen)["accepted"])

    def test_bad_signature_and_stale_timestamp(self):
        event = signed_event()
        event["headers"]["X-Webhook-Signature"] = "sha256=" + "0" * 64
        self.assertIn("signature_mismatch", inspect_webhook(event, trusted_key=b"trusted", now=1000)["errors"])
        self.assertIn("stale_timestamp", inspect_webhook(signed_event(), trusted_key=b"trusted", now=2000)["errors"])

    def test_strict_bounds_and_schema(self):
        base = {"method": "POST", "path": "/x", "headers": {}, "body": "x"}
        for bad in (None, {**base, "extra": 1}, {**base, "path": "/x\nattack"},
                    {**base, "headers": {"A": "x", "a": "y"}},
                    {**base, "body": b"bytes"}, {**base, "body": "\ud800"}):
            self.assertFalse(inspect_webhook(bad)["accepted"])
        self.assertFalse(inspect_webhook(base, True)["accepted"])

    def test_probe(self):
        self.assertTrue(probe()["ok"])


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for agent_airlock.scrubber.
"""

import os
import unittest
from agent_airlock.scrubber import scrub_text, scrub_data


class TestScrubber(unittest.TestCase):
    def test_scrub_api_keys(self):
        text = "export OPENAI_API_KEY=sk-abcdef1234567890abcdef1234567890"
        scrubbed = scrub_text(text)
        self.assertNotIn("sk-abcdef", scrubbed)
        self.assertIn("<SCRUBBED_API_KEY>", scrubbed)

    def test_scrub_github_tokens(self):
        text = "git clone https://ghp_123456789012345678901234567890123456@github.com/repo.git"
        scrubbed = scrub_text(text)
        self.assertNotIn("ghp_", scrubbed)
        self.assertIn("<SCRUBBED_GITHUB_TOKEN>", scrubbed)

    def test_scrub_aws_keys(self):
        text = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        scrubbed = scrub_text(text)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", scrubbed)
        self.assertIn("<SCRUBBED_AWS_KEY_ID>", scrubbed)

    def test_scrub_user_paths_and_names(self):
        text = r"C:\Users\JohnDoe\AppData\Local\Temp\file.txt"
        scrubbed = scrub_text(text)
        self.assertNotIn("JohnDoe", scrubbed)
        self.assertIn(r"C:\Users\<USER>\AppData\Local\Temp\file.txt", scrubbed)

    def test_scrub_linux_paths(self):
        text = "/home/alice/projects/secret_code"
        scrubbed = scrub_text(text)
        self.assertNotIn("alice", scrubbed)
        self.assertIn("/home/<USER>/projects/secret_code", scrubbed)

    def test_scrub_emails(self):
        text = "contact developer at security-team@example.com for access"
        scrubbed = scrub_text(text)
        self.assertNotIn("security-team@example.com", scrubbed)
        self.assertIn("<SCRUBBED_EMAIL>", scrubbed)

    def test_scrub_recursive_dict(self):
        payload = {
            "tool": "run_command",
            "tool_args": {
                "command": "curl -H 'Authorization: Bearer 1234567890abcdef1234' http://192.168.1.50/api",
                "cwd": r"C:\Users\SecretUser\workspace"
            },
            "meta": ["admin@corp.org", "normal_string"]
        }
        cleaned = scrub_data(payload)
        self.assertNotIn("1234567890abcdef1234", cleaned["tool_args"]["command"])
        self.assertNotIn("192.168.1.50", cleaned["tool_args"]["command"])
        self.assertNotIn("SecretUser", cleaned["tool_args"]["cwd"])
        self.assertNotIn("admin@corp.org", cleaned["meta"][0])


if __name__ == "__main__":
    unittest.main()

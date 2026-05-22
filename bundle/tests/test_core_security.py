import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))

from core.security import LoginAttemptLimiter, as_bool  # noqa: E402


class SecurityHelpersTest(unittest.TestCase):
    def test_as_bool_accepts_common_values(self):
        self.assertTrue(as_bool("1"))
        self.assertTrue(as_bool("yes"))
        self.assertTrue(as_bool(True))
        self.assertFalse(as_bool("0", True))
        self.assertFalse(as_bool("off", True))
        self.assertTrue(as_bool("unexpected", True))

    def test_login_limiter_locks_after_threshold_and_resets_on_success(self):
        now = [1000.0]
        limiter = LoginAttemptLimiter(
            max_attempts=3,
            window_seconds=60,
            lockout_seconds=120,
            now_func=lambda: now[0],
        )
        key = "127.0.0.1:admin"

        self.assertTrue(limiter.allow(key))
        self.assertEqual(limiter.record_failure(key), 0)
        self.assertEqual(limiter.record_failure(key), 0)
        self.assertEqual(limiter.record_failure(key), 120)
        self.assertFalse(limiter.allow(key))
        self.assertGreater(limiter.retry_after(key), 0)

        limiter.record_success(key)
        self.assertTrue(limiter.allow(key))

    def test_login_limiter_prunes_old_failures(self):
        now = [1000.0]
        limiter = LoginAttemptLimiter(
            max_attempts=2,
            window_seconds=10,
            lockout_seconds=60,
            now_func=lambda: now[0],
        )
        key = "127.0.0.1:admin"

        limiter.record_failure(key)
        now[0] += 11
        self.assertEqual(limiter.record_failure(key), 0)
        self.assertTrue(limiter.allow(key))


if __name__ == "__main__":
    unittest.main()

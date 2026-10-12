"""Verify upgrades from the published 1.7.1 example databases."""

import sqlite3
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class AccountMigrationTests(unittest.TestCase):
    def database(self, style):
        directory = ROOT / f"examples/cf-workers-{style}/worker/migrations"
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript((directory / "0001_init.sql").read_text())
        db.execute("INSERT INTO user (id, name, email) VALUES ('u', 'Test', 'test@example.com')")
        db.execute("""INSERT INTO account
            (id, issuer, account_id, provider_id, user_id, password, access_token, updated_at)
            VALUES ('a', 'old-issuer', 'remote-id', 'apple', 'u', 'hash', 'token', 123)""")
        db.execute("""INSERT INTO session (id, expires_at, token, updated_at, user_id)
            VALUES ('s', 9999999999999, 'session-token', 123, 'u')""")
        db.commit()
        return db, (directory / "0002_remove_account_issuer.sql").read_text()

    def test_preserves_accounts_and_sessions_and_allows_new_accounts(self):
        for style in ("swiftui", "uikit"):
            with self.subTest(style=style):
                db, migration = self.database(style)
                db.executescript(migration)
                self.assertNotIn("issuer", [row[1] for row in db.execute("PRAGMA table_info(account)")])
                self.assertEqual(db.execute("SELECT password, access_token FROM account").fetchone(), ("hash", "token"))
                self.assertEqual(db.execute("SELECT token FROM session").fetchone(), ("session-token",))
                db.execute("""INSERT INTO account (id, account_id, provider_id, user_id, updated_at)
                    VALUES ('b', 'remote-id', 'google', 'u', 123)""")
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute("""INSERT INTO account (id, account_id, provider_id, user_id, updated_at)
                        VALUES ('c', 'remote-id', 'apple', 'u', 123)""")
                self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
                db.execute("DELETE FROM user WHERE id = 'u'")
                self.assertEqual(db.execute("SELECT COUNT(*) FROM account").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM session").fetchone()[0], 0)

    def test_duplicate_provider_accounts_fail_before_schema_changes(self):
        for style in ("swiftui", "uikit"):
            with self.subTest(style=style):
                db, migration = self.database(style)
                db.execute("""INSERT INTO account
                    (id, issuer, account_id, provider_id, user_id, updated_at)
                    VALUES ('b', 'other-issuer', 'remote-id', 'apple', 'u', 123)""")
                db.commit()
                with self.assertRaises(sqlite3.IntegrityError):
                    db.executescript(migration)
                self.assertIn("issuer", [row[1] for row in db.execute("PRAGMA table_info(account)")])
                self.assertEqual(db.execute("SELECT COUNT(*) FROM account").fetchone()[0], 2)
                self.assertIn("account_issuer_accountId_uidx", [row[1] for row in db.execute("PRAGMA index_list(account)")])


if __name__ == "__main__":
    unittest.main()

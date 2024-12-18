import unittest
import os
import sqlite3
import time
from app import app, init_db, save_rsa_key, get_rsa_key, DB_NAME
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class JWKSAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()
        cls.app = app.test_client()
        cls.app.testing = True

    def insert_invalid_key(self):
        """Insert an invalid key format to test deserialization error handling in jwks endpoint."""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")  # Clear any existing keys
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", ("INVALID_KEY_DATA", int(time.time()) + 3600))
        conn.commit()
        conn.close()

    def insert_keys(self):
        """Insert both valid and expired keys into the database for testing purposes."""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")  # Clear any existing keys

        # Create an expired key
        private_key_expired = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pem_key_expired = private_key_expired.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_key_expired, int(time.time()) - 3600))

        # Create a valid key
        private_key_valid = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        pem_key_valid = private_key_valid.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_key_valid, int(time.time()) + 3600))

        conn.commit()
        conn.close()

    def test_keys_in_database(self):
        """Verify that keys are saved in the database."""
        self.insert_keys()
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM keys")
        key_count = cursor.fetchone()[0]
        conn.close()
        self.assertGreater(key_count, 0, "No keys found in the database.")

    def test_save_rsa_key(self):
        """Test saving a key using save_rsa_key within an app context."""
        with app.app_context():
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys")  # Clear any existing keys
            conn.commit()
            conn.close()

            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            exp_time = int(time.time()) + 3600
            save_rsa_key(private_key, exp_time)

            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM keys WHERE exp = ?", (exp_time,))
            key_count = cursor.fetchone()[0]
            conn.close()
            self.assertEqual(key_count, 1)

    def test_jwks(self):
        """Test the JWKS endpoint to ensure it returns only valid keys."""
        self.insert_keys()
        response = self.app.get("/.well-known/jwks.json")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("keys", data)
        self.assertGreater(len(data["keys"]), 0, "No valid keys found in JWKS response")

    def test_jwks_with_invalid_key(self):
        """Test JWKS endpoint handling with an invalid key in the database."""
        self.insert_invalid_key()
        response = self.app.get("/.well-known/jwks.json")
        data = response.get_json()
        self.assertEqual(response.status_code, 500)
        self.assertIsNotNone(data)
        self.assertIn("error", data)

    def test_auth_valid_jwt(self):
        """Test the /auth endpoint without the expired parameter to get a valid JWT."""
        self.insert_keys()
        response = self.app.post("/auth")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", data)

    def test_auth_expired_jwt(self):
        """Test the /auth endpoint with the expired parameter to get an expired JWT."""
        self.insert_keys()
        response = self.app.post("/auth?expired=true")
        data = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", data)

    def test_auth_with_no_keys(self):
        """Test the /auth endpoint when no keys are available in the database."""
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")  # Clear all keys
        conn.commit()
        conn.close()

        response = self.app.post("/auth")
        data = response.get_json()
        self.assertIsNotNone(data, "Response data should not be None")
        self.assertEqual(response.status_code, 500)
        self.assertIn("error", data)

    def test_user_registration(self):
        """Test user registration endpoint."""
        response = self.app.post("/register", json={
            "username": "testuser",
            "email": "testuser@example.com"
        })
        data = response.get_json()
        self.assertEqual(response.status_code, 201)
        self.assertIn("password", data)

        # Verify user in database
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = ?", ("testuser",))
        user_count = cursor.fetchone()[0]
        conn.close()
        self.assertEqual(user_count, 1)

    def test_auth_logging(self):
        """Test that authentication requests are logged."""
        self.insert_keys()
        response = self.app.post("/auth", json={"user_id": 1})
        self.assertEqual(response.status_code, 200)

        # Check logs
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM auth_logs WHERE user_id = ?", (1,))
        log_count = cursor.fetchone()[0]
        conn.close()
        self.assertGreater(log_count, 0)

    def test_rate_limiting(self):
        """Test rate limiting on the /auth endpoint."""
        self.insert_keys()

        # Exceed rate limit
        for _ in range(15):  # Exceeding the 10 requests per second limit
            response = self.app.post("/auth", json={"user_id": 1})
            if response.status_code == 429:
                break

        self.assertEqual(response.status_code, 429)

    def test_get_rsa_key_no_keys(self):
        """Test get_rsa_key function when no keys are available in the database."""
        with app.app_context():
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM keys")
            conn.commit()
            conn.close()

            key, kid = get_rsa_key()
            self.assertIsNone(key, "Key should be None when no keys are present.")
            self.assertIsNone(kid, "Kid should be None when no keys are present.")


if __name__ == "__main__":
    unittest.main()

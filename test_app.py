import unittest
from app import app, generate_rsa_key

class JWKSAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Set up the Flask app for testing
        cls.app = app.test_client()
        cls.app.testing = True

        # Generate a RSA key for testing
        generate_rsa_key()

    def test_jwks(self):
        response = self.app.get("/jwks")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("keys", data)
        self.assertGreater(len(data["keys"]), 0)

    def test_auth_valid_jwt(self):
        response = self.app.post("/auth")
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.get_json())

    def test_auth_expired_jwt(self):
        response = self.app.post("/auth?expired=true")
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.get_json())

if __name__ == "__main__":
    unittest.main()

import time
import jwt
import sqlite3
from flask import Flask, jsonify, request, g
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

app = Flask(__name__)
DB_NAME = os.path.join(os.path.dirname(__file__), 'totally_not_my_privateKeys.db')

def get_db_connection():
    """Provide a SQLite database connection for requests."""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_NAME, check_same_thread=False)
    return g.db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection when the app context ends."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the SQLite database and create the keys table if it doesn't exist."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def save_rsa_key(private_key, exp):
    """Serialize and store an RSA private key in the SQLite database."""
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_key, exp))
    conn.commit()

def get_rsa_key(expired=False):
    """Retrieve an RSA key from the database, based on expiration."""
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())
    if expired:
        cursor.execute("SELECT key, kid FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (current_time,))
    else:
        cursor.execute("SELECT key, kid FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
    result = cursor.fetchone()
    return result if result else (None, None)

@app.route('/.well-known/jwks.json', methods=["GET"])
def jwks():
    """Return public keys in JWKS format."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        current_time = int(time.time())
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (current_time,))
        valid_keys = cursor.fetchall()
        
        jwks_keys = []
        for kid, pem_key in valid_keys:
            try:
                private_key = serialization.load_pem_private_key(
                    pem_key.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                public_key = private_key.public_key()
                public_numbers = public_key.public_numbers()
                jwks_keys.append({
                    "kty": "RSA",
                    "kid": str(kid),
                    "n": str(public_numbers.n),
                    "e": str(public_numbers.e),
                    "use": "sig"
                })
            except ValueError:
                print(f"Error loading key {kid}: Invalid key format")
                return jsonify({"error": "Error loading keys"}), 500

        return jsonify({"keys": jwks_keys}), 200
    except Exception as e:
        print(f"Error retrieving keys: {e}")
        return jsonify({"error": "Error retrieving keys"}), 500

@app.route("/auth", methods=["POST"])
def auth():
    """Authenticate user and issue JWT signed by RSA private key."""
    expired = request.args.get("expired") == "true"
    pem_key, kid = get_rsa_key(expired=expired)
    
    if not pem_key:
        return jsonify({"error": "No suitable keys available"}), 500

    private_key = serialization.load_pem_private_key(
        pem_key.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    exp_time = time.time() - 3600 if expired else time.time() + 900
    payload = {"sub": "fake_user", "iat": time.time(), "exp": exp_time}
    
    # Use the `kid` from the database in the JWT header
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": str(kid)})
    return jsonify({"token": token}), 200

if __name__ == "__main__":
    init_db()

    # Clear existing keys to avoid duplication issues
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM keys")
    conn.commit()

    # Insert an expired and a valid key
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
    
    app.run(host="0.0.0.0", port=8080)

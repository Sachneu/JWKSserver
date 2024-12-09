import time
import os
import jwt
import sqlite3
import logging
from flask import Flask, jsonify, request, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import uuid
import binascii

# Initialize Flask app
app = Flask(__name__)

# Configure rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per second"],
    storage_uri="memory://"
)

# Logging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants
DB_NAME = os.path.join(os.path.dirname(__file__), 'totally_not_my_privateKeys.db')
AES_KEY = os.getenv('NOT_MY_KEY', secrets.token_bytes(32))  # Generate a secure AES key

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
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Create the keys table with the iv column
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        iv BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    """)
    # Create the auth_logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    user_id INTEGER, 
    timestamp INTEGER NOT NULL
    )

    """)
    # Create the users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
    )
    """)
    conn.commit()
    conn.close()

def encrypt_private_key(private_key_pem):
    """Encrypt the private key using AES."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(private_key_pem) + encryptor.finalize()
    logger.debug(f"Private Key Encrypted: {binascii.hexlify(encrypted_key)}")
    logger.debug(f"IV Used: {binascii.hexlify(iv)}")
    return encrypted_key, iv

def decrypt_private_key(encrypted_key, iv):
    """Decrypt the private key using AES."""
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key) + decryptor.finalize()

def save_rsa_key(private_key, exp):
    """Serialize and store an RSA private key in the SQLite database with encryption."""
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_key, iv = encrypt_private_key(pem_key)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO keys (key, iv, exp) VALUES (?, ?, ?)",
        (sqlite3.Binary(encrypted_key), sqlite3.Binary(iv), exp)
    )
    conn.commit()
    logger.info(f"Saved RSA key with expiration: {exp}")

def get_rsa_key(expired=False):
    """Retrieve an RSA key from the database, based on expiration."""
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())
    if expired:
        cursor.execute("SELECT key, iv FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (current_time,))
    else:
        cursor.execute("SELECT key, iv FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (current_time,))
    result = cursor.fetchone()
    if result:
        encrypted_key, iv = result
        decrypted_key = decrypt_private_key(encrypted_key, iv)
        return decrypted_key
    return None

@app.route('/register', methods=["POST"])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({"error": "Username and email are required"}), 400

    password = str(uuid.uuid4())  # Generate a valid UUID
    password_hash = secrets.token_hex(32)  # Simplified hashing for demo purposes

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 400

@app.route("/auth", methods=["POST"])
@limiter.limit("10 per second")
def auth():
    try:
        expired = request.args.get("expired") == "true"
        pem_key = get_rsa_key(expired=expired)

        if not pem_key:
            return jsonify({"error": "No suitable keys available"}), 500

        private_key = serialization.load_pem_private_key(
            pem_key,
            password=None,
            backend=default_backend()
        )

        exp_time = time.time() - 3600 if expired else time.time() + 900
        payload = {"sub": "fake_user", "iat": time.time(), "exp": exp_time}
        token = jwt.encode(payload, private_key, algorithm="RS256")
        return jsonify({"token": token}), 200
    except Exception as e:
        app.logger.error(f"Error in /auth endpoint: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/.well-known/jwks.json', methods=["GET"])
def jwks():
    """Return public keys in JWKS format."""
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())
    cursor.execute("SELECT id, key, iv FROM keys WHERE exp > ?", (current_time,))
    keys = cursor.fetchall()

    jwks_keys = []
    for kid, encrypted_key, iv in keys:
        decrypted_key = decrypt_private_key(encrypted_key, iv)
        private_key = serialization.load_pem_private_key(
            decrypted_key,
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

    return jsonify({"keys": jwks_keys}), 200

if __name__ == "__main__":
    init_db()


    with app.app_context():
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys")

        private_key_expired = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        save_rsa_key(private_key_expired, int(time.time()) - 3600)

        private_key_valid = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        save_rsa_key(private_key_valid, int(time.time()) + 3600)

        conn.commit()
        conn.close()

    app.run(host="0.0.0.0", port=8080)

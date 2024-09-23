import time
import json
import jwt
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
# Root route
@app.route('/')
def home():
    return "Welcome to the JWKS Server", 200

# Global variable to hold RSA keys
rsa_keys = []  

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    kid = str(time.time())
    expiry = time.time() + 86400  # 24 hours
    rsa_keys.append({
        "private_key": private_key,
        "public_key": public_key.decode("utf-8"),  # Decode to string for JSON serialization
        "kid": kid,
        "expiry": expiry
    })

@app.route("/jwks", methods=["GET"])
def jwks():
    print("Serving JWKS")
    valid_keys = [key for key in rsa_keys if key["expiry"] > time.time()]

    # Debugging key generation
    print(f"Valid keys: {len(valid_keys)}")

    if not valid_keys:
        print("No valid keys available.")
        
    # Return only public keys
    return jsonify({"keys": [{"kty": "RSA", "kid": key["kid"], "n": key["public_key"], "use": "sig"} for key in valid_keys]}), 200


@app.route("/auth", methods=["POST"])
def auth():
    print("Received /auth request")
    expired = request.args.get("expired") == "true"
    
    if expired:
        print("Issuing expired JWT")
    else:
        print("Issuing valid JWT")
    
    # Check if key exists before signing
    if not rsa_keys:
        print("No RSA keys found!")
        return jsonify({"error": "No keys available"}), 500
    
    exp_time = time.time() - 3600 if expired else time.time() + 900
    payload = {"sub": "fake_user", "iat": time.time(), "exp": exp_time}
    
    # Get the most recent private key for signing
    signing_key = rsa_keys[-1]  # Use the last generated key
    private_key = signing_key["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": signing_key["kid"]})
    return jsonify({"token": token}), 200

if __name__ == "__main__":
    generate_rsa_key()  # Create at least one key to start
    app.run(host="0.0.0.0", port=8080)

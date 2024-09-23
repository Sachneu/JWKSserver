# JWKS Server

## Overview

This is a JWKS (JSON Web Key Set) server that provides public keys for verifying JSON Web Tokens (JWTs).

## Features

- Issues valid JWTs upon authentication.
- Provides JWKS endpoint for retrieving keys.
- Supports expired JWK handling.

## Requirements

This project requires the following Python packages to be installed:

- **Flask**: A lightweight WSGI web application framework.
- **PyJWT**: A Python library to encode and decode JSON Web Tokens.
- **Flask-Cors**: A Flask extension for handling Cross-Origin Resource Sharing (CORS).

You can install these packages using pip:


pip install Flask PyJWT Flask-Cors


## Running the Server
Step 1:  Create Repository in your Local Machine

git clone https://github.com/Sachneu/JWKSserver.git


Step2: Create virtual environment

python -m venv venv


Step3: Activate Virtual environment

On Windows:   venv\Scripts\activate

Step 4: Install required packages:

pip install Flask PyJWT Flask-Cors


Step 5: Run

python app.py


### The server will run on http://127.0.0.1:8080

### Endpoints


/auth: Issues a valid JWT.
/jwks: Returns the JWKS.


### Testing
You can run the tests using pytest:

pytest --cov=app test_app.py











On macOS/Linux:  source venv/bin/activate




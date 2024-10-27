## Project 2 (continued from project 1)
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


 cd JWKSserver

Step2: Create virtual environment

python -m venv venv


Step3: Activate Virtual environment

On Windows:   venv\Scripts\activate

Step 4: Install required packages:

pip install Flask PyJWT Flask-Cors pytest coverage



Step 5: Run

python app.py


### The server will run on http://127.0.0.1:8080

### Endpoints


/auth: Issues a valid JWT.
/jwks: Returns the JWKS.



### Open another terminal (or Command Prompt) and use the following commands to test the endpoints:

Get JWKS:
curl -X GET http://127.0.0.1:8080/jwks


Authenticate (get JWT):
curl -X POST http://127.0.0.1:8080/auth


Authenticate with expired JWT:
curl -X POST http://127.0.0.1:8080/auth?expired=true


### Testing
To run tests in test_app.py with coverage, use the following command:

coverage run -m unittest discover
coverage report -m

















# JWKSserver

Overview
This project implements a JSON Web Key Set (JWKS) server using Flask. The server provides endpoints to authenticate users and issue JSON Web Tokens (JWTs). It also serves public keys for JWT verification.

Features
Issue valid JWTs for authenticated users.
Serve JWKS containing public keys.
Handle expired JWTs and JWKs.
Provide appropriate HTTP methods and status codes.
Requirements
Python 3.7 or higher
Flask
PyJWT
Other dependencies (as specified in requirements.txt)
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/Sachneu/JWKSserver.git
cd JWKSserver
Set up a virtual environment (optional but recommended):

bash
Copy code
python -m venv venv
Activate the virtual environment:

On Windows:
bash
Copy code
venv\Scripts\activate
On macOS/Linux:
bash
Copy code
source venv/bin/activate
Install dependencies:

bash
Copy code
pip install -r requirements.txt
Running the Server
Start the Flask application:
bash
Copy code
python app.py
The server will run at http://127.0.0.1:8080.
API Endpoints
1. Authentication Endpoint
URL: /auth
Method: POST
Description: Authenticates a user and returns a valid JWT.
Example Request:
bash
Copy code
curl -X POST http://127.0.0.1:8080/auth
2. JWKS Endpoint
URL: /jwks
Method: GET
Description: Returns the JSON Web Key Set containing public keys.
Example Request:
bash
Copy code
curl http://127.0.0.1:8080/jwks
Running Tests
You can run tests using pytest to ensure everything is working correctly.

Install pytest (if you haven't already):

bash
Copy code
pip install pytest pytest-cov
Run the tests:

bash
Copy code
pytest --cov=app test_app.py
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Author
Sachet Neupane
Acknowledgments
Flask documentation
JSON Web Tokens documentation
Other libraries and resources used in this project

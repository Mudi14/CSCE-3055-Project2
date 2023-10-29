from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import time

# Database file name
db_file = "totally_not_my_privateKeys.db"

hostName = "localhost"
serverPort = 8080

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

# Function to create the keys table if it doesn't exist
def create_keys_table():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Function to insert a key into the database
def insert_key(key, exp):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))
    conn.commit()
    conn.close()

# Function to retrieve an unexpired or expired key
def get_key(expired=False):
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT * FROM keys WHERE exp <= ?", (int(time.time()),))
    else:
        cursor.execute("SELECT * FROM keys WHERE exp > ?", (int(time.time()),))
    row = cursor.fetchone()
    conn.close()
    return row

def get_keys():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys WHERE exp > ?", (int(time.time()),))
    rows = cursor.fetchall()
    conn.close()
    return rows

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    # Modified the do_POST method
    def do_POST(self):
        #For Testing
        print("hit")
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Retrieve the private key from the database
            key = get_key('expired' in params)
            if key is not None:
                headers = {
                    "kid": str(key[0])
                }
                token_payload = {
                    "exp": key[2]
                }
                private_key = serialization.load_pem_private_key(key[1], None)
                encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
            else:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Private key not found.")
            return

    # Modified the do_GET method
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            keys = get_keys()
            jwks = []
            print(keys)
            for key in keys:
                numbers = serialization.load_pem_private_key(key[1], None).private_numbers()
                jwks.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(key[0]),
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                })
            resp = {
                "keys": jwks
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(json.dumps(resp), "utf-8"))
            return


if __name__ == "__main__":
    create_keys_table()
    insert_key(pem, int (time.time() + 1000))
    insert_key(expired_pem, int (time.time() - 1000))
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
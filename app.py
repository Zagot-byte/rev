"""
Flask CTF Challenge - WASM IDOR Login
A simple login page with an intentional IDOR vulnerability.
"""
from flask import Flask, render_template, request, jsonify, send_from_directory, abort, redirect, url_for, session
import os

app = Flask(__name__)

# The flag - only revealed on successful admin login
FLAG = "FLAG{wasm_1d0r_x0r_m4st3r}"

# XOR key used in admin.wasm
XOR_KEY = 0x5A

# XOR-encrypted credentials from admin.wasm
ENCRYPTED_USERNAME = bytes([0x29, 0x2f, 0x2a, 0x3f, 0x28, 0x3b, 0x3e, 0x37, 0x33, 0x34])  # "superadmin"
ENCRYPTED_PASSWORD = bytes([0x3c, 0x36, 0x6e, 0x3d, 0x05, 0x32, 0x2f, 0x34, 0x2e, 0x69, 0x28, 0x7b])  # "fl4g_hunt3r"

WASM_DIR = os.path.join(os.path.dirname(__file__), 'wasm')


def check(username: str, password: str) -> bool:
    """
    Validate credentials using XOR decryption logic from admin.wasm.
    This mirrors the WASM validation on the backend.
    
    Returns True if credentials match, False otherwise.
    """
    # Check username
    if len(username) != len(ENCRYPTED_USERNAME):
        return False
    
    for i, encrypted_byte in enumerate(ENCRYPTED_USERNAME):
        decrypted_byte = encrypted_byte ^ XOR_KEY
        if ord(username[i]) != decrypted_byte:
            return False
    
    # Check password
    if len(password) != len(ENCRYPTED_PASSWORD):
        return False
    
    for i, encrypted_byte in enumerate(ENCRYPTED_PASSWORD):
        decrypted_byte = encrypted_byte ^ XOR_KEY
        if ord(password[i]) != decrypted_byte:
            return False
    
    return True


@app.route('/')
def index():
    """Serve the login page."""
    return render_template('index.html')


@app.route('/api/<filename>.wasm')
def serve_wasm(filename):
    """
    Serve WASM files.
    VULNERABILITY: No authorization check - IDOR allows access to admin.wasm
    """
    wasm_file = f"{filename}.wasm"
    wasm_path = os.path.join(WASM_DIR, wasm_file)
    
    if os.path.exists(wasm_path):
        return send_from_directory(WASM_DIR, wasm_file, mimetype='application/wasm')
    else:
        abort(404)


@app.route('/login', methods=['POST'])
def login():
    """
    Handle login requests.
    Validates credentials and returns redirect URL on successful admin login.
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Server-side validation using XOR decryption (mirrors admin.wasm)
    if check(username, password):
        return jsonify({
            'success': True,
            'redirect': '/flag'
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Invalid credentials'
        }), 401


@app.route('/flag')
def flag():
    """Serve the flag page."""
    return render_template('flag.html', flag=FLAG)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

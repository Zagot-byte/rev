# WASM IDOR Login Challenge

A CTF challenge featuring a vulnerable login portal with an Insecure Direct Object Reference (IDOR) vulnerability.

## Setup

### Requirements
- Python 3.8+
- Flask
- WABT toolkit (for building WASM from source)

### Installation

```bash
# Install Python dependencies
pip install flask

# Install WABT (if building from WAT source)
# Ubuntu/Debian: sudo apt install wabt
# macOS: brew install wabt
```

### Building WASM (if needed)

```bash
cd wasm
wat2wasm user.wat -o user.wasm
wat2wasm admin.wat -o admin.wasm
```

### Running

```bash
python app.py
```

Visit `http://localhost:5000` in your browser.

## Challenge Description

You've discovered a secure login portal. Can you find a way to authenticate as the admin and capture the flag?

**Hint**: Sometimes developers leave more than they should accessible...

## For CTF Organizers

**Difficulty**: Medium  
**Category**: Web, Reverse Engineering  
**Points**: Suggested 300-500

### Solution Path
1. Inspect JavaScript to find WASM endpoint
2. Discover IDOR at `/api/admin.wasm`
3. Reverse engineer admin.wasm
4. Extract XOR key and encrypted credentials
5. Decrypt to obtain admin login
6. Capture the flag

### Flag
`FLAG{wasm_1d0r_x0r_m4st3r}`

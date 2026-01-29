/**
 * Login Handler - WASM Credential Validation
 * Loads user.wasm for credential validation
 */

// WASM module instance
let wasmInstance = null;

// Configuration for WASM validator
const WASM_CONFIG = {
    // Default validator for regular users
    validator: '/api/user.wasm',
    // Memory configuration
    memoryPages: 1
};

/**
 * Initialize the WASM module
 */
async function initWasm() {
    try {
        const response = await fetch(WASM_CONFIG.validator);
        if (!response.ok) {
            throw new Error('Failed to load validator module');
        }

        const wasmBytes = await response.arrayBuffer();
        const wasmModule = await WebAssembly.instantiate(wasmBytes, {
            env: {
                memory: new WebAssembly.Memory({ initial: WASM_CONFIG.memoryPages })
            }
        });

        wasmInstance = wasmModule.instance;
        console.log('Validator module loaded successfully');
        return true;
    } catch (error) {
        console.error('WASM initialization failed:', error);
        // Fallback: try loading admin.wasm if user.wasm fails (for debugging)
        // TODO: Remove this fallback before production
        return false;
    }
}

/**
 * Write string to WASM memory
 */
function writeStringToMemory(str, offset) {
    if (!wasmInstance || !wasmInstance.exports.memory) {
        return false;
    }

    const memory = new Uint8Array(wasmInstance.exports.memory.buffer);
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);

    for (let i = 0; i < bytes.length; i++) {
        memory[offset + i] = bytes[i];
    }
    memory[offset + bytes.length] = 0; // Null terminator

    return bytes.length;
}

/**
 * Validate credentials using WASM
 */
function validateCredentials(username, password) {
    if (!wasmInstance) {
        console.warn('WASM not initialized, skipping client validation');
        return true; // Fallback to server-side validation
    }

    try {
        // Write credentials to WASM memory
        const usernameOffset = 256;
        const passwordOffset = 512;

        writeStringToMemory(username, usernameOffset);
        writeStringToMemory(password, passwordOffset);

        // Call WASM validate function
        if (wasmInstance.exports.validate) {
            return wasmInstance.exports.validate(
                usernameOffset,
                username.length,
                passwordOffset,
                password.length
            ) === 1;
        }

        return true; // Fallback if validate function not found
    } catch (error) {
        console.error('Validation error:', error);
        return true; // Fallback to server-side
    }
}

/**
 * Show message to user
 */
function showMessage(text, isError = true) {
    const messageEl = document.getElementById('message');
    messageEl.textContent = text;
    messageEl.className = 'message ' + (isError ? 'error' : 'success');
}

/**
 * Handle login form submission
 */
async function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const submitBtn = document.getElementById('login-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const btnLoader = submitBtn.querySelector('.btn-loader');

    if (!username || !password) {
        showMessage('Please enter both username and password');
        return;
    }

    // Disable button and show loader
    submitBtn.disabled = true;
    btnText.style.display = 'none';
    btnLoader.style.display = 'inline';

    try {
        // Client-side WASM validation (optional)
        const clientValid = validateCredentials(username, password);

        if (!clientValid) {
            showMessage('Invalid credentials');
            return;
        }

        // Server-side validation
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (data.success) {
            // Redirect to flag page on successful login
            window.location.href = data.redirect || '/flag';
        } else {
            showMessage(data.message || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        showMessage('An error occurred. Please try again.');
    } finally {
        // Re-enable button
        submitBtn.disabled = false;
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
    // Initialize WASM validator
    await initWasm();

    // Set up form handler
    const loginForm = document.getElementById('login-form');
    loginForm.addEventListener('submit', handleLogin);
});

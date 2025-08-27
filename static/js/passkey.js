// WebAuthn/Passkey JavaScript Implementation

class PasskeyManager {
    constructor() {
        this.modal = null;
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.modal = document.getElementById('passkeyModal');
    }

    setupEventListeners() {
        // Register passkey button
        const registerBtn = document.getElementById('register-passkey');
        if (registerBtn) {
            registerBtn.addEventListener('click', () => this.registerPasskey());
        }

        // Authenticate passkey button
        const authBtn = document.getElementById('authenticate-passkey');
        if (authBtn) {
            authBtn.addEventListener('click', () => this.authenticatePasskey());
        }
    }

    showModal(title, content) {
        if (this.modal) {
            this.modal.querySelector('.modal-title').textContent = title;
            this.modal.querySelector('.modal-body').innerHTML = content;
            const bsModal = new bootstrap.Modal(this.modal);
            bsModal.show();
            return bsModal;
        }
    }

    hideModal() {
        const bsModal = bootstrap.Modal.getInstance(this.modal);
        if (bsModal) {
            bsModal.hide();
        }
    }

    async registerPasskey() {
        try {
            this.showModal('Register Passkey', `
                <div class="text-center">
                    <div class="webauthn-icon passkey-animation">🔐</div>
                    <p>Initializing passkey registration...</p>
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            `);

            // Begin registration
            const response = await fetch('/webauthn/register/begin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            });

            if (!response.ok) {
                throw new Error('Failed to begin registration');
            }

            const options = await response.json();
            
            this.showModal('Register Passkey', `
                <div class="text-center webauthn-prompt">
                    <div class="webauthn-icon passkey-animation">👆</div>
                    <h5>Touch your authenticator</h5>
                    <p class="text-muted">Follow your browser's prompts to create a new passkey. You may need to use your fingerprint, face recognition, or security key.</p>
                </div>
            `);

            // Convert base64url strings to ArrayBuffer
            options.options.challenge = this.base64urlToArrayBuffer(options.options.challenge);
            options.options.user.id = this.base64urlToArrayBuffer(options.options.user.id);
            
            if (options.options.excludeCredentials) {
                options.options.excludeCredentials = options.options.excludeCredentials.map(cred => ({
                    ...cred,
                    id: this.base64urlToArrayBuffer(cred.id)
                }));
            }

            // Create credential
            const credential = await navigator.credentials.create({
                publicKey: options.options
            });

            // Convert credential to JSON format
            const credentialJson = {
                id: credential.id,
                rawId: this.arrayBufferToBase64url(credential.rawId),
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64url(credential.response.attestationObject)
                },
                type: credential.type
            };

            // Complete registration
            const completeResponse = await fetch('/webauthn/register/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credentialJson)
            });

            const result = await completeResponse.json();

            if (result.verified) {
                this.showModal('Success!', `
                    <div class="text-center">
                        <div class="webauthn-icon text-success">✅</div>
                        <h5 class="text-success">Passkey Registered Successfully!</h5>
                        <p>Your passkey has been registered and can now be used for authentication.</p>
                    </div>
                `);
                
                setTimeout(() => {
                    this.hideModal();
                    window.location.reload();
                }, 2000);
            } else {
                throw new Error(result.error || 'Registration verification failed');
            }

        } catch (error) {
            console.error('Passkey registration error:', error);
            
            let errorMessage = 'An error occurred during passkey registration.';
            
            if (error.name === 'NotAllowedError') {
                errorMessage = 'Passkey registration was cancelled or not allowed.';
            } else if (error.name === 'NotSupportedError') {
                errorMessage = 'Passkeys are not supported on this device/browser.';
            } else if (error.name === 'SecurityError') {
                errorMessage = 'Security error: Please ensure you\'re using HTTPS.';
            } else if (error.message) {
                errorMessage = error.message;
            }

            this.showModal('Registration Failed', `
                <div class="text-center">
                    <div class="webauthn-icon text-danger">❌</div>
                    <h5 class="text-danger">Registration Failed</h5>
                    <p class="text-muted">${errorMessage}</p>
                    <button class="btn btn-secondary" onclick="passkeyManager.hideModal()">Close</button>
                </div>
            `);
        }
    }

    async authenticatePasskey() {
        const email = document.getElementById('passkey-email').value;
        
        if (!email) {
            window.toastManager.error('Please enter your email address');
            return;
        }

        try {
            this.showModal('Authenticate with Passkey', `
                <div class="text-center">
                    <div class="webauthn-icon passkey-animation">🔐</div>
                    <p>Preparing authentication...</p>
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            `);

            // Begin authentication
            const response = await fetch('/webauthn/authenticate/begin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email: email })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Failed to begin authentication');
            }

            const options = await response.json();
            
            this.showModal('Authenticate with Passkey', `
                <div class="text-center webauthn-prompt">
                    <div class="webauthn-icon passkey-animation">👆</div>
                    <h5>Touch your authenticator</h5>
                    <p class="text-muted">Use your registered passkey to authenticate. You may need to use your fingerprint, face recognition, or security key.</p>
                </div>
            `);

            // Convert base64url strings to ArrayBuffer
            options.options.challenge = this.base64urlToArrayBuffer(options.options.challenge);
            
            if (options.options.allowCredentials) {
                options.options.allowCredentials = options.options.allowCredentials.map(cred => ({
                    ...cred,
                    id: this.base64urlToArrayBuffer(cred.id)
                }));
            }

            // Get credential
            const credential = await navigator.credentials.get({
                publicKey: options.options
            });

            // Convert credential to JSON format
            const credentialJson = {
                id: credential.id,
                rawId: this.arrayBufferToBase64url(credential.rawId),
                response: {
                    authenticatorData: this.arrayBufferToBase64url(credential.response.authenticatorData),
                    clientDataJSON: this.arrayBufferToBase64url(credential.response.clientDataJSON),
                    signature: this.arrayBufferToBase64url(credential.response.signature),
                    userHandle: credential.response.userHandle ? this.arrayBufferToBase64url(credential.response.userHandle) : null
                },
                type: credential.type
            };

            // Complete authentication
            const completeResponse = await fetch('/webauthn/authenticate/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credentialJson)
            });

            const result = await completeResponse.json();

            if (result.verified) {
                this.showModal('Authentication Successful!', `
                    <div class="text-center">
                        <div class="webauthn-icon text-success">✅</div>
                        <h5 class="text-success">Authentication Successful!</h5>
                        <p>Redirecting to success page...</p>
                    </div>
                `);
                
                setTimeout(() => {
                    window.location.href = result.redirect;
                }, 1500);
            } else {
                throw new Error(result.error || 'Authentication verification failed');
            }

        } catch (error) {
            console.error('Passkey authentication error:', error);
            
            let errorMessage = 'An error occurred during passkey authentication.';
            
            if (error.name === 'NotAllowedError') {
                errorMessage = 'Authentication was cancelled or not allowed.';
            } else if (error.name === 'NotSupportedError') {
                errorMessage = 'Passkeys are not supported on this device/browser.';
            } else if (error.name === 'SecurityError') {
                errorMessage = 'Security error: Please ensure you\'re using HTTPS.';
            } else if (error.message.includes('No credentials found')) {
                errorMessage = 'No passkeys found for this email address.';
            } else if (error.message) {
                errorMessage = error.message;
            }

            this.showModal('Authentication Failed', `
                <div class="text-center">
                    <div class="webauthn-icon text-danger">❌</div>
                    <h5 class="text-danger">Authentication Failed</h5>
                    <p class="text-muted">${errorMessage}</p>
                    <button class="btn btn-secondary" onclick="passkeyManager.hideModal()">Close</button>
                </div>
            `);
        }
    }

    // Utility functions for base64url encoding/decoding
    arrayBufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    base64urlToArrayBuffer(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
        const binary = atob(padded);
        const buffer = new ArrayBuffer(binary.length);
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return buffer;
    }

    // Check if WebAuthn is supported
    static isSupported() {
        return window.PublicKeyCredential !== undefined &&
               typeof window.PublicKeyCredential === 'function';
    }

    // Check if platform authenticator is available
    static async isPlatformAuthenticatorAvailable() {
        if (!this.isSupported()) return false;
        
        try {
            return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        } catch (error) {
            console.warn('Error checking platform authenticator availability:', error);
            return false;
        }
    }
}

// Initialize PasskeyManager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check WebAuthn support
    if (!PasskeyManager.isSupported()) {
        // Hide passkey authentication card if not supported
        const passkeyCard = document.querySelector('.card-header:contains("Passkey")');
        if (passkeyCard) {
            passkeyCard.closest('.card').style.display = 'none';
        }
        
        console.warn('WebAuthn not supported on this browser/device');
        return;
    }

    // Initialize passkey manager
    window.passkeyManager = new PasskeyManager();
    
    // Check for platform authenticator availability
    PasskeyManager.isPlatformAuthenticatorAvailable().then(available => {
        if (!available) {
            // Show warning about external authenticator requirement
            const passkeyCard = document.querySelector('[data-auth-method="passkey"]');
            if (passkeyCard) {
                const warning = document.createElement('div');
                warning.className = 'alert alert-warning alert-sm mt-2';
                warning.innerHTML = '⚠️ Platform authenticator not available. You may need an external security key.';
                passkeyCard.appendChild(warning);
            }
        }
    });
});

// Export for use in other scripts
window.PasskeyManager = PasskeyManager;
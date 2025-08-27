// Admin Configuration JavaScript
// Using ES5 syntax for maximum compatibility

document.addEventListener('DOMContentLoaded', function() {
    // Form submission handler
    var configForm = document.getElementById('configForm');
    if (configForm) {
        configForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            var formData = new FormData(this);
            var configData = {};
            
            // Convert form data to object - use traditional iteration for compatibility
            var formDataEntries = formData.entries();
            var entry = formDataEntries.next();
            while (!entry.done) {
                configData[entry.value[0]] = entry.value[1];
                entry = formDataEntries.next();
            }
            
            // Handle checkboxes
            var scimEnabled = document.getElementById('scim_enabled');
            if (scimEnabled) {
                configData['scim_enabled'] = scimEnabled.checked ? 'true' : 'false';
            }
            
            fetch('/admin/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(configData)
            }).then(function(response) {
                if (response.ok) {
                    // Show success modal using Bootstrap
                    var successModal = document.getElementById('successModal');
                    if (successModal && typeof bootstrap !== 'undefined') {
                        var modal = new bootstrap.Modal(successModal);
                        modal.show();
                    } else {
                        alert('Configuration saved successfully!');
                    }
                } else {
                    alert('Error saving configuration');
                }
            }).catch(function(error) {
                alert('Error saving configuration: ' + error.message);
            });
        });
    }

    // Update SCIM endpoint URL when app origin changes
    var appOriginField = document.getElementById('app_origin');
    if (appOriginField) {
        appOriginField.addEventListener('input', function() {
            var origin = this.value.endsWith('/') ? this.value.slice(0, -1) : this.value;
            var scimEndpoint = document.getElementById('scim-endpoint');
            if (scimEndpoint) {
                scimEndpoint.textContent = origin + '/scim/v2/Users';
            }
        });
    }
});

// Global functions that need to be accessible from onclick handlers
function generateScimToken() {
    try {
        var token = 'scim_';
        
        // Try using crypto.getRandomValues if available
        if (window.crypto && window.crypto.getRandomValues) {
            var randomBytes = crypto.getRandomValues(new Uint8Array(32));
            for (var i = 0; i < randomBytes.length; i++) {
                var hex = randomBytes[i].toString(16);
                if (hex.length === 1) hex = '0' + hex;
                token += hex;
            }
        } else {
            // Fallback to Math.random() if crypto API not available
            for (var i = 0; i < 32; i++) {
                var randomByte = Math.floor(Math.random() * 256);
                var hex = randomByte.toString(16);
                if (hex.length === 1) hex = '0' + hex;
                token += hex;
            }
        }
        
        var tokenField = document.getElementById('scim_bearer_token');
        if (tokenField) {
            tokenField.value = token;
        }
        
        // Show visual feedback
        var buttons = document.getElementsByTagName('button');
        var generateButton = null;
        for (var i = 0; i < buttons.length; i++) {
            var buttonText = buttons[i].textContent || buttons[i].innerText;
            if (buttonText && buttonText.indexOf('Generate') !== -1) {
                generateButton = buttons[i];
                break;
            }
        }
        
        if (generateButton) {
            var originalText = generateButton.textContent || generateButton.innerText;
            generateButton.textContent = 'Generated!';
            generateButton.className = generateButton.className.replace('btn-outline-secondary', 'btn-success');
            
            setTimeout(function() {
                generateButton.textContent = originalText;
                generateButton.className = generateButton.className.replace('btn-success', 'btn-outline-secondary');
            }, 2000);
        }
        
    } catch (error) {
        console.error('Error generating SCIM token:', error);
        alert('Error generating token: ' + error.message);
    }
}

function resetForm() {
    if (confirm('Are you sure you want to reset all changes?')) {
        location.reload();
    }
}

// Make functions globally available
window.generateScimToken = generateScimToken;
window.resetForm = resetForm;
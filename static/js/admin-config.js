// Admin Configuration JavaScript
// Using ES5 syntax for maximum compatibility

document.addEventListener('DOMContentLoaded', function() {
    // Form submission handlers for each configuration section
    var forms = ['samlForm', 'oidcForm', 'scimForm', 'appForm'];
    
    forms.forEach(function(formId) {
        var form = document.getElementById(formId);
        if (form) {
            form.addEventListener('submit', function(e) {
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
                
                // Handle SCIM checkbox specifically for SCIM form
                if (formId === 'scimForm') {
                    var scimEnabled = document.getElementById('scim_enabled');
                    if (scimEnabled) {
                        configData['scim_enabled'] = scimEnabled.checked ? 'true' : 'false';
                    }
                }
                
                // Get form title for success message
                var formTitle = form.querySelector('.card-header h5').textContent || 'Configuration';
                
                fetch('/admin/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(configData)
                }).then(function(response) {
                    return response.json();
                }).then(function(data) {
                    if (data.status === 'success') {
                        alert(formTitle + ' saved successfully!');
                    } else {
                        alert('Error saving ' + formTitle + ': ' + (data.message || 'Unknown error'));
                    }
                }).catch(function(error) {
                    alert('Error saving ' + formTitle + ': ' + error.message);
                });
            });
        }
    });

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

// Reset form function removed - now using separate forms for each section

function importSamlMetadata() {
    var urlField = document.getElementById('saml_metadata_url');
    if (!urlField || !urlField.value.trim()) {
        alert('Please enter a SAML metadata URL');
        return;
    }
    
    var url = urlField.value.trim();
    if (!url.startsWith('https://')) {
        alert('Metadata URL must use HTTPS');
        return;
    }
    
    var button = document.querySelector('button[onclick="importSamlMetadata()"]');
    var originalText = button ? (button.textContent || button.innerText) : '';
    
    if (button) {
        button.textContent = 'Importing...';
        button.disabled = true;
    }
    
    fetch('/admin/import_saml_metadata', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({metadata_url: url})
    }).then(function(response) {
        return response.json();
    }).then(function(data) {
        if (data.success) {
            // Populate fields with imported data
            if (data.entity_id) {
                var entityIdField = document.getElementById('saml_idp_entity_id');
                if (entityIdField) entityIdField.value = data.entity_id;
            }
            if (data.sso_url) {
                var ssoUrlField = document.getElementById('saml_idp_sso_url');
                if (ssoUrlField) ssoUrlField.value = data.sso_url;
            }
            if (data.slo_url) {
                var sloUrlField = document.getElementById('saml_idp_slo_url');
                if (sloUrlField) sloUrlField.value = data.slo_url;
            }
            if (data.certificate) {
                var certField = document.getElementById('saml_idp_cert');
                if (certField) certField.value = data.certificate;
            }
            alert('SAML metadata imported successfully!');
        } else {
            alert('Error importing metadata: ' + (data.error || 'Unknown error'));
        }
    }).catch(function(error) {
        alert('Error importing metadata: ' + error.message);
    }).finally(function() {
        if (button) {
            button.textContent = originalText;
            button.disabled = false;
        }
    });
}

function importOidcDiscovery() {
    var urlField = document.getElementById('oidc_discovery_url');
    if (!urlField || !urlField.value.trim()) {
        alert('Please enter an OIDC discovery URL');
        return;
    }
    
    var url = urlField.value.trim();
    if (!url.startsWith('https://')) {
        alert('Discovery URL must use HTTPS');
        return;
    }
    
    var button = document.querySelector('button[onclick="importOidcDiscovery()"]');
    var originalText = button ? (button.textContent || button.innerText) : '';
    
    if (button) {
        button.textContent = 'Importing...';
        button.disabled = true;
    }
    
    fetch('/admin/import_oidc_discovery', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({discovery_url: url})
    }).then(function(response) {
        return response.json();
    }).then(function(data) {
        if (data.success) {
            // Extract base URL from issuer or discovery URL
            if (data.issuer) {
                var authentikUrlField = document.getElementById('oidc_authentik_url');
                if (authentikUrlField) {
                    // Extract base URL from issuer (remove /application/o/slug part)
                    var baseUrl = data.issuer.split('/application/')[0];
                    authentikUrlField.value = baseUrl;
                }
            }
            alert('OIDC discovery imported successfully! Please enter your Client ID and Client Secret.');
        } else {
            alert('Error importing discovery: ' + (data.error || 'Unknown error'));
        }
    }).catch(function(error) {
        alert('Error importing discovery: ' + error.message);
    }).finally(function() {
        if (button) {
            button.textContent = originalText;
            button.disabled = false;
        }
    });
}

// Make functions globally available
window.generateScimToken = generateScimToken;
window.importSamlMetadata = importSamlMetadata;
window.importOidcDiscovery = importOidcDiscovery;
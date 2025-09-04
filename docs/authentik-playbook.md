# Authentik Integration Playbook

This playbook provides step-by-step instructions for configuring SAML, OIDC, and SCIM authentication with Authentik for the SSO Test Application.

## Prerequisites

- Authentik server running at `https://auth.visiquate.com`
- Admin access to Authentik
- Admin access to SSO Test App at `https://sso-app.visiquate.com`
- Users that will be granted access to the application

## Overview

This guide covers three authentication methods:

1. **SAML 2.0** - Security Assertion Markup Language for SSO
2. **OIDC (OpenID Connect)** - OAuth 2.0-based authentication 
3. **SCIM 2.0** - System for Cross-domain Identity Management for user provisioning

---

## Part 1: SAML Configuration

### Step 1: Configure SAML Provider in Authentik

1. **Login to Authentik Admin**
   - Go to `https://auth.visiquate.com/if/admin/`

2. **Create SAML Provider**
   - Navigate to **Applications** → **Providers**
   - Click **"Create"**
   - Select **"SAML Provider"**

3. **SAML Provider Settings:**
   ```
   Name: SSO Test App SAML
   Authentication flow: default-authentication-flow
   Authorization flow: default-provider-authorization-explicit-consent
   
   ACS URL: https://sso-app.visiquate.com/saml/acs
   Issuer: https://auth.visiquate.com
   Service Provider Binding: Post
   Audience: https://sso-app.visiquate.com
   
   Subject mode: Based on the User's hashed ID
   Name ID Mapping: authentik default SAML Mapping: Username
   
   Property mappings: 
   ✅ authentik default SAML Mapping: User details
   ✅ authentik default SAML Mapping: Username  
   ✅ authentik default SAML Mapping: UPN
   ✅ authentik default SAML Mapping: Email
   ```

4. **Advanced Settings:**
   ```
   Signing Certificate: authentik Self-signed Certificate (or your custom cert)
   Verification Certificate: (leave empty unless needed)
   
   NameID Property Mapping: authentik default SAML Mapping: Username
   Assertion valid not before: minutes=5
   Assertion valid not on or after: minutes=5
   Session valid not on or after: minutes=86400
   
   Digest Algorithm: http://www.w3.org/2001/04/xmlenc#sha256
   Signature Algorithm: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
   ```

### Step 2: Create Application

1. **Create Application**
   - Navigate to **Applications** → **Applications**
   - Click **"Create"**

2. **Application Settings:**
   ```
   Name: SSO Test App
   Slug: sso-test-app
   Provider: SSO Test App SAML (select the provider you just created)
   
   Policy engine mode: any
   Launch URL: https://sso-app.visiquate.com/saml/login
   ```

### Step 3: Configure SSO Test App SAML Settings

1. **Login to SSO Test App Admin**
   - Go to `https://sso-app.visiquate.com`
   - Navigate to **Admin Dashboard** → **Configuration**

2. **SAML Configuration:**
   
   **Service Provider Information (already displayed):**
   - Entity ID: `https://sso-app.visiquate.com`
   - ACS URL: `https://sso-app.visiquate.com/saml/acs`
   - SLS URL: `https://sso-app.visiquate.com/saml/sls`

   **Identity Provider Settings (fill these in):**
   ```
   Authentik SSO URL: https://auth.visiquate.com/api/v3/providers/saml/[PROVIDER_ID]/sso/binding/redirect/
   Authentik SLO URL: https://auth.visiquate.com/api/v3/providers/saml/[PROVIDER_ID]/slo/binding/redirect/
   Authentik Entity ID: https://auth.visiquate.com
   ```

   **To find your Provider ID:**
   - In Authentik, go to **Applications** → **Providers** → **SSO Test App SAML**
   - Look at the URL, the number after `/providers/saml/` is your Provider ID
   - Example: If URL is `/if/admin/#/core/providers/saml/12/`, then Provider ID is `12`

3. **X.509 Certificate:**
   - In Authentik, go to **Applications** → **Providers** → **SSO Test App SAML**
   - Scroll down to **"Signing Certificate"**
   - Click on the certificate name
   - Copy the **Certificate data** (the long base64 string)
   - Paste into the **"X.509 Certificate"** field in SSO Test App

### Step 4: Test SAML Authentication

1. **Assign Users to Application**
   - In Authentik: **Applications** → **Applications** → **SSO Test App** → **Users** tab
   - Click **"Assign"** and add test users

2. **Test Login**
   - Go to `https://sso-app.visiquate.com/login`
   - Click **"Login with SAML"**
   - Should redirect to Authentik for authentication
   - After successful auth, should redirect back to SSO Test App

---

## Part 2: OIDC (OpenID Connect) Configuration

### Step 1: Create OIDC Provider in Authentik

1. **Create Provider**
   - Navigate to **Applications** → **Providers**
   - Click **"Create"**
   - Select **"OAuth2/OpenID Provider"**

2. **OIDC Provider Settings:**
   ```
   Name: SSO Test App OIDC
   Authentication flow: default-authentication-flow
   Authorization flow: default-provider-authorization-explicit-consent
   
   Client type: Confidential
   Client ID: sso-test-app-oidc (generate unique ID)
   Client Secret: (generate secure random string)
   
   Redirect URIs/Origins (CORS): https://sso-app.visiquate.com/oauth/callback/authentik
   
   Scopes: openid, email, profile
   Subject mode: Based on the User's hashed ID
   Include claims in id_token: ✅
   
   Issuer mode: Each provider has a different issuer
   ```

3. **Advanced Settings:**
   ```
   Signing Key: authentik Self-signed Certificate
   
   Access code validity: minutes=10
   Access token validity: minutes=5
   Refresh token validity: days=30
   ```

### Step 2: Create OIDC Application

1. **Create Application**
   - Navigate to **Applications** → **Applications**  
   - Click **"Create"**

2. **Application Settings:**
   ```
   Name: SSO Test App OIDC
   Slug: sso-test-app-oidc  
   Provider: SSO Test App OIDC (select the provider you just created)
   
   Launch URL: https://sso-app.visiquate.com/oauth/login/authentik
   ```

### Step 3: Configure SSO Test App OIDC Settings

1. **In SSO Test App Admin → Configuration:**

   **VisiQuate OIDC Provider Settings:**
   ```
   Authentik Server URL: https://auth.visiquate.com
   Client ID: sso-test-app-oidc (from Authentik provider)
   Client Secret: (from Authentik provider)
   Scope: openid email profile
   ```

   **Configuration URLs (auto-generated from server URL):**
   - Authorization Endpoint: `https://auth.visiquate.com/application/o/authorize/`
   - Token Endpoint: `https://auth.visiquate.com/application/o/token/`
   - UserInfo Endpoint: `https://auth.visiquate.com/application/o/userinfo/`

### Step 4: Test OIDC Authentication

1. **Assign Users**
   - In Authentik: **Applications** → **Applications** → **SSO Test App OIDC** → **Users** tab
   - Assign test users

2. **Test Login**
   - Go to `https://sso-app.visiquate.com/login`
   - Click **"Login with VisiQuate OIDC"**
   - Should redirect to Authentik for OAuth consent
   - After approval, should redirect back with user info

---

## Part 3: SCIM User Provisioning

### Step 1: Configure SCIM in SSO Test App

1. **Enable SCIM Provisioning**
   - Go to **Admin Dashboard** → **Configuration**
   - In **SCIM Configuration** section:
   - ✅ **Enable "Enable SCIM Provisioning"**
   - Click **"Generate"** to create SCIM Bearer Token
   - **Copy the token** (format: `scim_abc123...`)

2. **SCIM Endpoint Information:**
   ```
   SCIM Base URL: https://sso-app.visiquate.com/scim/v2
   Users Endpoint: https://sso-app.visiquate.com/scim/v2/Users
   Bearer Token: scim_abc123... (the generated token)
   ```

### Step 2: Create SCIM Provider in Authentik

1. **Create SCIM Provider**
   - Navigate to **Applications** → **Providers**
   - Click **"Create"**
   - Select **"SCIM Provider"**

2. **SCIM Provider Settings:**
   ```
   Name: SSO Test App SCIM
   URL: https://sso-app.visiquate.com/scim/v2
   Token: scim_abc123... (paste from SSO Test App)
   
   Exclude users service account: ✅
   Filter group: (optional - select to limit provisioned users)
   
   User Property Mappings: (use defaults)
   ✅ authentik default SCIM Mapping: User details  
   ✅ authentik default SCIM Mapping: Username
   
   Group Property Mappings: (optional, use if needed)
   ```

### Step 3: Attach SCIM to Application

**Important:** SCIM provider must be attached as a "Backchannel Provider" to your main application.

1. **Edit Your Main Application**
   - Go to **Applications** → **Applications** 
   - Edit either **"SSO Test App"** (SAML) or **"SSO Test App OIDC"**

2. **Add Backchannel Provider**
   - Look for **"Backchannel Providers"** section
   - Click **"+"** to add
   - Select **"SSO Test App SCIM"** provider
   - Save the application

### Step 4: Test SCIM Provisioning

1. **Manual Test**
   ```bash
   # Test SCIM endpoint accessibility
   curl -H "Authorization: Bearer YOUR_SCIM_TOKEN" \
        -H "Content-Type: application/json" \
        https://sso-app.visiquate.com/scim/v2/Users
   ```

2. **User Assignment Test**
   - In Authentik: **Applications** → **Applications** → **SSO Test App** → **Users**
   - **Assign a new user** to the application
   - Check SSO Test App admin panel for the newly created user

3. **Monitor Provisioning**
   - **Authentik Logs**: **Events** → **Logs** - look for SCIM events
   - **SSO App Logs**: Check application logs for SCIM requests

### Step 5: User Lifecycle Management

Once configured, SCIM will automatically:

- **CREATE** users when assigned to application
- **UPDATE** user attributes when changed in Authentik  
- **DEACTIVATE** users when unassigned from application

**User Assignment Options:**
1. **Individual Assignment**: Assign users one by one
2. **Group Assignment**: Assign entire groups to auto-provision all members
3. **Policy-Based**: Use Authentik policies for automatic assignment

---

## Troubleshooting

### SAML Issues

**Error:** "SAML Response signature validation failed"
- **Solution:** Ensure X.509 certificate is correctly copied from Authentik
- Verify Entity ID and ACS URL match exactly

**Error:** "SAML assertion expired"  
- **Solution:** Check time synchronization between servers
- Adjust assertion validity periods in Authentik provider

### OIDC Issues

**Error:** "Invalid client credentials"
- **Solution:** Verify Client ID and Client Secret match between Authentik and SSO App
- Ensure redirect URI is exactly: `https://sso-app.visiquate.com/oauth/callback/authentik`

**Error:** "Scope not allowed"
- **Solution:** Verify scopes in Authentik provider include: `openid email profile`

### SCIM Issues

**Error:** "Bearer token authentication failed"
- **Solution:** Regenerate SCIM token in SSO Test App and update in Authentik SCIM provider

**Error:** "SCIM endpoint not reachable"
- **Solution:** Verify SCIM is enabled in SSO Test App
- Check network connectivity from Authentik to SSO app
- Test endpoint manually with curl

**Error:** "User provisioning failed"  
- **Solution:** Check user property mappings in SCIM provider
- Verify required fields (email, username) are mapped correctly

### General Issues

**SSL Certificate Errors:**
- Ensure all endpoints use valid HTTPS certificates
- Authentik and SSO Test App must trust each other's certificates

**Network Connectivity:**
- Authentik must be able to reach SSO Test App for SCIM
- All redirects must use HTTPS

**Time Synchronization:**  
- Ensure system clocks are synchronized (especially important for SAML)

---

## Security Best Practices

1. **Use Strong Secrets:**
   - Generate secure random Client Secrets and SCIM Bearer Tokens
   - Rotate secrets regularly

2. **Certificate Management:**
   - Use proper SSL/TLS certificates (not self-signed in production)
   - Monitor certificate expiration dates

3. **Access Control:**
   - Use Authentik groups and policies to control application access
   - Implement least-privilege access principles

4. **Monitoring:**
   - Monitor authentication logs in both Authentik and SSO Test App
   - Set up alerts for failed authentication attempts

5. **Updates:**
   - Keep Authentik and SSO Test App updated to latest versions
   - Review security advisories regularly

---

## Configuration Summary

After completing this playbook, you will have:

✅ **SAML Authentication** - Users can login via SAML SSO  
✅ **OIDC Authentication** - Users can login via VisiQuate OIDC  
✅ **SCIM Provisioning** - Users automatically provisioned from Authentik  
✅ **User Lifecycle Management** - Create, update, deactivate users automatically  
✅ **Centralized Access Control** - Manage all access through Authentik groups and policies

The SSO Test App will support multiple authentication methods while maintaining centralized user management through Authentik.
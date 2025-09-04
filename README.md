# SSO Authentication Test Application

A comprehensive SSO authentication testing platform that allows users to test SAML, OIDC, password, and passkey authentication methods with detailed transaction data logging, group membership display, and admin oversight.

## ✨ Recent Updates

- **Dynamic Group Membership**: Display groups from SAML/OIDC authentication payloads in real-time
- **Enhanced Dashboard**: Improved user validation status with progress tracking
- **Real IP Logging**: Accurate client IP addresses behind Cloudflare tunnel
- **HTTPS Detection**: Proper SSL detection for SAML behind reverse proxies
- **Production Server**: Gunicorn WSGI server for better performance
- **Debug Endpoints**: Enhanced debugging capabilities for troubleshooting

## Features

### Authentication Methods
- **SAML 2.0**: Test SAML authentication with detailed assertion analysis and group extraction
- **OIDC (OpenID Connect)**: Test OAuth 2.0/OIDC flows with Authentik and custom providers
- **Passkey (WebAuthn)**: Passwordless authentication using FIDO2/WebAuthn

### User Experience
- **Dynamic Group Display**: Real-time group membership from authentication payloads
- **Validation Status**: Visual progress tracking for tested authentication methods
- **Account Information**: User role, membership date, and provisioning status
- **Enhanced Success Page**: Group badges and detailed transaction data

### Admin Features
- **Configuration Management**: Web interface for SAML, OIDC, SCIM, and app settings
- **Metadata Import**: Automatic SAML metadata and OIDC discovery import
- **User Oversight**: View all users and their authentication test status
- **SCIM Provisioning**: Automatic user provisioning from Authentik
- **Real-time Logs**: Detailed authentication logs with accurate IP addresses

### Developer Features
- **Transaction Analysis**: Expandable detailed view of authentication data
- **Group Membership**: Display groups from SAML attributes and OIDC claims
- **Security Analysis**: Comprehensive logging for troubleshooting
- **Debug Endpoints**: `/debug/saml-config`, `/debug/headers` for troubleshooting
- **API Endpoints**: SCIM 2.0 compliant provisioning endpoints

## Quick Start

### Development

1. **Clone and setup**:
   ```bash
   git clone <repository-url>
   cd sso-app
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Start development environment**:
   ```bash
   make dev
   ```

3. **Access the application**:
   - Open http://localhost:5000
   - Register with `brent.langston@visiquate.com` or `yuliia.lutai@visiquate.com` for admin access

### Production Deployment

The application follows VisiQuate DevOps standards with automated deployments:

1. **Push to main branch** triggers automatic build and deployment
2. **Docker images** are built and pushed to GHCR
3. **Watchtower** automatically pulls and deploys new versions
4. **Health checks** ensure successful deployment

## Configuration

### Environment Variables

Key environment variables (see `.env.example` for full list):

```bash
# Application
SECRET_KEY=your-secure-secret-key
DATABASE_URL=sqlite:///data/sso_test.db

# WebAuthn
RP_ID=sso-app.visiquate.com
ORIGIN=https://sso-app.visiquate.com

# Deployment
WATCHTOWER_TOKEN=your-watchtower-token
CLOUDFLARE_TUNNEL_TOKEN=your-tunnel-token
```

### SAML Configuration

Configure via the admin interface at `/admin/config`:
- **IdP Entity ID**: Your identity provider's entity identifier
- **IdP SSO URL**: Single sign-on endpoint  
- **IdP Certificate**: X.509 certificate from your IdP
- **SP Certificate**: Service Provider certificate (optional)
- **SP Private Key**: Private key for SP certificate (for encrypted assertions)
- **Metadata Import**: Automatic import from Authentik metadata URL

### OIDC Configuration

Configure OIDC providers:
- **Authentik URL**: Base URL of your Authentik instance
- **Discovery URL**: Full OpenID configuration URL (auto-imported)
- **Client ID**: OAuth client identifier
- **Client Secret**: OAuth client secret
- **Scopes**: `openid email profile groups` (includes group membership)

### Group Membership

Groups are automatically extracted and displayed from:
- **SAML Attributes**: `groups`, `memberOf`, `roles`, and standard claim URIs
- **OIDC Claims**: `groups`, `roles`, `authorities`, `group_membership`
- **Real-time Display**: Groups shown from current authentication session
- **No Storage**: Groups displayed dynamically, not stored in database

### SCIM Provisioning

Enable automatic user provisioning from Authentik:
1. Set `SCIM_ENABLED=true`
2. Generate secure bearer token
3. Configure Authentik with endpoint: `https://your-app.com/scim/v2/Users`

## API Endpoints

### Health Check
```
GET /health
```
Returns service health status with database and configuration checks.

### SCIM 2.0 Endpoints
- `GET /scim/v2/Users` - List users
- `POST /scim/v2/Users` - Create user
- `GET /scim/v2/Users/{id}` - Get user
- `PUT /scim/v2/Users/{id}` - Update user
- `DELETE /scim/v2/Users/{id}` - Deactivate user
- `GET /scim/v2/ServiceProviderConfig` - SCIM configuration

### Authentication Endpoints
- `GET /saml/login` - Initiate SAML authentication
- `POST /saml/acs` - SAML assertion consumer service
- `GET /oauth/{provider}` - OIDC authentication (authentik)
- `POST /webauthn/register/begin` - Start passkey registration
- `POST /webauthn/authenticate/begin` - Start passkey authentication

### Debug Endpoints
- `GET /debug/saml-config` - Check SAML configuration status (admin only)
- `GET /debug/headers` - View request headers for troubleshooting (admin only)

## Development

### Running Tests
```bash
make test
```

### Code Quality
```bash
# Format code
black .
isort .

# Lint code
flake8 .
bandit -r .

# Type checking
mypy .
```

### Database Management
```bash
# Initialize database
make init

# View logs
make logs

# Access shell
make shell
```

## Architecture

### Technology Stack
- **Backend**: Flask with SQLAlchemy, Gunicorn WSGI server
- **Database**: SQLite (production), PostgreSQL (optional)
- **Authentication**: python-saml, Authlib, WebAuthn 2.0
- **Frontend**: Bootstrap 5 with ES5-compatible JavaScript
- **Deployment**: Docker, Watchtower, Cloudflare Tunnel
- **Reverse Proxy**: Cloudflare with SSL termination

### Security Features
- **HTTPS Required**: WebAuthn requires secure context
- **CSRF Protection**: All forms protected with Flask-WTF
- **Input Validation**: Comprehensive input validation
- **Real IP Detection**: Accurate client IP logging behind proxies
- **Security Headers**: Proper security headers set
- **Group-based Access**: Dynamic group membership from IdP

### DevOps Integration
- **Multi-stage Docker builds** for optimized images
- **Automated security scanning** with Bandit, Safety, Semgrep, Trivy
- **Health checks** for container orchestration
- **Version tracking** with git commit hash and build time display
- **Cache busting** for static assets with git commit hash
- **Automatic deployments** via Watchtower (30-second polling)
- **Multi-architecture builds** (amd64, arm64)

## Contributing

1. Follow VisiQuate coding standards
2. Add tests for new features
3. Update documentation
4. Ensure security scans pass
5. Test with all authentication methods

## License

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

**SAML Authentication Errors:**
- Check `/debug/saml-config` endpoint for configuration status
- Verify SP certificate and private key are configured for encrypted assertions
- Ensure Authentik is configured with correct ACS URL (HTTPS)

**OIDC Authentication Issues:**
- Use `/debug/headers` to verify proxy headers
- Check discovery URL configuration in admin panel
- Ensure `groups` scope is included in OAuth configuration

**WebAuthn/Passkey Registration:**
- Requires HTTPS in production
- Check browser console for WebAuthn API errors
- Verify RP_ID and ORIGIN environment variables match domain

**Group Membership Not Showing:**
- Verify identity provider sends group claims in authentication response
- Check success page raw data for available attributes/claims
- Ensure OIDC scope includes `groups`

### Debug Resources
- **Admin Dashboard**: `/admin` - User and authentication log overview
- **Configuration Panel**: `/admin/config` - SAML/OIDC settings
- **Health Endpoint**: `/health` - Service health and database status
- **SAML Config Debug**: `/debug/saml-config` - SAML configuration status
- **Headers Debug**: `/debug/headers` - Request headers and proxy detection

## Support

For issues or questions:
- Check the admin dashboard for authentication logs with real IP addresses
- Review health endpoint for system status and version information
- Use debug endpoints to troubleshoot configuration issues
- Check container logs for detailed error information
- Monitor footer for current deployment version and build time
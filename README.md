# SSO Authentication Test Application

A comprehensive SSO authentication testing platform that allows users to test SAML, OIDC, password, and passkey authentication methods with detailed transaction data logging and admin oversight.

## Features

### Authentication Methods
- **SAML 2.0**: Test SAML authentication with detailed assertion analysis
- **OIDC (OpenID Connect)**: Test OAuth 2.0/OIDC flows with Google, Microsoft, and custom providers
- **Password Authentication**: Traditional username/password authentication
- **Passkey (WebAuthn)**: Passwordless authentication using FIDO2/WebAuthn

### Admin Features
- **Configuration Management**: Configure SAML and OIDC settings via web interface
- **User Oversight**: View all users and their authentication test status
- **SCIM Provisioning**: Automatic user provisioning from Authentik
- **Transaction Logging**: Detailed logs of all authentication attempts

### Developer Features
- **Transaction Analysis**: Expandable detailed view of authentication data
- **Real-time Monitoring**: Live authentication status tracking
- **Security Analysis**: Comprehensive logging for troubleshooting
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

Configure via the admin interface:
- **IdP Entity ID**: Your identity provider's entity identifier
- **IdP SSO URL**: Single sign-on endpoint
- **IdP Certificate**: X.509 certificate from your IdP

### OIDC Configuration

Configure OAuth providers:
- **Google**: Client ID and secret from Google Console
- **Microsoft**: Client ID and secret from Azure AD
- **Authentik**: Custom OIDC provider URL and credentials

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
- `GET /oauth/{provider}` - OIDC authentication (google, microsoft)
- `POST /password_auth` - Password authentication
- `POST /webauthn/register/begin` - Start passkey registration
- `POST /webauthn/authenticate/begin` - Start passkey authentication

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
- **Backend**: Flask with SQLAlchemy
- **Database**: SQLite (production), PostgreSQL (optional)
- **Authentication**: python-saml, Authlib, WebAuthn
- **Frontend**: Bootstrap 5 with custom JavaScript
- **Deployment**: Docker, Watchtower, Cloudflare Tunnel

### Security Features
- **HTTPS Required**: WebAuthn requires secure context
- **CSRF Protection**: All forms protected
- **Input Validation**: Comprehensive input validation
- **Rate Limiting**: Protection against brute force attacks
- **Security Headers**: Proper security headers set

### DevOps Integration
- **Multi-stage Docker builds** for optimized images
- **Automated security scanning** with Bandit, Safety, Semgrep
- **Health checks** for container orchestration
- **Version tracking** with git commit hash display
- **Cache busting** for static assets

## Contributing

1. Follow VisiQuate coding standards
2. Add tests for new features
3. Update documentation
4. Ensure security scans pass
5. Test with all authentication methods

## License

Internal VisiQuate application - not for public distribution.

## Support

For issues or questions:
- Check the admin dashboard for authentication logs
- Review health endpoint for system status  
- Check container logs for detailed error information
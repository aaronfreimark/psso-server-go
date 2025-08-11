# psso-server-go

Welcome to psso-server-go. It is a basic implementation of the Platform Single Sign on protocol with OIDC support for app authentication. The protocol implementation is handled by psso-pkg-go. psso-server-go implements the user and session management, groups, and web-specific calls. The package handles the cryptography, JWT, and other protocol-specific features.

## PSSO
PSSO is a feature of macOS for cloud binding. It provides a mechanism for authenticating users and devices. This server also supports standard OIDC (OpenID Connect) for app authentication, allowing apps to reuse PSSO authentication sessions.

To learn more about Platform SSO (PSSO), please visit https://twocanoes.com/sso.

## Features

- **Platform SSO (PSSO)**: Native macOS authentication support
- **OIDC/OAuth2**: Standard app authentication with JWT tokens
- **Shared Sessions**: Single sign-on between PSSO and OIDC flows
- **User Management**: Built-in user authentication with groups
- **File-based Storage**: Simple file storage for sessions, devices, and keys

## Running
psso-server-go should be able to be deployed on macOS, Windows, and Linux. PSSO requires that the service use TLS with a public SSL certificate (Let's Encrypt works fine). The basic steps are:

1. Install Go (https://golang.com) and Git (xcode-select --install on macOS) on your target platform

2. Register a DNS name and get a certificate from a well known authority. Make sure the private key and certificate are in PEM format and are not password protected. Copy the private key to /etc/psso/privkey.pem and the certificate chain to /etc/psso/fullchain.pem. The server certificate should listed first and the root certificate in the chain listed last in the fullchain.pem.
3. Clone the repo to the target machine:

	`git clone https://github.com/twocanoes/psso-server-go`
			
4. Run go mod tidy to get the required packages:
			
	`go mod tidy`

5. Run the app. The defaults assume a folder writeable by the app /var/psso. The defaults are set for macOS and Linux and should be modified as outlined in the Modifying Defaults section. Set the PSSO\_ISSUER to the hostname of the service. It must match the Issuer in the configuration profile below.

	```bash
	sudo -s
	PSSO_ISSUER=idp.example.com go run cmd/local/main.go
	```

6. If the hostname is not accessible via DNS on the client, add the hostname and the IP address to the /etc/hosts file, replacing idp.example.com with the hostname of the PSSO server.

	```bash
	sudo -s
	echo "192.168.1.100 idp.example.com" >> /etc/hosts
	```

7. On the client, verify these endpoints are accessible (replace idp.example.com with your hostname) and do not have any SSL errors:
	- https://idp.example.com/.well-known/apple-app-site-association
	- https://idp.example.com/.well-known/jwks.json
	- https://idp.example.com/.well-known/openid-configuration (OIDC Discovery)
		
8. Install Scissors test app from:

	> https://github.com/twocanoes/psso-server-go/releases

## OIDC App Authentication

For apps that need to authenticate against this PSSO server using standard OIDC:

### Discovery Endpoint
```
GET https://your-server.com/.well-known/openid-configuration
```

### App Configuration
```json
{
  "client_id": "psso-client",
  "redirect_uri": "your-app://callback",
  "response_type": "code",
  "scope": "openid profile email"
}
```

### Authentication Flow
1. **Authorization Request**: `GET /auth?client_id=psso-client&redirect_uri=...&response_type=code`
2. **Token Exchange**: `POST /oidc/token` with authorization code
3. **Token Validation**: Verify JWT using JWKS from `/.well-known/jwks.json`

The OIDC tokens will contain the same rich user information (groups, display name, email) as the PSSO authentication, enabling true single sign-on between platform and app authentication.
		
9. Create a configuration profile and SSOE app in macOS to use this service. Replace the following key/values:

* AccountDisplayName: name of the Identity Provider that will show in dialogs. For example, "My Identity Provider".
* BaseURL: The URL of the service. For example, https://idp.example.com.
* Issuer: the hostname. It must match the issuer when running. For example, idp.example.com.
 
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">~
<dict>
<key>PayloadContent</key>
<array>
	<dict>
		<key>AuthenticationMethod</key>
		<string>Password</string>
		<key>ExtensionIdentifier</key>
		<string>com.twocanoes.Scissors.ssoe</string>
		<key>PayloadDisplayName</key>
		<string>Single Sign-On Extensions Scissors</string>
		<key>PayloadIdentifier</key>
		<string>com.apple.extensiblesso.CA351D35-96B1-41CF-B25B-DF3273189AAD</string>
		<key>PayloadOrganization</key>
		<string></string>
		<key>PayloadType</key>
		<string>com.apple.extensiblesso</string>
		<key>PayloadUUID</key>
		<string>4B7148CD-1069-4140-95CE-78F61BCD9C2B</string>
		<key>PayloadVersion</key>
		<integer>1</integer>
		<key>PlatformSSO</key>
		<dict>
			<key>AccountDisplayName</key>
			<string>My Identity Provider</string>
			<key>AuthenticationMethod</key>
			<string>Password</string>
			<key>EnableAuthorization</key>
			<true/>
			<key>EnableCreateUserAtLogin</key>
			<true/>
			<key>NewUserAuthorizationMode</key>
			<string>Groups</string>
			<key>UseSharedDeviceKeys</key>
			<true/>
			<key>UserAuthorizationMode</key>
			<string>Groups</string>
		</dict>
		<key>TeamIdentifier</key>
		<string>UXP6YEHSPW</string>
		<key>Type</key>
		<string>Redirect</string>
	</dict>
	<dict>
		<key>BaseURL</key>
		<string>https://idp.example.com/</string>
		<key>Issuer</key>
		<string>idp.example.com</string>
		<key>Audience</key>
		<string>idp-audience</string>
		<key>ClientID</key>
		<string>idp-clientid</string>
		<key>PayloadDisplayName</key>
		<string>Scissors SSOE</string>
		<key>PayloadIdentifier</key>
		<string>mdscentral.00A38C42-503B-4016-A86D-2186CDA5989C.com.twocanoes.xcreds.3E7FAF27-6179-46AA-B1A3-B55E08D3273D</string>
		<key>PayloadOrganization</key>
		<string></string>
		<key>PayloadType</key>
		<string>com.twocanoes.Scissors.ssoe</string>
		<key>PayloadUUID</key>
		<string>3E7FAF27-6179-46AA-B1A3-B55E08D3273D</string>
		<key>PayloadVersion</key>
		<integer>1</integer>
	</dict>
</array>
<key>PayloadDisplayName</key>
<string>PSSO</string>
<key>PayloadIdentifier</key>
<string>mdscentral.00A38C42-503B-4016-A86D-2186CDA5989C</string>
<key>PayloadOrganization</key>
<string></string>
<key>PayloadScope</key>
<string>System</string>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadUUID</key>
<string>851A1B56-6A8A-442B-91CB-BC12FF416766</string>
<key>PayloadVersion</key>
<integer>1</integer>
</dict>
</plist>
```

## Modifying Defaults

Set up the environment variables for the service configuration:

### Core Configuration

_PSSO\_ISSUER_ Issuer (required, no default value. Usually URL to IdP like https://idp.example.com). Used for Iss in JWT. Must match the Issuer key in the config profile for the sample app "Scissors" or issuer in ASAuthorizationProviderExtensionLoginConfiguration as shown below:

> let config = ASAuthorizationProviderExtensionLoginConfiguration(clientID:clientID , issuer: *issuer*, tokenEndpointURL: tokenEndpoint, jwksEndpointURL: jwksEndpoint, audience: audience)

_PSSO\_AUDIENCE_ (psso): Audience. Used for Aud in JWT.

_PSSO\_ADDRESS_ (:443): Network address and port to listen on.

### SSL/TLS Configuration

_PSSO\_TLSPRIVATEKEYPATH_ (/etc/psso/privkey.pem): Path to TLS private key in PEM format.

_PSSO\_TLSCERTIFICATECHAINPATH_ (/etc/psso/fullchain.pem): Path to TLS certificate chain in PEM format.

### File Storage Paths

_PSSO\_JWKSFILEPATH_ (/var/psso/jwks.json): Path to JSON file where the service keys will be created and stored.

_PSSO\_DEVICEFILEPATH_ (/var/psso/devices): Path to folder where device registration files are stored.

_PSSO\_KEYPATH_ (/var/psso/keys): Path to folder where device keys are stored for lookup by key ID.

_PSSO\_NONCEPATH_ (/var/psso/nonce): Path to folder where nonce files are stored.

_PSSO\_SESSIONPATH_ (/var/psso/sessions): Path to folder where user session files are stored.

_PSSO\_AUTHCODEPATH_ (/var/psso/authcodes): Path to folder where OIDC authorization codes are stored.

### HTTP Endpoints

_PSSO\_ENDPOINTNONCE_ (/nonce): HTTP endpoint where the client requests a nonce.

_PSSO\_ENDPOINTREGISTER_ (/register): HTTP endpoint where client registers a new device.

_PSSO\_ENDPOINTTOKEN_ (/token): HTTP endpoint where client posts JWT tokens for PSSO authentication.

_PSSO\_ENDPOINTJWKS_ (/.well-known/jwks.json): HTTP endpoint for advertising the public key for the service.

### OIDC Configuration

_OIDC\_DISCOVERY_ (/.well-known/openid-configuration): OIDC discovery endpoint.

_OIDC\_AUTH_ (/auth): OIDC authorization endpoint.

_OIDC\_TOKEN_ (/oidc/token): OIDC token endpoint.

_OIDC\_CLIENT\_ID_ (psso-client): Default OIDC client ID.

_OIDC\_REDIRECT\_URI_ (""): Default OIDC redirect URI (configure as needed).

## Built-in Users

The server includes these test users for development:

- **jappleseed@twocanoes.com** (no password required)
  - Groups: admin, net-admin, software-install
- **liz@twocanoes.com** (password: twocanoes)
  - Groups: software-install, psso-standard-users
- **nate@twocanoes.com** (password: twocanoes)  
  - Groups: software-install, psso-standard-users
- **aaron.freimark** (password: ArloPuppy0)
  - Groups: software-install, psso-standard-users

## Session Management

The server maintains user sessions that can be shared between PSSO and OIDC authentication flows:

- **PSSO Authentication**: Creates a 24-hour session when users authenticate via Platform SSO
- **OIDC Authentication**: Can reuse existing PSSO sessions for seamless app authentication
- **Session Storage**: File-based session storage in `/var/psso/sessions/`
- **Session ID**: Passed as refresh token in PSSO responses and used for OIDC token generation


## Thanks
Thanks to Joel Rennich for his deep dive into figuring out the details of PSSO and providing guidance on how this all works.
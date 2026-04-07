# Header-Based Authorization in dotCMS

This plugin demonstrates how to implement **header-based authorization** in dotCMS using the trusted proxy pattern. In this case, we are using [StrongDM](https://www.strongdm.com/) as the proxy, but the pattern applies to any system that can sit in front of dotCMS and inject a trusted token into request headers (e.g. Cloudflare Access, AWS ALB, Nginx, Istio).

## How It Works

The core idea is a **trusted proxy pattern**:

1. A proxy (StrongDM) authenticates the user externally
2. The proxy injects a signed JWT into a request header (`x-sdm-token`) before forwarding to dotCMS
3. dotCMS intercepts the request, validates the token against StrongDM's API, and extracts user identity from the JWT payload
4. If valid, dotCMS automatically creates the user (if they don't exist) and logs them in

This means users never touch dotCMS's login form — authentication is handled entirely by the proxy. 


```
User → StrongDM (authenticates, injects x-sdm-token header) → dotCMS
                                                                  ↓
                                              Validate token with StrongDM API
                                                                  ↓
                                              Create user if not exists + log in
```

This is what it could look like with an OAuth provider:

<img width="1037" height="433" alt="image" src="https://github.com/user-attachments/assets/4a19cdde-7d8c-493a-a33a-81374325552c" />






## Implementation

### WebInterceptor

`StrongDMInterceptor` implements dotCMS's `WebInterceptor` interface and runs on all backend URLs. On each request it:

1. Skips if a user session already exists
2. Reads the `x-sdm-token` header
3. Validates the token against `https://api.strongdm.com/v1/control-panel/http/verify`
4. Decodes the JWT payload to extract `email`, `firstName`, `lastName`
5. Creates or activates the dotCMS user, grants CMS Admin + Backend roles, and logs them in via cookie

### User Provisioning

On first login, dotCMS automatically:
- Creates a user account from the JWT claims (email, first/last name)
- Sets a random password (the user will always authenticate via the proxy, never by password)
- Grants `CMS Admin` and `Backend User` roles
- Grants access to all layouts/portlets

On subsequent logins, the user is looked up by email and logged in directly. If the account was deactivated, it is re-activated.

### XSS Prevention

A second interceptor, `StrongDMXSSPreventionWebInterceptor`, wraps dotCMS's built-in `XSSPreventionWebInterceptor`. On the initial redirect after login, the `sDMToken` is passed as a URL parameter so the frontend can store it in a cookie. This interceptor validates that token and bypasses the referer check for that one request, then delegates all other requests to the standard XSS interceptor.

### Adapting to a Different Proxy

To use a different trusted proxy, replace `StrongDmUtils.validateAndParseToken()` with your own validation logic:

- **Cloudflare Access / AWS ALB**: Validate the JWT signature using the provider's public key (no external API call needed)
- **Internal SSO proxy**: Validate a shared secret or HMAC signature
- **mTLS proxy**: Trust based on client certificate rather than a header token

The user provisioning logic in `StrongDmUtils.validateUser()` is proxy-agnostic and can be reused as-is.

## Installation

1. Build the OSGi bundle:
   ```bash
   mvn clean package
   ```
2. Deploy the resulting JAR from `target/` into your dotCMS `dynamic-plugins` directory, or upload it via the dotCMS Plugin Manager at **Admin → Plugins**.

3. The plugin registers itself automatically on startup — no additional configuration is required.

> **Note:** The plugin sets `PREVENT_SESSION_FIXATION_ON_LOGIN=false` at startup. This is required because the proxy controls the session lifecycle; dotCMS must not invalidate the session on login.

## Security Considerations

- **Trust the proxy, not the header.** This plugin is only secure when the `x-sdm-token` header cannot be injected by end users. Ensure your network topology prevents direct access to dotCMS without going through StrongDM.
- **Every authenticated StrongDM user receives CMS Admin access.** StrongDM is designed for infrastructure and database access management, so this is intentional — only engineers with StrongDM access will reach this login path.
- **Token validation is performed against StrongDM's external API** on every unauthenticated request. A 5-second circuit-breaker timeout is in place. If the StrongDM API is unreachable, unauthenticated requests will receive a `401`.

## Requirements

- dotCMS 26.x or later
- Java 11+
- Maven 3.6+

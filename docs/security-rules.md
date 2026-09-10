# Security Heuristic Rules

WireSniffer evaluates decoded traffic against security rules to catch sensitive data exposure during local development and testing.

## Rule Summary

| Rule ID | Severity | Description | Category |
| --- | --- | --- | --- |
| `PLAINTEXT_BASIC_AUTH` | CRITICAL | Unencrypted Basic Auth credentials in headers | Authentication |
| `PLAINTEXT_BEARER_TOKEN` | HIGH | Bearer token transmitted over cleartext HTTP | Authentication |
| `CREDENTIAL_LEAK_OPENAI` | CRITICAL | OpenAI secret API key (`sk-...`) in payload or header | Secrets |
| `CREDENTIAL_LEAK_GITHUB` | CRITICAL | GitHub token (`ghp_`, `gho_`, `github_pat_`) in traffic | Secrets |
| `CREDENTIAL_LEAK_AWS` | CRITICAL | AWS Access Key ID (`AKIA...`) or secret key | Secrets |
| `CREDENTIAL_LEAK_STRIPE` | CRITICAL | Live Stripe API key (`sk_live_...`) | Secrets |
| `CREDENTIAL_LEAK_SLACK` | HIGH | Slack bot token (`xoxb-`, `xoxp-`) | Secrets |
| `CREDENTIAL_LEAK_DATABASE` | CRITICAL | Database URI with plaintext password (`postgres://user:pass@host`) | Secrets |
| `PRIVATE_KEY_EXPOSURE` | CRITICAL | RSA, EC, or OpenSSH private key block in payload | Secrets |
| `PII_CREDIT_CARD` | HIGH | Valid credit card number passing Luhn checksum | Data Privacy |
| `PII_SSN` | HIGH | Unmasked US Social Security Number | Data Privacy |
| `EXPIRED_JWT` | MEDIUM | Decoded JWT with `exp` timestamp in the past | Token Security |
| `INSECURE_JWT_ALG_NONE` | HIGH | JWT header specifies `"alg": "none"` | Token Security |
| `SENSITIVE_JWT_PAYLOAD` | MEDIUM | JWT claims contain passwords, secrets, or SSN fields | Token Security |
| `STACK_TRACE_EXPOSURE` | MEDIUM | Detailed backend traceback or error dump | Information Leak |
| `SQL_ERROR_EXPOSURE` | MEDIUM | Raw database query syntax error returned in response | Information Leak |
| `INSECURE_CORS_WILDCARD` | LOW | `Access-Control-Allow-Origin: *` with credentials enabled | Configuration |
| `GRAPHQL_INTROSPECTION_ENABLED` | MEDIUM | Introspection returns full internal GraphQL schema | GraphQL Security |
| `GRAPHQL_FIELD_SUGGESTIONS` | LOW | Server suggests unpublished field names on error | GraphQL Security |

## Detailed Rule Explanations

### 1. Plaintext Authentication
Transmitting authentication headers over cleartext HTTP exposes credentials to network observers.
- `PLAINTEXT_BASIC_AUTH`: Decodes the Base64 value in `Authorization: Basic ...` to reveal `username:password`.
- `PLAINTEXT_BEARER_TOKEN`: Flags `Authorization: Bearer <token>` when transmitted over an unencrypted TCP port.

### 2. High-Entropy Credential Detection
Scans HTTP request headers, query strings, and request/response bodies for API token patterns:
- OpenAI Keys: Matches regex `sk-[a-zA-Z0-9]{20,}`.
- GitHub Tokens: Matches classic tokens (`ghp_[a-zA-Z0-9]{36}`) and fine-grained PATs (`github_pat_[a-zA-Z0-9_]{82}`).
- AWS Credentials: Matches 20-character AWS Access Key IDs beginning with `AKIA` or `ASIA`.
- Database Connection Strings: Matches URIs containing user credentials (e.g. `mysql://root:password@localhost:3306/prod`).

### 3. Payment and Personal Information (PII)
- Credit Card Validation: Matches 13-19 digit candidate numbers formatted as Visa, Mastercard, American Express, or Discover. Each candidate is tested with the Luhn checksum algorithm to eliminate random numeric strings.
- Social Security Numbers: Matches standard SSN formats (`XXX-XX-XXXX`) in request and response bodies.

### 4. JWT Analysis
Parses JSON Web Tokens (`eyJ...`) without requiring signature keys:
- Checks the `exp` claim against current Unix time.
- Inspects the JOSE header: flags `"alg": "none"` or symmetric `"alg": "HS256"` configured with common default passwords.
- Inspects claim keys: flags presence of `password`, `secret`, `ssn`, or `pin`.

### 5. Information Exposure
- Identifies stack traces from Python (`Traceback (most recent call last)`), Java/Spring Boot (`org.springframework.web...`), and PHP (`Fatal error:`).
- Identifies database errors disclosing query structure (PostgreSQL syntax errors, MySQL error codes).

### 6. GraphQL Security
- Introspection Checks: Verifies if `__schema` and `__type` queries succeed in returning the full schema. Disabling introspection in production prevents reconnaissance of unreleased or internal administrative models.
- Field Suggestions: Detects "Did you mean ...?" hints in GraphQL error payloads that disclose internal field naming conventions.

### 7. Custom Organizational Rules (.wiresniffer.yaml)
Teams can enforce internal API policies by placing a `.wiresniffer.yaml` file in their repository root:

```yaml
rules:
  - id: REQ_CORRELATION_ID
    title: Missing X-Correlation-ID Header
    severity: HIGH
    description: Internal services must supply a correlation ID header.
    target: request_headers
    missing_header: X-Correlation-ID

  - id: NO_SERVER_TOKENS
    title: Server Header Disclosing Version
    severity: LOW
    description: Production gateways must strip internal server tokens.
    target: response_headers
    forbidden_header: Server
```


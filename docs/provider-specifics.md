# Provider-Specific Webhook Requirements and Quirks

This document outlines the specific requirements, quirks, and implementation details for each webhook provider supported by the Unified Webhook Router.

## Stripe

### Signature Verification
- **Header**: `stripe-signature`
- **Algorithm**: HMAC-SHA256
- **Format**: `t=timestamp,v1=signature1,v1=signature2,...`
- **Timestamp Validation**: Default 5-minute tolerance (configurable)

### Configuration
```javascript
{
  stripe: {
    signingSecret: 'whsec_...', // Webhook endpoint signing secret
    tolerance: 300 // Optional: timestamp tolerance in seconds (default: 300)
  }
}
```

### Quirks
- Stripe sends multiple signatures in a single header for key rotation
- The signature is computed over `timestamp.raw_body`
- Timestamp validation prevents replay attacks
- All event types are extracted from the `type` field in the payload

### Common Event Types
- `payment_intent.succeeded`
- `payment_intent.failed`
- `customer.created`
- `customer.subscription.created`
- `charge.succeeded`

## GitHub

### Signature Verification
- **Header**: `x-hub-signature-256` (SHA256) or `x-hub-signature` (SHA1)
- **Algorithm**: HMAC-SHA256 or HMAC-SHA1
- **Format**: `sha256=signature` or `sha1=signature`

### Configuration
```javascript
{
  github: {
    secret: 'your_webhook_secret',
    algorithm: 'sha256' // Optional: 'sha1' or 'sha256' (default: 'sha256')
  }
}
```

### Quirks
- GitHub prefixes the signature with the algorithm name
- Event type is sent in the `x-github-event` header, not in the payload
- Delivery ID is in `x-github-delivery` header
- Some events have action subtypes (e.g., `pull_request.opened`)

### Common Event Types
- `push`
- `pull_request`
- `issues`
- `release`
- `workflow_run`

## Slack

### Signature Verification
- **Header**: `x-slack-signature`
- **Algorithm**: HMAC-SHA256
- **Format**: `v0=signature`
- **Timestamp Header**: `x-slack-request-timestamp`
- **Timestamp Validation**: Default 5-minute tolerance

### Configuration
```javascript
{
  slack: {
    signingSecret: 'your_signing_secret',
    tolerance: 300 // Optional: timestamp tolerance in seconds
  }
}
```

### Quirks
- **URL Verification**: Slack sends a special `url_verification` challenge that must be echoed back
- The signature is computed over `v0:timestamp:raw_body`
- Event types can be nested under `event.type` for Events API
- Different payload structures for slash commands, interactive components, and events

### Common Event Types
- `url_verification` (special case)
- `message`
- `app_mention`
- `team_join`
- `channel_created`

### URL Verification Example
```javascript
// Automatically handled by the router
{
  "type": "url_verification",
  "challenge": "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"
}
```

## Twilio

### Signature Verification
- **Header**: `x-twilio-signature`
- **Algorithm**: HMAC-SHA1 with Base64 encoding
- **Special Requirement**: Signature includes the full webhook URL

### Configuration
```javascript
{
  twilio: {
    authToken: 'your_auth_token',
    webhookUrl: 'https://your-domain.com/webhooks' // Optional: for validation
  }
}
```

### Quirks
- **URL Dependency**: The signature is computed over the full URL including query parameters
- Form-encoded payloads (not JSON)
- The signature algorithm is:
  1. Sort all POST parameters alphabetically
  2. Concatenate parameter names and values
  3. Append the full URL
  4. Compute HMAC-SHA1 with auth token
  5. Base64 encode the result

### Common Event Types
- SMS status callbacks (`MessageStatus`)
- Voice call status (`CallStatus`)
- Recording status (`RecordingStatus`)

## Square

### Signature Verification
- **Header**: `x-square-hmacsha256-signature`
- **Algorithm**: HMAC-SHA256 with Base64 encoding
- **Format**: Base64-encoded signature

### Configuration
```javascript
{
  square: {
    signatureKey: 'your_signature_key',
    notificationUrl: 'https://your-domain.com/webhooks/square' // Required for validation
  }
}
```

### Quirks
- The signature is computed over `notification_url + raw_body`
- The notification URL must exactly match what's configured in Square
- Event types are in the `type` field
- All payloads are JSON

### Common Event Types
- `payment.created`
- `payment.updated`
- `refund.created`
- `customer.created`
- `order.updated`

## General Implementation Notes

### Error Handling
- All providers return specific error messages for common failures
- Invalid signatures return 403 Forbidden
- Unknown providers return 400 Bad Request
- Handler errors return 500 Internal Server Error

### Best Practices
1. **Always verify signatures** in production
2. **Use timestamp validation** where available to prevent replay attacks
3. **Log webhook events** for debugging and audit trails
4. **Implement idempotency** in your handlers
5. **Return quickly** - process webhooks asynchronously when possible

### Testing Webhooks
Each provider typically offers tools for testing:
- **Stripe**: Stripe CLI for local testing
- **GitHub**: Webhook delivery history in repository settings
- **Slack**: Events API tester in app settings
- **Twilio**: Test credentials and phone numbers
- **Square**: Sandbox environment

### Security Considerations
1. **Keep secrets secure** - use environment variables
2. **Validate timestamps** to prevent replay attacks
3. **Use HTTPS only** for webhook endpoints
4. **Implement rate limiting** to prevent abuse
5. **Log security events** for monitoring

### Framework Integration Examples

#### Express.js
```javascript
app.post('/webhooks', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const result = await router.handle(req, res);
    // Response is handled by the router
  } catch (error) {
    res.status(400).send(error.message);
  }
});
```

#### Python Flask
```python
@app.route('/webhooks', methods=['POST'])
async def webhook():
    try:
        result = await router.handle_request(request)
        if result:
            return jsonify(result)
        return '', 200
    except InvalidWebhookError as e:
        return str(e), 400
```
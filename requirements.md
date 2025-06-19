Perfect, I’ll draft a comprehensive, technical PRD for the Unified Webhook Router that supports both TypeScript/Node.js and Python, includes built-in support for Stripe, GitHub, Slack, Square, and other common providers, is framework-agnostic, serverless-compatible, and allows for user-defined extensions.

I’ll get started and let you know once the document is ready for review.

# Unified Webhook Router – Product Requirements Document (PRD)

## Introduction and Overview

**Unified Webhook Router** is a developer library designed to handle inbound webhooks from various third-party services (e.g. Stripe, GitHub, Slack, Twilio, Square, etc.) in a unified and secure manner. Modern SaaS applications often rely on numerous external services that deliver event notifications via webhooks. Each service has its own HTTP payload format, unique authentication/signature method, and endpoint requirements. This project aims to provide a single, cohesive solution – a “mini framework” – to manage these webhooks consistently across providers, reducing boilerplate code and security risks for development teams.

**Target Users:** This library is targeted at software developers (especially in startups or small teams) who need to integrate multiple webhook providers into their applications. It will have implementations in both TypeScript (Node.js) and Python, making it accessible in the two most common backend stacks. The solution will be framework-agnostic and serverless-friendly, meaning it can be used in diverse environments (Express or Flask apps, Next.js API routes, AWS Lambda, Vercel Functions, etc.) with minimal setup.

## Problem Statement – Pain Points

Integrating incoming webhooks from external services is tedious and error-prone due to inconsistent patterns across providers. Key pain points include:

- **Duplicate Effort & Boilerplate:** Each provider (Stripe, GitHub, Slack, etc.) has different webhook payload schemas, HTTP headers, and signature algorithms. Developers often write separate endpoint handlers for each service, duplicating a lot of similar code (parsing JSON, verifying signatures). This redundant code increases maintenance effort and the chance of bugs.

- **Complex Security Verification:** Verifying that a webhook request is genuine (untampered and actually from the provider) is critical. Every provider has its own method for signing requests (HMAC signatures with secrets, tokens, etc.). Implementing and **correctly** coding these verification steps for each service is tricky. Mistakes can lead to security vulnerabilities, such as accepting forged or replayed requests. For example, if a team forgets to properly validate a signature or timestamp, a malicious actor could spoof a webhook and compromise the system.

- **Inconsistent Data Formats:** The JSON (or form) payloads differ widely. A payment success event from Stripe looks nothing like a GitHub push event or a Slack command event. Handling these requires writing custom parsing logic for each, and mapping them to internal models or types. This adds cognitive load and potential for errors when interpreting the data.

- **Scattered Documentation & Learning Curve:** Developers must constantly refer to multiple external docs (Stripe’s docs for stripe-signature header, Slack’s docs for signing secrets, etc.) and learn each service’s quirks. This slows down integration. It’s especially painful for small teams who want to quickly support new webhooks but don’t have time to deeply learn every API’s nuances.

- **Lack of a Unified Solution:** There isn’t a popular, go-to library that abstracts webhook handling across many providers. Typically one might use each provider’s official SDK or copy-paste code from docs, resulting in a mix of approaches. Existing solutions (like individual SDK helpers or manual implementations) are siloed per service and cannot be easily reused for another service’s webhooks. This fragmentation means no single source of truth for webhook handling, and inconsistent quality (some endpoints might be less secure if implemented hastily). In short, developers today either roll their own handlers from scratch or use disparate tools, which is inefficient and error-prone.

## Why Existing Solutions Are Lacking

While some providers offer SDKs or example code for their webhooks, there is a gap when it comes to a unified approach:

- **Provider SDK Limitations:** Using each provider’s SDK just for webhook handling means installing multiple libraries (Stripe, Twilio, etc.), increasing bloat. Each SDK has a different API style, and some may be heavy if you only need the webhook part. There’s no cohesion – developers must juggle different conventions. Moreover, not all providers even have official libraries for every language (or the SDK might not cover webhook verification thoroughly).

- **Homegrown Implementations:** Many teams implement webhook endpoints manually by following providers’ documentation. This often leads to **duplicated code** across projects for similar tasks (e.g., computing an HMAC signature) and can introduce subtle bugs. For example, calculating an HMAC requires using the exact raw request body and secret; a mistake like using a parsed body or the wrong encoding will break verification. Without a standard library, each team risks “getting it wrong” in their custom code.

- **Security Mistakes:** It’s easy to make mistakes in verification logic. A number of incidents and Stack Overflow questions show developers struggling with signature verification or missing the step to check timestamps for replay attacks. If each webhook integration is custom, there’s a higher chance of a missed security step (e.g., not validating the GitHub secret correctly, or forgetting to enforce Stripe’s 5-minute tolerance on timestamps). No widely-used unified library means no centralized best-practice enforcement.

- **No Unified Abstraction:** Currently, developers don’t have a single interface to handle webhooks from multiple sources in one place. You either set up separate HTTP routes for each service or write a big conditional in one endpoint. In both cases, the logic diverges per provider. There’s a lack of **abstraction** where you could, for instance, register handlers for events in a consistent way and let a framework take care of the rest. This fragmentation also makes it harder to add new webhook integrations quickly – you essentially start from scratch for each new service.

- **Third-Party Services (Optional):** There are SaaS products (e.g., Hookdeck, Svix) that help manage webhooks externally, but adopting them means adding an external dependency and possibly cost. They are not libraries but hosted solutions where webhooks get routed. Many small startups prefer an in-app solution for simplicity and cost reasons. Therefore, a gap remains for an open-source, in-app library that unifies webhook handling.

In summary, existing approaches either silo the problem (one-off solutions per provider) or require adopting external systems. This PRD addresses the need for an in-house library that standardizes how developers receive and process webhooks across the board.

## Proposed Solution: Unified Webhook Router

The **Unified Webhook Router** will solve these issues by offering a single, configurable package that handles inbound webhooks uniformly. At its core, the library will function as an **HTTP request router and validator** specialized for webhooks. Key aspects of the concept include:

- **One Router for All Providers:** Developers will be able to define a single webhook endpoint (or a small number of endpoints) that is backed by this router. The router will inspect incoming requests, **identify which provider/service they belong to** (based on headers or payload signatures), **verify the authenticity** (signature or token validation using the proper method for that provider), and then **route the request to the appropriate handler function** that the developer registered for that specific event type or provider.

- **Unified API for Handling Events:** The library provides a consistent way to register webhook handlers. For example, a developer might register something like: `router.on('stripe', 'payment_intent.succeeded', handleStripePayment)` or `router.on('github', 'push', handleGitPush)`. This could also support wildcard or default handlers (e.g. handle any Stripe event if needed). The idea is to abstract away the raw HTTP details – the developer just declares what to do when a certain event arrives, and the router ensures that it only gets called when a genuine event of that type arrives, no matter the differences in upstream formats.

- **Built-in Verification & Security Best Practices:** For each supported provider, Unified Webhook Router will implement the recommended verification mechanism out-of-the-box. This includes HMAC signature checking, secret token matching, and timestamp validation as applicable:

  - **Signature Verification:** The library will compute and compare cryptographic signatures for services like Stripe (which uses a secret key and SHA-256 HMAC with a signed payload string), Slack (which uses a signing secret and a base string of `v0:timestamp:body` with HMAC SHA-256), GitHub (HMAC SHA-1/256 with a secret), Square (HMAC-SHA256 of body+URL, etc.), Twilio (HMAC-SHA1 of URL & params), and others. These checks will be done **before invoking any handler**, so unverified requests are rejected by the library. This dramatically reduces the likelihood of a forged request doing anything in the system. For example, Square’s docs emphasize that any request failing validation must be discarded – our library will enforce that automatically.

  - **Replay Attack Prevention:** Many providers include a timestamp in their signature scheme (e.g., Slack’s `X-Slack-Request-Timestamp` and Stripe’s `t=` field in `Stripe-Signature`). The router will by default check that the timestamp is recent (within an allowed tolerance window, typically 5 minutes) and reject old requests to prevent replay attacks. This follows best practices (Stripe’s official libraries use a 5 minute default tolerance as well). The tolerance (time window) will be configurable but with a secure default.

  - **Secure Comparison and Handling:** All secret comparisons and signature checks will use constant-time comparison to avoid timing attacks (as noted in Square’s security guidelines). The library will handle character encoding issues (by using raw request bytes for hashing, per provider requirements) so developers don’t accidentally introduce vulnerabilities by using, say, a parsed body when verifying a signature. In short, **security is baked in**: developers get robust verification without having to implement it themselves.

- **Normalized Event Data:** Upon successful verification, the library will parse and normalize the webhook payload into a standardized object (or class/TypeScript type). The goal is to present the incoming data in a developer-friendly way:

  - Each event handler will receive a structured object that includes:

    - The `provider` (e.g. `"stripe"` or `"github"`) and perhaps the specific `eventType` (e.g. `"payment_intent.succeeded"` or `"push"`).
    - A **normalized payload** field that is the essential data of the event. For example, for a Stripe payment succeeded event, the handler might get an object with a unified shape (perhaps similar to Stripe’s own Event object structure) rather than raw JSON text. For a GitHub push, it might provide a parsed object with repository info, commit list, etc., according to GitHub’s JSON schema.
    - Optionally, the original raw payload and headers could be accessible if needed (for advanced use).

  - The normalization will not force unrelated webhooks into one schema (each provider’s data is inherently different), but it will ensure that within each provider we present a consistent, typed structure. If using TypeScript, the library will include Type Definitions or interfaces for the common events (e.g., a TypeScript type for `StripePaymentSucceededEvent` payload). This gives developers compile-time checking and IntelliSense when working with event data, making integration less error-prone.

- **Routing to Handler Functions:** The router will maintain an internal mapping of registered handlers. Developers register handlers for specific events or providers, and the library takes care of calling the correct one when an incoming webhook matches. The routing can be configured by:

  - **Provider and Event Type:** e.g., Stripe’s `"checkout.session.completed"` vs `"invoice.paid"` can have different handlers. The router might allow registering by exact event name strings as provided by the service. In cases where providers have many types, we could allow wildcard patterns or a default catch-all for a provider.
  - **Single Endpoint vs Multiple Endpoints:** The library will support both modes:

    - _Unified Endpoint:_ All providers’ webhooks could be sent to one HTTP endpoint (e.g. `/webhooks`) and the router will discern the provider internally (based on headers like `Stripe-Signature` vs `X-GitHub-Event` etc.). This simplifies external configuration (you could point all webhook sources to one URL).
    - _Separate Endpoints (optional):_ If developers prefer separate endpoints per provider (for organizational or permissions reasons), they can still use one router instance or multiple – e.g., instantiate separate sub-routers for each provider or configure the main router to only accept certain providers on certain path prefixes. The design will be flexible but emphasize ease of having a unified pipeline.

  - The router will handle errors and edge cases: if no handler is registered for a given event, it can either ignore it or call a fallback handler (configurable behavior). This ensures that unexpected event types don’t crash the application – they can be safely logged or ignored.

- **Extensibility:** While the library will come with out-of-the-box support for many common webhook providers, it’s impossible to cover everything. Therefore, a core feature is an **easy way to add new providers** or customize existing ones:

  - We will define a clear interface (or abstract class) for a “Webhook Provider Module”. This could include methods or configurations like: how to identify the provider (e.g., look for a specific HTTP header or request path), how to verify the signature (e.g., HMAC with these inputs, or a public key check, etc.), and how to parse the payload into a normalized object.
  - Developers can register a new provider by supplying this information. For instance, if a new service “FooService” uses a secret token in a header `X-Foo-Token`, a developer could plug that into the router by providing a small config (the header name and expected secret value or verification callback). The router would then handle “FooService” webhooks as well. We’ll make sure this extension process is well-documented and only a few lines of code, encouraging open-source contributions for more providers.
  - The library might also allow overriding aspects of existing providers’ logic if necessary (for example, if a provider changes their scheme or if a user has a custom variant).
  - Extensibility ensures the product remains useful as new services emerge or if a project has niche webhooks not initially supported.

- **Framework Agnostic Design:** Unified Webhook Router will not be tied to a specific web framework, making it flexible to use in different setups:

  - **Node/TypeScript:** It will not assume Express or any particular HTTP server. Instead, it might expose a function like `router.handleRequest(req, res)` that can be used inside an Express route handler, a Next.js API route, a Fastify or Koa context, etc. We will document how to extract the raw body and headers in various frameworks (since raw body is needed for signature verification) – or possibly provide small middleware helpers. For example, in an Express app you might do:

    ```ts
    app.post("/webhooks", express.raw({ type: "*/*" }), (req, res) => {
      router.handle(req, res);
    });
    ```

    In a Next.js API route (which provides `req` as a Node.js IncomingMessage), you could similarly call the router. The library will focus on pure functions or minimal wrapper so that it can integrate with any Node HTTP scenario. It will also be compatible with serverless function signatures (which are often just `(event, context) => result` and have a similar request shape).

  - **Python:** Similarly, the Python version will avoid assuming Flask vs Django, etc. We may provide an interface like `router.handle(request)` that returns a response or raises an HTTP exception. For Flask, a developer might do in a route: `response = router.handle(request)` and return that. In FastAPI (ASGI), you might use a dependency or a custom endpoint calling the router. We will ensure the library can work with WSGI/ASGI by providing utilities or documentation. It could also be used in an AWS Lambda (Python) via the AWS Gateway payload.
  - By being framework agnostic, the library can also be used in microframeworks or even in testing harnesses easily. We will not hard-require any heavy framework-specific dependency; instead we rely on standard library or lightweight utilities for things like HTTP header parsing or cryptography.

- **Serverless Compatibility:** A special consideration is that many teams deploy webhook handlers on serverless platforms (AWS Lambda, Google Cloud Functions, Vercel, etc.). The Unified Webhook Router will be designed to run efficiently in such environments:

  - **Stateless and Lightweight:** The library will not assume any persistent state (no in-memory cache or global that carries over requests, aside from configuration). Each invocation can cleanly verify and route using just the input. This is crucial for serverless, where each request may run in a fresh context.
  - **Cold Start Friendly:** We will minimize package size and initialization overhead. Using built-in crypto libraries or small fast libraries ensures that even in a cold start, the performance is acceptable. We’ll avoid large dependencies. The library should load quickly so that webhook endpoints don’t suffer extra latency.
  - **AWS Lambda Integration:** We will document how to use the library with AWS Lambda (for Node, you might use an API Gateway proxy integration and pass the event body/headers to the router; for Python, similarly). Possibly, we might provide convenience wrappers, like a handler function that can serve as the Lambda entrypoint.
  - **Vercel / Next.js:** On Vercel, where Next.js API routes run, the library will work as it would in Node, ensuring that the body parsing is handled correctly (Next’s default might parse JSON – we’ll document how to get raw body in Next for Stripe, etc., or provide an option to supply the raw bytes). Ensuring it works in this environment means many frontend-framework users (Next.js, etc.) can adopt it easily.
  - **Other Environments:** Similarly ensure compatibility with Azure Functions, GCP Functions, Cloudflare Workers (if possible – though CF Workers use a Service Worker model in JS, but perhaps the TS library could be adapted if it doesn’t use Node-specific APIs heavily; this can be explored as a stretch goal).
  - The outcome is a library that _naturally fits the serverless paradigm_, allowing early-stage apps to deploy secure webhook endpoints on scalable infrastructure without custom code.

- **Developer Experience and Best Practices by Default:** This library is not just about code reuse; it also implicitly enforces best practices:

  - **Secure by Default:** As discussed, it automatically does things that developers might forget (signature check, timestamp check, constant-time comparisons, using correct raw payload) so that even a rushed integration remains secure. For example, the Slack verification requires checking the timestamp and signature with a specific formula – our library will handle that; if the check fails or timestamp is too old, the request will be rejected (e.g., not routed to any handler, and an appropriate HTTP 403 or 400 response can be returned). The developer doesn’t have to remember these steps – they get it by default.
  - **Error Handling:** The library will include robust error handling around the webhook processing. If a signature is invalid or required fields are missing, it can automatically return an HTTP 400/401/403 response (or throw an exception in Python) indicating a bad request, which the framework or calling code can use to respond. This prevents the application from accidentally processing malformed or unauthorized data. Likewise, inside a handler, if the developer code throws an exception, the library could catch it and perhaps log it (and return a generic 500 response to the provider to trigger a retry, or allow it to bubble depending on configuration). We will provide sensible defaults so that one buggy handler doesn’t break the entire webhook system without at least logging an error.
  - **Logging and Debugging:** We will include optional verbose logging for development mode. This could log incoming events (at least their types and sources), verification results, and any errors. In debug mode, developers can simulate webhook payloads easily and see what the router would do. This is important because testing webhooks (often coming from external sources) can be challenging – the library will facilitate local testing by perhaps allowing developers to feed sample payload+header and see it route (maybe a CLI or test helper).
  - **Documentation and Samples:** A part of DX is having great docs. We plan to include clear documentation for how to use the library in various scenarios (Express, Flask, serverless, etc.), and example code for integrating common providers. Also, guides for adding a new provider integration. Possibly even provide a set of **test payloads** for each provider to help with local testing (some providers, like Stripe, provide sample events – we can incorporate those in tests or docs).
  - **Type Definitions:** In the TypeScript version, provide `.d.ts` definitions for all public interfaces, especially the event payload types, so developers get auto-complete. In the Python version, possibly provide Pydantic models or type hints (so if using Python 3.9+ with typing, they can have `WebhookEvent[StripePaymentSucceeded]` or similar).
  - The end goal is that using the Unified Webhook Router feels intuitive and saves time: integrating a new webhook should be as simple as configuring the provider secret and writing a small function to handle the event, with no worry about the plumbing.

## Key Features and Requirements

Below is a detailed breakdown of the core features and requirements for the Unified Webhook Router. These encompass functional capabilities, supported platforms, security requirements, and extensibility. The requirements are grouped by theme for clarity.

### 1. Multi-Provider Support (Out-of-the-box Integrations)

The library will come with built-in support for a set of common webhook providers, including but not limited to:

- **Stripe:** Payment webhooks (e.g. `payment_intent.succeeded`, `invoice.paid`). Uses Stripe’s signing secret to verify `Stripe-Signature` header (HMAC SHA-256). Must parse JSON payload to Stripe’s event object format. Enforce Stripe’s 5-minute tolerance for signature timestamp by default.
- **GitHub:** Repository/webhooks events (e.g. `push`, `pull_request`). Uses a secret (HMAC SHA-1 or SHA-256 depending on config) in `X-Hub-Signature`/`X-Hub-Signature-256` header. The library will support the GitHub scheme to validate payload integrity. Payload is JSON (commits, repo info, etc.) – provide a Python/TS type for common fields.
- **Slack:** Slack’s Events API and interactive webhooks. Uses `X-Slack-Signature` and `X-Slack-Request-Timestamp` headers with HMAC SHA-256. The router will implement Slack’s signature verification recipe (concatenate version, timestamp, body) and ensure the request is recent (within 5 minutes) to avoid replay. Also, handle Slack’s URL verification challenge: when Slack sends a challenge (a special event to verify the endpoint), the library can detect this and optionally auto-respond with the challenge token as plaintext (since Slack expects the challenge echoed back for verification).
- **Twilio:** Webhooks from Twilio (for SMS, Voice, etc.). Twilio uses an `X-Twilio-Signature` header, which is HMAC-SHA1 of a concatenation of the request URL and all params (sorted) with the auth token as secret. The library will incorporate Twilio’s algorithm to verify authenticity. Support both JSON and form-encoded payloads Twilio might send. Twilio also allows Basic/Digest auth on webhook URLs; while that’s outside the primary scope, our library should not interfere – if basic auth is used, that would be handled at the web server level prior to our router being invoked.
- **Square:** Square payments webhooks. Uses `x-square-hmacsha256-signature` header (HMAC SHA-256). The signature is calculated using the provided signature key, the notification URL, and the raw body. The router will need the Square signature key (secret) and the knowledge of the endpoint URL (the latter can be configured if needed, since it’s required for verification). It will validate the signature and parse the JSON payload (e.g. order updated events).
- **Shopify:** (If included in initial list) Shopify webhooks (e.g. orders/create). Uses `X-Shopify-Hmac-Sha256` header, HMAC-SHA256 with the Shopify shared secret and raw request body (in JSON). The library can verify this and parse the JSON (Shopify sends resource data).
- **PayPal:** _\[Potentially]_ PayPal webhooks use a slightly different approach (they provide transmission ID, a cert URL, etc., and use an asymmetric signing or a REST API to verify). PayPal’s verification is more complex (with public certificates or a POST-back verification). This might be a stretch goal – initial focus can be on symmetric HMAC-based webhooks. We might document PayPal as a custom integration using the extensibility mechanism (or plan support in a later version).
- **Others:** Other common services to consider: **SendGrid** (event webhooks for emails, which use an API key in header or signature), **HubSpot** or **Zapier Catch Hooks**, **Contentful/ContentStack**, **Okta** (which might use static tokens or basic auth), etc. We will choose a handful of high-value ones for MVP. The design will make adding any similar HMAC-based webhook straightforward via configuration (as opposed to requiring full new code each time).

_Requirement:_ The library **must provide at least 5 provider integrations in the initial version** (likely the ones listed: Stripe, GitHub, Slack, Twilio, Square). Each integration should be tested against real examples from those services to ensure accuracy of signature verification and payload parsing. The documentation will enumerate exactly which providers (and which event types) are supported out of the box.

### 2. Unified Configuration and Initialization

There will be a clean way to configure the router with all necessary secrets/keys and options for the providers you want to use:

- **API for Configuration:** For example, in Node/TS:

  ```ts
  const router = new WebhookRouter({
    stripe: { signingSecret: "whsec_xxx" },
    github: { secret: "mygithubsecret", algorithm: "sha256" },
    slack: { signingSecret: "slacksecret" },
    twilio: { authToken: "twilio_auth_token" },
    square: {
      signatureKey: "square_sig_key",
      notificationUrl: "https://myapp.com/webhooks",
    },
  });
  ```

  In Python, a similar initialization, perhaps via a dictionary or using environment variables. We will support both programmatic config and perhaps environment-variable based defaults (for 12-factor apps).

- **Secret Management:** The library will encourage keeping secrets out of code (in env vars). The config interface will accept secrets (strings) or a callable to retrieve them (if someone wants to integrate with a secret manager at runtime). All secrets will be handled securely in memory.
- **Global vs Local Config:** You can instantiate the router with all providers at once as above. Alternatively, one might instantiate separate routers per provider if desired (the library design will allow multiple router instances). But a single router handling multiple is the main use-case.
- **Optional Settings:** Provide optional configuration flags such as:

  - Tolerance override (e.g. Stripe allows customizing the timestamp tolerance; our config could allow that if needed).
  - Enabling/disabling certain verifications (though default is all enabled for safety).
  - Logging level (verbose debug logging on/off).
  - Custom behavior toggles, e.g., an option to automatically respond to Slack challenge requests (true by default, perhaps).
  - A mode to automatically return a 200 OK after executing handler, or let the developer handle response (depending on integration style – in some frameworks the router might manage the HTTP response, in others it might just raise or return data).

- **Thread Safety:** The configuration/initialization should be done once (e.g., at app startup). The router instance must be safe to use concurrently (in Node, it will just handle one request at a time per event loop naturally; in Python, if using something like Gunicorn threads or async, it should handle multiple calls – avoid global mutable state that can conflict).
- **Example Config:** Document examples for common frameworks (e.g., using Next.js API routes requires `config.api.bodyParser` to be false to get raw body – we will include such tips in docs).

_Requirement:_ The library’s initialization should be straightforward and well-documented. It should throw clear errors if required configuration is missing (e.g., if you attempt to handle a Stripe webhook without setting a Stripe signing secret, it should alert you).

### 3. Signature Verification & Security (Functional Requirements)

This is the most critical part of the library’s functionality – ensuring that each incoming webhook is authenticated correctly:

- **Implement Provider-Specific Verification:**

  - **Stripe:** Parse the `Stripe-Signature` header, which contains one or more signatures and a timestamp. Compute the expected signature using HMAC SHA-256 with the signing secret and the raw request payload (prepending the timestamp). Check that the computed signature matches one of those in header, and that the timestamp is within tolerance. If any check fails, treat the request as invalid.
  - **GitHub:** If `X-Hub-Signature-256` (or older `X-Hub-Signature`) header is present, compute HMAC with the known secret and compare to the header’s value. GitHub’s signature is usually hex string prefixed with algorithm (e.g., `"sha256=abcdef..."`). We will support at least sha256 (preferred) and sha1 for backward compatibility. Reject if signature doesn’t match exactly.
  - **Slack:** Retrieve `X-Slack-Signature` and `X-Slack-Request-Timestamp`. Compute the basestring `v0:{timestamp}:{raw_body}` and then compute HMAC SHA-256 with Slack signing secret. Compare to the header (which is prefixed with `v0=`). Also, check the timestamp is not too old (the library will default to 5 minutes as Slack suggests to mitigate replay). If timestamp check fails or signature mismatch, reject.
  - **Twilio:** Retrieve `X-Twilio-Signature`. Per Twilio’s spec, take the full URL of the request (the exact URL Twilio hit, including query params if any, in the exact domain/case – this sometimes is tricky in frameworks behind proxies; we’ll document getting the correct URL). Gather all POST fields (for form-encoded requests) or JSON fields (Twilio may send application/x-www-form-urlencoded by default). Sort parameters alphabetically by key, concatenate key and value pairs to the URL string, then compute HMAC-SHA1 with the auth token. Compare to the provided signature (base64 encoded). The library will do this and return valid/invalid. (Twilio provides their own helper in their SDK; we’ll implement equivalent logic natively).
  - **Square:** Retrieve `x-square-hmacsha256-signature`. Compute HMAC-SHA256 using the Square signature key, with message = notification URL + raw body (as Square describes). We must ensure to use exactly the same URL string that Square used (which includes protocol, domain, path – likely the config’s `notificationUrl`). Compare to header (base64 encoded). If mismatch, reject.
  - **Other HMAC-based (Shopify, etc.):** Compute HMAC-SHA256 of raw body with the secret, compare to provided header (Shopify’s is base64 of the HMAC). Similar approach for others like SendGrid (which signs events with an “X-Twilio-Email-Event-Webhook-Signature” since Twilio owns SendGrid now – that one uses an ECDSA signature actually; if we include it, that’s a different algorithm).
  - **Static Token / Secret Header:** Some services (older or simpler ones like GitLab or certain custom webhooks) don’t use HMAC but a simple secret token in a header or as a query param. The library can support this in a generalized way: if configured with a static token method, it just checks that a given header matches the expected secret exactly. For example, GitLab sends a header `X-Gitlab-Token` that the consumer must check against a pre-shared token. Our GitLab support (if added) will simply compare the header value to the configured token and reject if not equal. This is a straightforward but important check.
  - **Asymmetric (Public Key) Verification:** A few providers (e.g., PayPal, DocuSign) sign webhooks with their private key and provide either a JWT or a certificate for verification. Our initial version may not handle this out of the box (unless we include a JWT verify for something like Plaid which uses JWTs). However, the architecture should not preclude it. If needed, we could integrate standard JWT verification (using PyJWT or node’s JWT libraries) for providers like Plaid (which sign webhooks as JWTs) or at least allow the user to plug in a verification callback (extensibility) to handle these cases. This would be marked as advanced usage.

- **Time Stamp and Replay Protection:** As noted, for any provider that supplies a timestamp or id for replay prevention, enforce it:

  - Slack – 5 minutes by default.
  - Stripe – 5 minutes by default (tolerance configurable).
  - Others – if no timestamp, we can’t auto-prevent replays beyond just signature (some providers include an event ID in payload; we might not track seen IDs in this library because that requires state or storage, which is out-of-scope. We assume if signature matches and no timestamp is provided, it’s as safe as that provider allows. If a user needs extreme security, they could implement an idempotency check in their handler logic).

- **Rejecting Invalid Requests:** If verification fails for a request:

  - In Node usage, the `router.handle(req, res)` could immediately respond with an HTTP 400 or 401/403 (the exact status can be chosen per scenario: 401 Unauthorized or 403 Forbidden might be appropriate for “signature invalid” – Stripe for instance expects a 400 on invalid signature in some cases, or a generic non-2xx which triggers retries). We will pick sensible default (likely 400 Bad Request for bad signature). We will also include a short response body or log message for debugging (but not too verbose to avoid leaking info).
  - In Python usage, the `router.handle(request)` might raise a specific exception (like `InvalidWebhookSignature`) that the user’s framework can catch and turn into an HTTP response. If integrating directly, we might return an `HttpResponse` (in Django terms) or Flask Response with error.
  - The library will ensure that **no user-defined handler is executed if the request fails auth**. This containment is crucial – unverified requests are never processed further.

- **Middleware Ordering:** We will document that the router should be invoked at a point where it has access to the raw request body. For Node, that usually means using a body parser that gives raw data (or disabling body parsing). For Python, frameworks like Django have `request.body` property with raw data (which we can use), Flask has `request.get_data()`. The library might provide a helper to unify getting raw body from a request object.
- **Constant-Time Comparison:** As a non-functional security detail, we will implement signature comparisons using constant-time algorithms to avoid timing attacks (where an attacker could exploit string compare time to guess secrets). Many languages offer a secure compare (e.g., Node’s `crypto.timingSafeEqual`, Python’s `hmac.compare_digest`) – we will use those.
- **Testing Security:** We will include unit tests using known sample secrets & payloads from provider docs to ensure our verification rejects bad signatures and accepts correct ones. Possibly integrate test vectors from documentation.

_Requirements Summary:_ The router **must** accurately verify incoming webhooks for all supported providers using the official methods. It should handle edge cases like multiple signatures (Stripe can send multiple signature values), case differences in header names, and body encoding issues (make sure to use raw bytes). If any check fails, the request is not processed. These checks are the heart of the library’s value proposition.

### 4. Event Parsing and Normalization

After a webhook request passes verification, the library will parse the request payload into a normalized event object and then dispatch it to the appropriate handler. Requirements for this stage:

- **Payload Parsing:** Identify the content type and parse accordingly:

  - Most webhooks use JSON payloads (Content-Type: application/json). We will parse the JSON string into an object/dictionary. The library should be careful to parse only after verification (for some providers like Stripe, verifying requires the raw payload string, so parsing should come after or be done on a cloned raw data).
  - Some webhooks (e.g., Twilio, certain form posts) may come as form-encoded (`application/x-www-form-urlencoded`). The library can decode those into key-value dictionaries. Twilio’s own Node/Python SDK expects a dict of params to compute signature. Our verification step will already have to parse or at least sort parameters – we will reuse that to form the event data.
  - If a provider sends XML (rare nowadays, but maybe some old ones do), initially we might not support XML out-of-the-box (could be a future extension). The library could at least provide the raw body for such a case or allow a custom parser.

- **Unified Event Object:** Define a structure for the event passed to handlers. For example (pseudocode in TS interface form):

  ```ts
  interface WebhookEvent<T = any> {
    provider: string; // e.g. "stripe", "github"
    type: string; // e.g. "payment_intent.succeeded" or "push"
    id?: string; // an optional event ID if provided (e.g. Stripe event has an 'id', GitHub deliveries have an 'X-GitHub-Delivery' UUID header)
    payload: T; // The parsed payload object, type T depends on event type
    rawHeaders: Record<string, string>; // maybe include headers if needed
    rawBody: string; // the raw request body text (for logging or debugging if needed)
  }
  ```

  In Python, this could be a dataclass or just a dict with similar keys.

  The **`payload`** field will be the main data, ideally typed or structured. For known providers, we might create specific classes or types for their payloads:

  - For Stripe: The payload has `id`, `type` (event name), `data.object` containing the resource. We might simplify so that for Stripe events, `event.type` is already there (as `type` field above), and `payload` is basically `data.object` (the core resource) or the whole Stripe event object. We need to decide if we present the entire event (with request metadata, etc.) or just the object of interest. Possibly, we give the entire event as provided by Stripe’s API so the handler can use all info.
  - For GitHub: The payload structure varies by event (push vs issues, etc.), but we can at least type it as `GitHubPushEvent` etc., or just a dict. We will likely leave it as a dict but documented keys. GitHub also has delivery headers we might surface (like delivery ID and event name).
  - Slack: Slack sends different structures for Events API vs slash commands vs interactive components:

    - Events API: a JSON with `type`, `event` nested object, etc.
    - Slash commands: form-encoded with specific fields like `command`, `text`, etc.
    - We might unify Slack such that the event passed to handler is a dict that always has a `slackEventType` and then relevant data. If the library sees a Slack verification challenge, it might intercept it before handler as mentioned.

  - Twilio: Twilio webhooks often have fixed parameter keys (e.g., for an SMS received event, fields like `From`, `Body`, etc.). We will provide those as a dictionary with proper types (strings, etc.).

- **Handler Signature:** When the router calls a user-registered handler, it will pass this event object (and possibly additional context arguments depending on language):

  - In Node/TS, maybe the handler signature is `function handler(event: WebhookEvent, context: WebhookContext)`. Context could include things like an easy way to respond or any config. However, since the handler might not need to send a response (just processing), context could be minimal. We might just do `handler(event)` and not complicate further.
  - In Python, similarly `def handler(event: WebhookEvent):` or possibly allow async handlers (especially in async frameworks like FastAPI).
  - If the user needs to send an HTTP response (some webhooks expect a specific response body: Slack slash commands expect an immediate response to acknowledge or message), we need to accommodate that. Two ways:

    - The handler could return a value that the library will use as the HTTP response. For example, Slack slash commands or interactive actions often expect a JSON response (or an empty 200). We could document that if a handler returns something like a dict or Response, the router will forward that as the HTTP response. Otherwise, the router can default to sending a generic 200 OK.
    - For simplicity in MVP, we might say: by default the router always responds 200 OK to the webhook source after processing (since most providers care simply that you returned 2xx). If a specific provider requires a different response (Slack’s challenge requires returning the challenge token in body), the library will handle that internally or expose a hook.
    - We should ensure that in cases of synchronous processing, we don’t accidentally hold up the response too long. Perhaps allow an option to process asynchronously and immediately return 200 (for time-consuming handlers, but that’s more on the user to offload tasks).

- **Normalized Metadata:** Provide some common metadata in the event object:

  - `event.provider`: unified provider key name.
  - `event.type`: normalized event type name (for Slack, maybe the inner event type, for others same as provider’s event name).
  - `event.id`: if the provider provides an event ID (Stripe has `id` in event payload, GitHub has `X-GitHub-Delivery` header, etc.), include it for logging/idempotency tracking.
  - Possibly `event.receivedAt` timestamp of processing.
  - We should be careful not to confuse `event.type` with Slack’s top-level request type (which might be “event_callback” for all events, with the actual event type inside). For Slack, probably we will surface the inner `event.type` for convenience.

- **Edge Cases:** If a payload is not valid JSON and was supposed to be (e.g., a malformed payload or wrong content type), the library should handle the JSON parse error by responding with a 400 (bad request). It should not crash the process. Similarly, if a provider’s payload structure is not as expected, we handle gracefully (perhaps just pass it through as dict).
- **Character Encodings:** Ensure we handle Unicode in payloads properly. The raw body likely is UTF-8 bytes; our verification uses those bytes. Then decoding to string and JSON parsing should handle unicode. Any binary data in webhooks (unlikely) would be handled as needed.
- **No Data Alteration:** The library will not modify the payload data except to parse. It won’t, for example, automatically retry or store the data. That is left to user code if needed. We just guarantee the handler gets the data if verified.

_Requirement:_ The event objects delivered to handlers must be correct and convenient. For each supported provider, document what the `event.payload` contains. The system should be designed such that adding a new provider includes specifying how to extract a meaningful payload and event type for that provider.

### 5. Unified Routing & Handler Management

The router’s dispatch mechanism needs to be robust and flexible:

- **Handler Registration API:** Provide methods to register handlers for specific events. Possible designs:

  - **Method-based (Fluent API):** e.g., `router.on(provider, eventName, handler)` as mentioned. Or `router.onStripe(eventType, handler)`, `router.onSlack(eventType, handler)` etc. A generic method is more scalable (just pass provider name string).
  - **Configuration-based:** Alternatively, the user can supply a mapping of event types to handlers in the config. For example:

    ```js
    const router = new WebhookRouter({...secrets...});
    router.registerHandlers({
      "stripe": {
         "payment_intent.succeeded": stripePaymentHandler,
         "invoice.paid": stripeInvoiceHandler
      },
      "github": {
         "push": gitPushHandler,
         "*": defaultGitHandler  // maybe wildcard for any GitHub event
      }
    });
    ```

    We might support both, but a programmatic `.on()` is user-friendly for incremental definition.

  - **Default Handlers:** Allow specifying a default handler for all events from a provider (perhaps using event name `"*"` or leaving eventName null). This is useful if the app doesn’t need to differentiate sub-types or wants to log all events in one place.
  - **Multiple Handlers / Middleware:** Possibly allow multiple handlers per event (like a chain), though initial version might keep it one-to-one (one event -> one handler) to avoid complexity. If multiple needed, user can call other functions from within their handler.

- **Dynamic Routing Logic:** The router will use the identification of provider (by headers or other cues) and event type (from payload or header) to choose the handler:

  - For example, if a request comes in with header `Stripe-Signature`, we identify provider = Stripe. We parse the JSON which has `"type": "invoice.paid"` for instance. The router looks up if a handler was registered for ("stripe", "invoice.paid"). If yes, call it. If not, check if there's a wildcard for "stripe" or a global fallback. If none, by default, it could simply return 200 OK and do nothing (or log that an event was unhandled). We will likely not treat missing handler as an error to provider (because many apps might not handle every single event type; unhandled events can be safely ignored to not cause endless retries from provider).
  - Similarly for GitHub: provider = GitHub by `X-GitHub-Event` header which gives event name (like "push"). We see if ("github", "push") is registered.
  - Slack: Slack’s case, provider = Slack if signature header present. For Events API requests, the JSON has `type: "event_callback"` and inside it `event.type` like "reaction_added". We would route based on that inner event type, presumably ("slack", "reaction_added"). For slash commands, Slack doesn’t use the same structure; those might be identified by the presence of form fields like `command` – possibly we treat slash commands as a different sub-type, or just unify by saying event type = "command" or the command name. We’ll define clearly how Slack events map to event names for handler routing.

- **Performance:** The routing lookup should be efficient (likely just dictionary lookups by provider -> event map). The number of providers and events is not huge in typical use, so performance is fine. But we ensure this is done after verification (which is the heavier operation due to cryptography).
- **Threading/Concurrency:** If multiple webhooks come in parallel (in a multi-threaded Python server or concurrently in Node’s event loop via async), the router should handle them simultaneously. Since the router state is mostly configuration and a handler map, and the handling of each request doesn’t share mutable data (besides perhaps logging), it is inherently parallelizable. We just need to ensure any internal data structures (like an event being built) are per-request and not global.
- **Return Values and HTTP Response:** As touched on, decide how the HTTP response is managed:

  - In many frameworks, once our handler function finishes, control goes back to the framework to return response. We likely should provide a way to indicate the response body/headers if needed. For example, Slack URL verification event: our library could detect and instead of invoking the user’s normal handler, we could short-circuit and return the challenge token with content-type text/plain. We can handle such special cases internally for correctness.
  - For normal events, after user handler executes, typically we just need to ensure a 200 OK is returned to the webhook source. The library can do this automatically if it owns the response object (like in Node if we have the `res`). In Python, if we raised exception for errors, for success maybe we return a simple response. Alternatively, we could require the user to send response in their framework after calling router (less ideal – better if library takes care of it).
  - We will likely implement that in Node: `router.handle(req, res)` will internally call `res.status(200).end()` (or `send()`), unless a custom response is provided by handler. We have to ensure this doesn’t get called too early (so perhaps call handlers synchronously or await if promise).
  - In Python, maybe `router.handle(request)` returns a tuple (status, body) or a framework-specific Response. We may provide small adapters for popular frameworks (like a Flask blueprint or a Django view util) to smooth this out.

- **Idempotency / Replays:** The library itself won’t store state to prevent duplicate processing (that’s a higher-level concern). However, we will document that providers may retry deliveries on failures and send duplicates, so user handlers should be idempotent. We can perhaps make it easier by surfacing event IDs so the user can log or track if needed. We might even include an optional in-memory deduplication (e.g., remember last X event IDs for Y minutes) just to demonstrate, but that’s not reliable in distributed environments unless using external store, so likely out of scope for now.
- **High Availability:** The router should be able to initialize even if only some providers are configured. If a request comes for an unconfigured provider, by default it should reject (since we don’t know how to verify it). But maybe allow a “passthrough” mode for unknown providers if the user wants to handle them manually (not a common need, probably skip).
- **Priority of Matches:** If by some chance two providers could match one request (unlikely because signatures and headers are unique), the router will have a defined priority or identification order (for instance, check known headers in some order). We should list the identifying characteristics: e.g. if `X-GitHub-Event` header is present, treat as GitHub (even if a Stripe-Signature also present? That wouldn’t happen realistically). We can just match on unique header presence:

  - Stripe: `Stripe-Signature` header.
  - Slack: `X-Slack-Signature` header.
  - GitHub: `X-Hub-Signature` (or delivery header + event header).
  - Twilio: `X-Twilio-Signature`.
  - etc.
    There should be no conflict (no two providers use the same header name).
  - If a conflict or uncertainty, we could also use the request URL path if the user set up distinct endpoints for clarity. E.g., user might route `/webhooks/stripe` vs `/webhooks/github` to the same router but we know context from path (we can allow passing the intended provider as a parameter in code if needed).

- **Testing Hooks:** Possibly allow a dry-run mode or test injection. For example, in unit tests a developer might want to simulate a webhook event. We could expose a method like `router.testTrigger(provider, eventType, payload)` that bypasses signature and directly invokes the handler (for testing business logic). This could be a nice-to-have utility.

_Requirement:_ The router must reliably call the correct handler for each verified webhook event. Handler registration should be easy and flexible. The system should never mis-route an event (each event type goes where intended) and should handle missing handlers gracefully (no crashes, and ideally no non-2xx to provider unless explicitly configured to do so for unhandled events).

### 6. Extensibility for Additional Providers

As mentioned, not all webhook providers will be known upfront. The library must allow extension without modifying its core code. Key requirements for extensibility:

- **Provider Definition Interface:** Define a structure for adding a provider. For example, in TypeScript, something like:

  ```ts
  interface WebhookProvider {
    name: string;
    identify: (headers: IncomingHttpHeaders, body: Buffer) => boolean;
    verify: (headers: IncomingHttpHeaders, rawBody: Buffer) => boolean;
    extractEventType: (headers: IncomingHttpHeaders, payload: any) => string;
    parsePayload: (rawBody: Buffer, headers: IncomingHttpHeaders) => any;
  }
  ```

  And in Python a similar class or dictionary of functions. This is a rough idea – essentially: a way to detect if a request belongs to this provider, how to verify it, how to get the event type, and how to parse it.

  - We might simplify by saying identify is based on a unique header or path, provided as a string (e.g. identify by `X-MyProvider-Sign` header existence). If the library sees that header, it picks that provider to use for verification.
  - The verify function would implement the logic (the library could offer utility functions, like a generic HMAC verifier you feed the secret and header name and algorithm).
  - extractEventType: some providers include event name in headers (GitHub, Stripe includes in payload, Slack in payload, etc.). The provider module should specify how to get a routing key from the content.
  - parsePayload: if standard JSON, we can default to JSON parse. If form encoded, or some special like JWT, the module can handle it.

- **Registration of Custom Provider:** Expose an API like `router.registerProvider(customProviderConfig)`. This would add it to the internal list of known providers. If identify logic is based on header, ensure no conflict. Possibly require the user to provide the secret or keys as part of this config as well, or the custom provider config can internally reference environment vars.
- **Use Case:** Suppose a developer wants to add **PayPal** webhook support. PayPal (for REST webhooks) sends `PAYPAL-TRANSMISSION-SIG`, `PAYPAL-TRANSMISSION-ID`, `PAYPAL-TRANSMISSION-TIME` and a cert URL. A custom verify might need to fetch the cert and verify the signature of the payload. The user could write a verify function to do that (or call PayPal’s API for verification). They then do `router.registerProvider({ name: "paypal", identify: hdrs => !!hdrs['paypal-transmission-id'], verify: myPaypalVerify, extractEventType: payload => payload.event_type, parsePayload: JSON.parse })`. Our router will then route PayPal events too.
- **Documentation of Extending:** We will clearly document how to add a provider, and perhaps provide template code for a generic HMAC-based provider so users can easily plug in values (like “if your provider uses an HMAC header, just use this helper with your secret and header name”).
- **Open Source Contribution:** Since this is likely an open-source library, we anticipate users contributing new provider modules. The architecture should allow adding them easily (maybe just adding a file or config entry). We might maintain a list of supported providers in docs and encourage PRs for new ones.

_Requirement:_ The library’s extendability is a core selling point. It should take only a few lines of code to integrate a new webhook source. Under the hood, the design might treat built-in providers just the same as custom ones (just pre-registered for convenience). We should avoid hard-coding things in a way that’s not generalizable.

### 7. Multi-Language Implementation (TypeScript/Node and Python)

The product must be delivered in both **TypeScript (Node.js)** and **Python** versions with parity in features:

- **Core Logic Mirrored:** The verification algorithms and routing logic should be consistent across the two implementations. We will maintain a specification or tests to ensure that, for example, Stripe signature verification is done correctly in both Node and Python. Differences in language standard libraries (like crypto functions) will be accounted for, but the outcome (pass/fail) should match for given inputs.

- **API Similarity:** While languages differ, we aim for a similar conceptual API:

  - In Node, likely an instance of a `WebhookRouter` class with methods.
  - In Python, perhaps a class as well or a Flask blueprint style. Possibly a singleton or module with configuration.
  - Example: Registering a handler in Node: `router.on('stripe', 'payment_intent.succeeded', handler)`. In Python: `router.on("stripe", "payment_intent.succeeded", handler)`. Python can accept a callable (function) as handler.
  - The names of providers and events should be the same strings in both (so documentation applies to both).
  - Both versions should support synchronous and asynchronous handlers. Node naturally can handle promises (if a handler returns a Promise, we can `await` it). In Python, we might have to consider if supporting async def handlers (especially for AsyncIO frameworks). Possibly the Python router could detect coroutine and run it via asyncio if needed.

- **Packaging and Distribution:**

  - Node/TS: We will publish it as an NPM package (possibly under name like `@myorg/webhook-router`). Written in TypeScript to provide types out-of-the-box. Should compile down to a CommonJS or ESM module as needed.
  - Python: Publish to PyPI (name e.g. `unified_webhook_router`). Ensure it supports Python 3.7+ (depending on target, likely focus on 3.8 or 3.9+). Use type hints. Possibly use minimal dependencies (maybe `hmac` and `hashlib` from stdlib for crypto, maybe `requests` if needed for any external calls like fetching PayPal certs – but we can avoid external calls in core).
  - Versioning: We will keep the versions in sync conceptually (e.g., release v1.0 for both at same time).
  - Testing in each: We will have tests possibly using pytest for Python and jest for Node to ensure functionality.

- **Example parity:** Provide examples in both languages for common scenarios in documentation.

- **Maintainability:** Ideally, the core logic can be specified in a language-agnostic way and then implemented per language. We might even auto-generate some test cases from a common source (for example, use known good signing test vectors and test in both implementations).

- **Note:** We are not implementing client-side (frontend) support (it doesn’t make sense, as webhooks are server-side). So no need for browser/React Native context. The mention of React Native or front-end frameworks by the user likely just underscores being usable in a variety of project contexts (i.e., even if the main app is RN, the backend can use this library).

_Requirement:_ Both the Node and Python libraries should fulfill all the same functional requirements. A developer should be able to achieve the same tasks in either environment. Documentation will cover both, and we must ensure consistency (for instance, if Slack challenge handling is automatic in Node, it should also be automatic in Python, etc.).

### 8. Framework Agnostic Integration

As noted, being framework-agnostic is crucial. More specific requirements to ensure ease of integration:

- **No Forced Dependencies on Web Frameworks:** The libraries will not import Express, Flask, etc., internally. They will use only standard interfaces (Node’s HTTP module types, Python WSGI-like request objects or simple wrappers). This keeps them lightweight and flexible.

- **Integration Guides:** Provide quick how-tos for:

  - **Express (Node):** How to plug in with `express.raw` body parser and using router.handle. Emphasize the need for raw body for certain providers (like Stripe).
  - **Next.js API routes:** How to disable automatic body parsing and use the router (Next allows `config = { api: { bodyParser: false } }` in an API route file, then you manually collect body – or possibly use our router to do it).
  - **AWS Lambda (API Gateway):** Show how to adapt the Lambda event to pass into the router (e.g., construct a headers dict and body from the event). Perhaps provide a small utility like `router.handleAwsLambda(event)` which returns a response object for Lambda.
  - **Flask (Python):** How to use in a Flask route (just call router and return its result).
  - **Django (Python):** Possibly as a Django view or integration with Django’s urls (maybe a simple view function that calls router).
  - **FastAPI (Python):** Show usage in an async endpoint (maybe call router in a thread if necessary, or we design router to be async-capable).
  - **Other**: Document that because we rely on basic constructs, it can work in others like Koa, Hapi (for Node), Starlette, etc.

- **Serverless nuance:** For serverless environments like Vercel or Netlify Functions, one just uses it as in Node (similar to Express usage). For Cloudflare Workers (which is an edge runtime with slightly different global fetch API), if we ever want to support that, we might need to adjust how crypto is done (Cloudflare workers have crypto.subtle API for HMAC). Probably out-of-scope initially, but something to keep in mind.

- **Performance overhead:** Ensure the library doesn’t add noticeable overhead beyond the necessary work. Being independent of frameworks means no double-parsing JSON, for instance. We should possibly detect if a request body is already parsed (to avoid re-parsing) – but since we need raw anyway, likely we always use raw and parse ourselves.

  - We can allow an optimization: if a framework already provided raw body on the request object (some do), we can use it. Or if the user passes the raw string directly to our verify function in some mode.
  - But these are micro-optimizations; baseline performance should be fine (crypto hashing of maybe a few KB payload is very fast in modern CPUs, on the order of microseconds to milliseconds).

_Requirement:_ It should be straightforward to integrate the Unified Webhook Router into any web app backend. We will treat this as met by thorough documentation and having minimal coupling. Essentially, if a developer has a web server, they should be able to feed requests into our router with a couple lines of code.

### 9. Non-Functional Requirements: Performance, Security, Quality

**Performance & Scalability:**

- The library should handle high throughput of events. The code should avoid any blocking operations that could hamper performance under load. In Node, everything is non-blocking except the crypto (which is usually asynchronous internally). In Python, if heavy crypto is needed (like verifying a large payload with HMAC), it’s quite fast but if needed can release GIL by using C implementations (the `hmac` module is in C).
- Memory footprint per request is small (just storing the payload string briefly, computing HMAC, etc.). The library should not leak memory; any state per request should be released after.
- Test with a scenario of, say, 100 concurrent webhooks to ensure it can handle it (in Node, concurrency, in Python maybe use async or threads to simulate).
- The library itself doesn’t introduce a bottleneck beyond the essential cryptographic verification and JSON parsing. These operations are efficient, and network I/O is not involved (unless in some extension like fetching a certificate for PayPal, which we likely won’t do in v1).
- For very high scale, users might horizontally scale their webhook receivers; our library should be stateless such that scaling is trivial.

**Security:** (Summarizing some from above)

- Absolutely no sensitive info should be logged by default (especially secrets). If logging debug, we will caution to never log the secret itself, and maybe not log full payloads in production.
- The library’s attack surface mainly is: it’s parsing external input. We must ensure our JSON parsing is safe (use standard library, which is safe as long as we treat it as data). We should avoid using something like `eval` or insecure deserialization.
- By handling verification and not passing unverified data to user code, we reduce security issues in user land.
- We will keep dependency count minimal to reduce supply chain risk. If using any, they should be well-known and maintained (for instance, if we use `cryptography` in Python for some HMAC or `PyJWT` for a JWT verification, but perhaps we can manage with stdlib).
- Regularly update the library to adapt to any security updates (e.g., if a provider changes their signing method or deprecates something).

**Error Handling & Reporting:**

- Provide clear error messages for configuration issues (like “Missing Stripe signing secret – cannot verify Stripe webhook”).
- For verification failure, we might not want to divulge details to the source (for security, e.g. don’t send “signature expected XYZ” back to sender). But we can log on the server side something like “Stripe signature verification failed for event X, possibly invalid signature” for debugging.
- Ensure that one bad request doesn’t crash the entire service. Use try/except around major steps (verification, parsing, handler execution).
- Possibly allow a global error handler callback that developers can use to be notified or override behavior (not necessary in v1, but a thought).

**Testing and QA:**

- We will create a comprehensive test suite:

  - Unit tests for each provider’s verification (with known test vectors).
  - Simulated end-to-end calls (maybe using sample HTTP requests for each provider).
  - If possible, integration test against actual provider simulator (Stripe CLI can send test webhooks, etc., but that might be outside the automated tests).

- Ensure 100% coverage on critical modules (verification code especially).
- Also test multi-provider scenario: feed mixed events and see if they route correctly.
- Performance tests for a typical size event to ensure latency overhead is minimal.
- The Python and TS versions should each be tested thoroughly on their own CI. We might also do a parity test: generate a Stripe payload and secret, test signature in Python and Node to ensure both accept or reject the same.

**Documentation & Examples:**

- This is crucial for adoption. We will include:

  - A README with quick start.
  - A detailed usage guide (possibly as part of docs site or markdown files) showing how to set up and configure, with code snippets for different frameworks and languages.
  - Security considerations section explaining what the library does (so users trust it) and what it doesn’t do (e.g., not storing events).
  - How to extend section.
  - Possibly reference tables of what headers and methods are used for each provider (for transparency).

- Possibly provide a demo repository or snippet for a minimal Express app and a minimal Flask app using the library, which users can reference.

**Maintenance & Roadmap:**

- Plan for updates as providers change. For example, if GitHub deprecates SHA-1 signatures, we’ll remove or warn on using it and use SHA-256. Or if a new provider becomes popular (e.g., some new payment API) we can add it.
- Roadmap could include adding a GUI or CLI to test webhooks (maybe outside scope, but interesting: e.g., a CLI command to “simulate a Stripe event” to your local handler for testing).
- Another future idea: the router could optionally integrate with a queue (so that upon receiving a webhook, it enqueues an event for processing elsewhere). But that’s beyond initial scope; our focus is on direct handling.

## Scope and Out-of-Scope

To clarify boundaries:

**In Scope (for initial release):**

- Unified webhook handling as described: verification, parsing, routing for the main providers (Stripe, GitHub, Slack, Twilio, Square, etc.).
- Implementations in Node/TypeScript and Python with feature parity.
- Basic integration documentation for popular frameworks.
- Extensibility interface for new providers (covering at least HMAC/token-based extensions).
- Automatic handling of special cases like Slack URL verification challenge.
- Robust security and error handling within the context of processing a single webhook request.

**Out of Scope (initially):**

- **Outgoing Webhook Delivery** – The library does **not** handle sending webhooks or acting as a webhook provider. It’s only for consuming/receiving webhooks from third parties.
- **Event Persistence & Retries** – The library itself won’t store events or manage retry logic beyond returning non-200 to trigger provider retries. Handling retries or ensuring idempotency is left to the application (or the provider’s retry mechanism). We won’t build a queue or DB for webhooks (but developers can integrate one if needed).
- **Dashboard/Monitoring UI** – No user interface or dashboard for received webhooks is included (though we may output logs that developers can pipe into their own monitoring).
- **Authentication methods beyond signatures** – We focus on the common signature and token strategies. We will not implement a full OAuth flow or complex auth server for webhooks. Basic auth on endpoints is considered external (the web server can protect the endpoint with basic auth if needed before the router is invoked).
- **Support for every single provider from day one** – We will cover many, but not all. Some specialized or less common webhooks might require the developer to use the extension mechanism themselves initially.
- **Cloud-specific deployments** – We won’t provide infrastructure (like AWS API Gateway config) as part of the library, just the code. Deployment is up to the user.

By explicitly not doing the above, we keep the library focused and lightweight. These could be addressed by complementary tools or future enhancements if needed.

## Technical Architecture & Design Considerations

This section outlines how we plan to implement the above features under the hood in both language environments, highlighting important design choices:

### Architecture Overview

At a high level, the Unified Webhook Router will have the following components internally:

- **Provider Modules:** A collection of modules or classes, each encapsulating the logic for one provider (verification algorithm, event extraction). For built-in providers, these are included in the library. For custom ones, they might be added at runtime via config.
- **Router Core:** The central dispatcher that:

  1. Inspects an incoming request (headers, body) to identify which provider module should handle it.
  2. Invokes that provider’s verification logic.
  3. If verified, obtains the event type and parsed payload via the provider module.
  4. Looks up the appropriate handler and calls it with the constructed event object.
  5. Handles the response logic (returning status, etc.).

- **Configuration Store:** Data structure to hold configured secrets/keys per provider, and settings like tolerance. This is populated at initialization from user input. Provider modules will access this for secrets when verifying.
- **Handler Registry:** Data structure (likely a nested map: provider -> event -> handler function) for the registered handlers. The router core consults this for routing. It may also store special handlers like a default handler per provider or a global fallback.
- **Utilities:** Common functions used by multiple providers, e.g. HMAC signature function (so we don’t rewrite HMAC code for each provider, we generalize it with different keys and message formats), a constant-time compare function, a function to get raw body from various request objects, etc.

**Sequence Flow (for a typical request):**

1. **Request Intake:** The user’s server passes the HTTP request to the library (e.g., calling `router.handle(req, res)` in Node or similar in Python).
2. **Provider Identification:** The router examines known distinguishing features. For example, it checks for presence of provider-specific headers in the request:

   - It might iterate through the list of registered providers (including built-ins and custom) and for each call a provided `identify()` function or check header keys. The first match “claims” the request. If none match, it either throws an error (unknown webhook source) or could assume a default if configured (likely we’ll error out or ignore because we can’t verify unknown source).

3. **Verification:** Once a provider is identified (say, Stripe):

   - The router retrieves the provider’s config (secret keys, etc.) from the config store.
   - Calls the provider’s verify function, passing it the headers and raw body (and config). If this returns false or throws, verification failed. The router will then immediately generate a failure response (HTTP 400). No handler is called. It may log the incident.
   - If verification succeeds, proceed.

4. **Parsing:** The router invokes the provider’s parse logic. For JSON, this is straightforward (could use a shared JSON parser utility). For forms, use appropriate parser. The result is a Python dict or JS object representing the payload.

   - If parsing fails (e.g., invalid JSON), the router treats it as an error -> respond 400 (with message about bad payload).

5. **Event Object Assembly:** Using the parsed data and provider info:

   - Determine the event type name. For some, the provider might embed it (Stripe: in the payload’s `type` field; GitHub: in `X-GitHub-Event` header; Slack: we might use payload’s inner event type or treat slash commands differently).
   - Create the `WebhookEvent` object with `provider`, `type`, `payload`, etc. Also include `id` if available (e.g., Stripe’s payload `id`, GitHub’s header `X-GitHub-Delivery`).
   - Attach any additional context if needed (maybe the request object itself if advanced user wants it, but by default not necessary).

6. **Routing to Handler:** The router looks up in `handlerRegistry[provider][eventType]`:

   - If found, get the handler function.
   - If not found:

     - If a wildcard handler for that provider exists (e.g., `handlerRegistry['github']['*']`), use that.
     - Else if a global catch-all handler exists (maybe user set something like router.on('\*', handler) meaning all unrecognized events go there), use it.
     - Otherwise, no handler – the router will decide to do nothing except return a 200 OK (because from the provider’s perspective, a 200 means “we handled it”, even if we just ignored it internally). We might log “no handler for X event, ignoring”.

   - This logic ensures providers don’t keep retrying due to 400s for events the app doesn’t care about; we’ll just accept (2xx) and drop them.

7. **Execute Handler:** If a handler is found:

   - In Node: call it. If it returns a Promise (async function), await it. If synchronous, just call. If it throws or rejects, catch that.
   - In Python: if sync function, call it. If it’s an async coroutine (we might allow that if using an async framework), we need to either run it in event loop (if within an async context, we can await it; if in a sync context like WSGI, perhaps not support coroutine handlers directly or run via loop run_until_complete which could be messy; we might initially say handlers should be regular functions for simplicity, or the user can ensure to run router in async env).
   - The handler can perform whatever business logic needed (update database, send response, etc.). If the handler needs to return something to send back to the webhook sender (like a Slack acknowledgement message), it can either directly use the response (in Node, they have `res` if we provided it via context, or in Python maybe they modify a response object). Or a simpler approach: allow handler to `return` some data and our router will treat that as the desired HTTP response content:

     - e.g., Slack slash command handler might return a JSON (dict) with a message, then our router will serialize it and send as HTTP 200 with `application/json` to Slack.
     - We will define what happens if a handler returns a value. If nothing is returned (typical case), we just send 200 empty. If something is returned and it’s not `None`, we try to send it. This behavior will be documented.

   - Any exception in handler:

     - The router catches it, logs it, and returns a 500 Internal Server Error to the webhook source. (We could also allow customization: maybe the developer would prefer to always respond 200 and handle errors internally to avoid retries. This could be an option. But default likely 500 so that provider will retry later, giving the app a chance if it was a transient error.)
     - In either case, ensure the exception doesn’t propagate and crash the server.

8. **Respond to Sender:** After handler execution:

   - If the handler (and library) ran successfully, ensure an HTTP 2xx has been or will be sent.
   - If a custom response body was provided (like Slack challenge or slash command reply), ensure correct headers (content-type) and formatting.
   - End the request-response lifecycle cleanly (close streams, etc., which typically the framework handles once our function returns).

The architecture ensures a clear separation: verification is done per provider module, and routing is done in core. This makes it easier to add new providers by just adding a module with the needed logic.

### Technology Choices and Libraries

- **Node/TypeScript Implementation:**

  - Will use Node’s built-in `crypto` module for HMAC (e.g., `crypto.createHmac('sha256', secret)`). Also use `crypto.timingSafeEqual` for comparisons.
  - No heavy external dependencies expected. Possibly might use a library for parsing raw body if needed (but we can just require the user to supply the raw body, so not necessarily).
  - TypeScript for type safety. Will compile to a Node-friendly output.
  - Possibly use an existing type for HTTP requests (like the types from @types/node for IncomingMessage, or define our own minimal interface).
  - Testing with Jest or Mocha.

- **Python Implementation:**

  - Use built-in `hmac` and `hashlib` for cryptography. Use `hmac.compare_digest` for constant-time compare.
  - Use Python standard library for base64 decoding (for signatures like in Stripe, which are hex not base64; Slack’s are hex as well with prefix; Twilio’s is base64; Square’s is base64).
  - JSON parsing with Python’s `json` module.
  - Possibly use `urllib.parse` to handle URL and form param sorting for Twilio.
  - Avoid heavy frameworks. Maybe use starlette’s Request object typing if writing integration for FastAPI, but not mandatory.
  - Testing with pytest.

- **Shared Knowledge:** Ensure we follow official documentation for each provider’s verification:

  - For instance, Slack and Stripe have official docs and even sample code which we’ll adhere to ensure correctness (Slack’s official pseudo-code was cited above).
  - That ensures no corners cut in security.

### Example Usage Scenario

To illustrate how it all comes together, consider a quick example in both Node and Python:

**Node Example:**

```ts
import { WebhookRouter } from "unified-webhook-router";

const router = new WebhookRouter({
  stripe: { signingSecret: process.env.STRIPE_SIGNING_SECRET },
  github: { secret: process.env.GITHUB_WEBHOOK_SECRET },
  slack: { signingSecret: process.env.SLACK_SIGNING_SECRET },
});

// Register handlers
router.on("stripe", "checkout.session.completed", async (event) => {
  // event.payload would be a Stripe Session object
  console.log(
    `Payment completed for session ${event.payload.id}, customer ${event.payload.customer}`
  );
  // Perform post-payment logic, e.g., mark order as paid.
});

router.on("github", "push", (event) => {
  const repo = event.payload.repository.full_name;
  console.log(
    `Received a push to repository ${repo}, commits: ${event.payload.commits.length}`
  );
  // Trigger CI pipeline or other actions...
});

// Slack example: handle a specific slash command
router.on("slack", "/deploy", (event) => {
  // Slack slash commands might use the command text as event.type or we detect by payload.command
  const user = event.payload.user_name;
  console.log(`Slack command /deploy invoked by ${user}`);
  // Return a message to Slack as response
  return { text: `Deployment started by ${user}!` };
});

// Plug router into an Express app
app.post("/webhooks", express.raw({ type: "*/*" }), (req, res) => {
  router.handle(req, res);
});
```

The above sets up three handlers and passes all webhooks to the unified endpoint. The router will sort out whether it’s a Stripe, GitHub, or Slack request and call the right code.

**Python Example (using Flask):**

```python
from unified_webhook_router import WebhookRouter

router = WebhookRouter({
    'stripe': { 'signing_secret': os.environ['STRIPE_SIGNING_SECRET'] },
    'github': { 'secret': os.environ['GITHUB_WEBHOOK_SECRET'] },
    'slack': { 'signing_secret': os.environ['SLACK_SIGNING_SECRET'] }
})

@router.on('stripe', 'checkout.session.completed')
def on_checkout_session(event):
    session = event['payload']  # a dict of Stripe session
    print(f"Checkout session {session['id']} completed, customer {session['customer']}")
    # ... further processing ...

@router.on('github', 'push')
def on_push(event):
    repo = event['payload']['repository']['full_name']
    print(f"Push event on repo {repo}")
    # ... further processing ...

@router.on('slack', '/deploy')
def on_slack_deploy(event):
    user = event['payload'].get('user_name')
    print(f"/deploy by {user}")
    # respond with a message to Slack
    return {"text": f"Deployment started by {user}!"}

# Flask route integration
from flask import request, make_response

@app.route('/webhooks', methods=['POST'])
def webhooks():
    # The router will handle verification and dispatch
    try:
        result = router.handle_request(request)  # This could return data to send or None
    except InvalidWebhookError as e:
        # automatically returns 400 if invalid
        return make_response("Invalid webhook", 400)
    # If result is not None, assume it's a response to send
    if result is not None:
        # e.g., Slack command response (a dict to return as JSON)
        return result, 200  # Flask can convert dict to JSON
    else:
        return "", 200  # default empty response
```

_Note:_ The Python snippet assumes our library provides a similar `router.on` decorator or method for registering. The integration shows catching an exception for invalid webhook (the library would raise on verification failure).

These examples are for illustration; final syntax might differ slightly but will be along these lines. The key point is that integration is concise and the library hides the heavy lifting.

## Conclusion

The Unified Webhook Router is poised to significantly streamline how developers integrate with third-party webhooks. By abstracting the common tasks of verification, parsing, and routing, it eliminates boilerplate and improves security uniformly across services. Small teams will benefit from faster integration of new services (“just plug it into the router”) and confidence that best practices (like signature checks and replay prevention) are handled by default. The dual availability in TypeScript/Node and Python covers a large segment of web development, and the framework-agnostic, serverless-compatible approach means it can be adopted in everything from a traditional monolith to a modern serverless architecture.

By delivering a comprehensive, extensible solution, Unified Webhook Router addresses a clear gap in the developer toolkit. It will reduce integration mistakes, save development time, and provide a consistent interface to deal with the ever-growing list of SaaS webhooks that modern applications rely on.

With this PRD as a guide, the development of Unified Webhook Router will focus on correctness, security, and developer experience, ensuring a robust 1.0 release that developers can trust for their critical webhook integrations.

**Sources:**

- Square Developer Docs – importance of validating and discarding unverified webhooks
- Square Developer Docs – use of HMAC-SHA256 and constant-time comparison for webhook signatures
- Slack API Documentation – verifying request signatures and using a 5-minute timestamp tolerance to prevent replay attacks
- Stripe Webhook Security (via Wecasa engineering blog) – signature contains timestamp and a default 5-minute validity window to mitigate replays
- WorkOS Blog – discussion of webhook security and the need for verification to ensure authenticity

import os
from flask import Flask, request, jsonify, make_response
from unified_webhook_router import WebhookRouter, WebhookEvent
from unified_webhook_router.types import InvalidWebhookError

app = Flask(__name__)

# Initialize the webhook router with provider configurations
router = WebhookRouter({
    'stripe': {
        'signing_secret': os.environ.get('STRIPE_SIGNING_SECRET', '')
    },
    'github': {
        'secret': os.environ.get('GITHUB_WEBHOOK_SECRET', ''),
        'algorithm': 'sha256'
    },
    'slack': {
        'signing_secret': os.environ.get('SLACK_SIGNING_SECRET', '')
    },
    'twilio': {
        'auth_token': os.environ.get('TWILIO_AUTH_TOKEN', '')
    },
    'square': {
        'signature_key': os.environ.get('SQUARE_SIGNATURE_KEY', ''),
        'notification_url': 'https://example.com/webhooks'
    }
})


# Register webhook handlers using decorators
@router.on('stripe', 'checkout.session.completed')
def handle_stripe_checkout(event: WebhookEvent):
    session = event.payload
    print(f"Stripe checkout completed: {session['id']}")
    print(f"Customer: {session.get('customer')}")
    # Process the checkout session


@router.on('stripe', 'payment_intent.succeeded')
def handle_stripe_payment(event: WebhookEvent):
    payment_intent = event.payload
    print(f"Stripe payment succeeded: {payment_intent['id']}")
    print(f"Amount: {payment_intent['amount']} {payment_intent['currency']}")
    # Process the payment


@router.on('github', 'push')
def handle_github_push(event: WebhookEvent):
    repo = event.payload['repository']['full_name']
    commits = len(event.payload.get('commits', []))
    print(f"GitHub push to {repo}: {commits} commits")
    # Trigger CI/CD pipeline


@router.on('github', 'pull_request')
def handle_github_pr(event: WebhookEvent):
    action = event.payload['action']
    pr_number = event.payload['pull_request']['number']
    print(f"GitHub PR #{pr_number} {action}")
    # Handle pull request event


@router.on('slack', '/deploy')
def handle_slack_deploy(event: WebhookEvent):
    user = event.payload.get('user_name')
    text = event.payload.get('text', '')
    print(f"Slack command /deploy invoked by {user}: {text}")
    
    # Return a response to Slack
    return {
        'text': f"Deployment started by {user}!",
        'response_type': 'in_channel'
    }


@router.on('twilio', 'message.received')
def handle_twilio_sms(event: WebhookEvent):
    from_number = event.payload.get('From')
    message_body = event.payload.get('Body')
    print(f"SMS received from {from_number}: {message_body}")
    # Process incoming SMS


@router.on('square', 'payment.updated')
def handle_square_payment(event: WebhookEvent):
    payment = event.payload.get('data', {}).get('object', {}).get('payment', {})
    print(f"Square payment updated: {payment.get('id')}")
    # Update payment status


# Wildcard handler for all unhandled Stripe events
@router.on('stripe', '*')
def handle_stripe_other(event: WebhookEvent):
    print(f"Unhandled Stripe event: {event.type}")


# Flask route for webhooks
@app.route('/webhooks', methods=['POST'])
async def webhooks():
    try:
        # The router will handle verification and dispatch
        result = await router.handle_request(request)
        
        # If result is not None, return it as response
        if result is not None:
            if isinstance(result, dict):
                return jsonify(result), 200
            else:
                return str(result), 200
        else:
            return '', 200
            
    except InvalidWebhookError as e:
        # Return appropriate error response
        return make_response(str(e), 400)
    except Exception as e:
        # Log the error
        app.logger.error(f"Webhook processing error: {e}")
        return make_response('Internal server error', 500)


if __name__ == '__main__':
    app.run(port=3000, debug=True)
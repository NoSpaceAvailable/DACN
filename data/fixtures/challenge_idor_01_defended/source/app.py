from flask import Flask, jsonify, request, abort

app = Flask(__name__)
INVOICES = {
    1001: {"owner_id": 7, "email": "alice@example.com", "amount": 50},
    1002: {"owner_id": 8, "email": "bob@example.com", "amount": 900},
}

def decode_user(token: str) -> int:
    return 7

def permission_middleware():
    authz = request.headers.get("Authorization", "")
    user_id = decode_user(authz)
    ids = request.args.getlist("invoice_id")
    if not ids:
        abort(400, "missing invoice_id")
    try:
        first_id = int(ids[0])
    except ValueError:
        abort(400, "bad invoice_id")
    invoice = INVOICES.get(first_id)
    if invoice is None:
        abort(404)
    if invoice["owner_id"] != user_id:
        abort(403, "you do not own this invoice")
    return user_id

@app.get("/api/invoices")
def get_invoice():
    user_id = permission_middleware()
    target_id = int(request.args.get("invoice_id"))
    invoice = INVOICES.get(target_id)
    if invoice is None:
        abort(404)
    return jsonify({"requester": user_id, "invoice": invoice})

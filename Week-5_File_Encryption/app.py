from flask import Flask, request, send_file
from flask_cors import CORS
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from io import BytesIO

app = Flask(__name__)
CORS(app)

def get_cipher(password: str):
    password = password.encode()
    salt = b'static_salt'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    if 'file' not in request.files:
        return {"error": "No file uploaded"}, 400

    uploaded_file = request.files['file']
    password = request.form.get('password')
    if not password:
        return {"error": "No password provided"}, 400

    cipher = get_cipher(password)

    file_data = uploaded_file.read()

    if not file_data:
        return {"error": "Uploaded file is empty"}, 400

    encrypted_data = cipher.encrypt(file_data)

    encrypted_stream = BytesIO(encrypted_data)
    encrypted_stream.seek(0)

    return send_file(
        encrypted_stream,
        as_attachment=True,
        download_name='encrypted_file.enc',
        mimetype='application/octet-stream'
    )

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    if 'file' not in request.files:
        return {"error": "No file uploaded"}, 400

    uploaded_file = request.files['file']
    password = request.form.get('password')
    if not password:
        return {"error": "No password provided"}, 400

    cipher = get_cipher(password)

    encrypted_data = uploaded_file.read()

    if not encrypted_data:
        return {"error": "Uploaded file is empty"}, 400

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception:
        return {"error": "Wrong password or corrupted file"}, 400

    decrypted_stream = BytesIO(decrypted_data)
    decrypted_stream.seek(0)

    return send_file(
        decrypted_stream,
        as_attachment=True,
        download_name='decrypted_file',
        mimetype='application/octet-stream'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)

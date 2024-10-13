import asyncio
import pathlib
import ssl
import websockets
from mnemonic import Mnemonic
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os, pyotp
import uuid, string, random, hashlib, jwt, datetime

from flask import Flask, make_response


app = Flask(__name__)


gunicorn.SERVER = ""
server_secret = None
infrastructure_name = "external_c2_01"
product_version = f"xnova v0.0.1 - [{infrastructure_name}]"

known_operators = {}
known_jwt = {}
CONNECTIONS = {}

def message_send(message):
    try:
        key = bytes.fromhex(server_secret)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()

        iv = os.urandom(algorithms.AES.block_size // 8)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return iv + ciphertext
    except:
        pass

def message_receive(encrypted_message):
    try:
        key = bytes.fromhex(server_secret)
        iv = encrypted_message[:algorithms.AES.block_size // 8]
        ciphertext = encrypted_message[algorithms.AES.block_size // 8:]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_message = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(padded_message) + unpadder.finalize()

        return decrypted_message.decode()
    except:
        pass

@app.after_request
def changeserver(response):
    print(response.headers)
    response.headers['Server'] = ''
    return response

@app.route("/")
def hello():
    return "Olá, mundo!"

@app.errorhandler(404)
def not_found_error(error):
    resp = make_response('')
    resp.status_code = 404

    return resp

@app.errorhandler(500)
def internal_server_error(error):
    resp = make_response('')
    resp.status_code = 404

    return resp

async def initial_communication(websocket, path):
    global known_jwt
    message = await websocket.recv()
    token = websocket.request_headers.get("Authorization", "")
    secret_key = secrets.token_urlsafe(32)

    # check if session are valid.

    if token != "":
        print("token found...")
        for user_data, jwt_token in known_jwt.items():
            if jwt_token['jwt'] == token:
                try:
                    decoded_payload = jwt.decode(token, secret_key, algorithms=["HS256"])
                    exp_timestamp = decoded_payload.get("exp", 0)
                    current_timestamp = int(datetime.datetime.utcnow().timestamp())

                    if exp_timestamp < current_timestamp:
                        print(" expired token.")
                except jwt.InvalidTokenError:
                    print(" invalid token.")

                except jwt.ExpiredSignatureError:
                    print(" expired signrature.")
                
    
    # check if credentials are valid.
    # try:
    print(message_receive(message))
    credentials = message_receive(message).split(":")

    for user_id, user_data in known_operators.items():
        if user_data['username'] == credentials[0] and hashlib.sha512(credentials[1].encode("utf-8")).hexdigest() == user_data['password']:

            payload = {
                    "sub": user_id,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
                }

            token = jwt.encode(payload, secret_key, algorithm="HS256")
            print(token)
            known_jwt = {user_id:{"jwt":token}}

            await websocket.send(message_send("authenticated"))
        
    await websocket.send(message_send(product_version))

async def main():
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=pathlib.Path("./certificate.pem"),  # Substitua pelo caminho do seu certificado
        keyfile=pathlib.Path("./key.pem"),   # Substitua pelo caminho da sua chave privada
    )

    async with websockets.serve(
        initial_communication, "localhost", 8765, ssl=ssl_context
    ):
        await asyncio.Future()  # run forever


def generate_random_username(length=25):
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


if __name__ == "__main__":
    random_bytes = secrets.token_bytes(32)
    server_secret = random_bytes.hex()

    os.environ['FLASK_ENV'] = 'production'

    print(f"server secret: {server_secret}")
    random_uuid = str(uuid.uuid4())
    operator_password = secrets.token_bytes(16).hex()
    operator_username = generate_random_username()
    operator_totp = pyotp.random_base32()

    known_operators[random_uuid] = {"username":operator_username, "password":hashlib.sha512(operator_password.encode("utf-8")).hexdigest(), "totp":operator_totp, "last_seen":None, "history":None, "first_use":0, "jwt":None}
    print(f"default admin operator:\n  username: {operator_username}\n  password (change after first use): {operator_password}\n  totp: {operator_totp}\n")
    print(f"\npython3 xnova.py --remote 127.0.0.1:8765 --username {operator_username} --password {operator_password} --cert ./server/certificate.pem --c2pass {server_secret} --2fa 000\n")

    print(known_operators)

    certfile = './server-cert.pem'
    keyfile = './server-key.pem'
    cafile = './ca-cert.pem'

    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_3)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile)
    context.load_cert_chain(certfile, keyfile)
    app.config['SERVER_NAME'] = None

    app.run(debug=False, ssl_context=context, port=3921)

    asyncio.run(main())
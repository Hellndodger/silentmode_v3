import socket
import threading
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import rsa

# Генеруємо RSA ключі
public_key, private_key = rsa.newkeys(1024)
public_friend = None

# Прапорець для визначення активності чату
chat_active = True

print(r"""
 ________  ___  ___       _______   ________   _________  _____ ______   ________  ________  _______      
|\   ____\|\  \|\  \     |\  ___ \ |\   ___  \|\___   ___\\   _ \  _   \|\   __  \|\   ___ \|\  ___ \     
\ \  \___|\ \  \ \  \    \ \   __/|\ \  \\ \  \|___ \  \_\ \  \\\__\ \  \ \  \|\  \ \  \_|\ \ \   __/|    
 \ \_____  \ \  \ \  \    \ \  \_|/_\ \  \\ \  \   \ \  \ \ \  \\|__| \  \ \  \\\  \ \  \ \\ \ \  \_|/__  
  \|____|\  \ \  \ \  \____\ \  \_|\ \ \  \\ \  \   \ \  \ \ \  \    \ \  \ \  \ \  \ \  \_\\ \ \  \_|\ \ 
    ____\_\  \ \__\ \_______\ \_______\ \__\\ \__\   \ \__\ \ \__\    \ \__\ \_______\ \_______\ \_______| 
   |\_________\|__|\|_______|\|_______|\|__| \|__|    \|__|  \|__|     \|__|\|_______|\|_______|\|_______| 
   \|_________|                                                                                           
""")
print("Welcome to the Silentmode v3, hope you'll have a good time using this product :> ")
choice = input("To host conversation type 1, to connect to the conversation type 2 : ")

def print_connection_status(status):
    print(f"\n[STATUS] {status}\n")

if choice == "1":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8887))  
    server.listen()
    print_connection_status("Please wait for a client to connect...(please dont leave app at that time, your friend would be really upset about it)")
    
    client, _ = server.accept()
    print_connection_status("Client connected.")
    client.send(public_key.save_pkcs1("PEM"))  # Надсилаємо свій відкритий ключ
    public_friend = rsa.PublicKey.load_pkcs1(client.recv(1024))

    # Генеруємо та надсилаємо симетричний ключ
    aes_key = os.urandom(16)  # 128-бітний AES ключ
    encrypted_aes_key = rsa.encrypt(aes_key, public_friend)
    client.send(encrypted_aes_key)  # Надсилаємо зашифрований AES ключ
    print_connection_status("AES key sent, yippie")
    
elif choice == "2":
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", 8887))  
    public_friend = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public_key.save_pkcs1("PEM"))
    
    # Отримуємо та дешифруємо AES ключ
    encrypted_aes_key = client.recv(1024)
    aes_key = rsa.decrypt(encrypted_aes_key, private_key)
    print_connection_status("AES key has been received and decrypted, congrats />")

else:
    exit()

# Функція для додавання наповнювача
def pad(data):
    block_size = algorithms.AES.block_size // 8
    padding_length = block_size - len(data) % block_size
    return data + bytes([padding_length] * padding_length)

# Функція для видалення наповнювача
def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

# Функція для шифрування AES
def encrypt_message(key, plaintext):
    iv = os.urandom(16)  # Генеруємо випадковий IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(plaintext.encode())
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Додаємо IV до початку шифротексту

# Функція для дешифрування AES
def decrypt_message(key, iv_and_ciphertext):
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded_data).decode()

# Функція для надсилання повідомлень
def send_message(sock):
    global chat_active
    while chat_active:
        message = input("You: ")
        if message.lower() == "exit":
            exit_message = "User has exited the chat. Please exit the program as well."
            print_connection_status("You have exited the chat, hope you come back until I download 1231903 trojans on your pc)))")
            sock.send(encrypt_message(aes_key, exit_message))  # Надсилаємо повідомлення про вихід
            sock.close()  # Закриваємо з'єднання
            chat_active = False  # Завершуємо чат
            break
        encrypted = encrypt_message(aes_key, message)
        sock.send(encrypted)  # Надсилаємо зашифроване повідомлення
        print("Sent: " + message)

# Функція для отримання повідомлень
def receive_message(sock):
    global chat_active
    while chat_active:
        try:
            data = sock.recv(1024 + 16)  # Отримуємо зашифроване повідомлення
            if not data:  # Якщо дані відсутні, з'єднання закрито
                break
            message = decrypt_message(aes_key, data)
            
            # Перевіряємо, чи це повідомлення про вихід
            if isinstance(message, bytes):  # Перевіряємо, чи це байти
                message = message.decode()  # Декодуємо лише якщо це байти
            
            if message == "User has exited the chat. Please exit the program as well.":
                print("\nChat friend has exited the chat. Please exit the program as well.")
                chat_active = False
                break
            
            print(f"\nChat friend: {message}\nYou: ", end="")  # Додаємо "You: " для введення наступного повідомлення
        except Exception as e:
            print(f"\nError receiving message: {e}")
            break
    chat_active = False  # Завершуємо чат при виникненні помилки

# Запускаємо потоки для обміну повідомленнями
threading.Thread(target=send_message, args=(client,)).start()
threading.Thread(target=receive_message, args=(client,)).start()

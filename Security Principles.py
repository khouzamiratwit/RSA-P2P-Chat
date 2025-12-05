# -*- coding: utf-8 -*-
"""
Created on Wed Nov 12 11:30:25 2025
@author: Robert Khouzami
"""

import socket, threading, re, struct
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Ask the user if they want to host the chat or connect to it
role = input("Type 'host' to start server or 'connect' to join: ").strip().lower()
my_label, peer_label = ("Client 1", "Client 2") if role == "host" else ("Client 2", "Client 1")

# Generate RSA keypair (private + public key)
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub  = priv.public_key()

# Convert public key to bytes so it can be sent over TCP
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# If hosting, wait for a client and exchange public keys
if role == "host":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind(("0.0.0.0", 8081))
    s.listen(1)
    print("[*] Waiting for connection...")
    conn, addr = s.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print(f"[*] Connected with {addr}")
    conn.sendall(pub_pem)              # send our public key
    peer_pub_pem = conn.recv(4096)     # receive their public key

# If connecting, connect to server and exchange public keys
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect(("127.0.0.1", 8081))
    peer_pub_pem = s.recv(4096)        # receive host's public key
    s.sendall(pub_pem)                 # send our public key
    conn = s

# Convert the received public key back to a usable RSA object
peer_pub = serialization.load_pem_public_key(peer_pub_pem)
print(f"[*] RSA handshake complete. You are {my_label}.\n")

# Read exactly N bytes from the socket (TCP may not give everything at once)
def read_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf

# Send a length-prefixed message so receiver knows how many bytes to read
def send_frame(sock, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

# Receive one full framed ciphertext
def recv_frame(sock) -> bytes:
    (length,) = struct.unpack(">I", read_exact(sock, 4))  # read message length
    return read_exact(sock, length)                       # read the message

# Calculate how many plaintext bytes RSA-OAEP can hold (about 190 bytes)
def rsa_max_plain_bytes(pubkey):
    key_bytes = pubkey.key_size // 8
    h = hashes.SHA256().digest_size
    overhead = 2 * h + 2
    return key_bytes - overhead

MAX_PLAIN = rsa_max_plain_bytes(peer_pub)

# Makes printing thread-safe so text doesn't overlap
print_lock = threading.Lock()
def safe_print(block):
    with print_lock:
        print(f"\n{block}\n")
        print(f"{my_label}: ", end="", flush=True)

msg_id = 0
# Encrypt and send a message (split into chunks if too large)
def send_message(txt: str):
    global msg_id

    txt = re.sub(r"^(Client\s*[12]\s*:\s*)", "", txt.strip(), flags=re.I)  # strip labels
    if not txt:
        return

    b = txt.encode("utf-8")

    # Break message into RSA-sized chunks
    chunk_size = MAX_PLAIN - 20
    parts = [b[i:i+chunk_size] for i in range(0, len(b), chunk_size)]
    total = len(parts)

    msg_id += 1  # each message gets a new ID

    for idx, chunk in enumerate(parts, 1):
        # Prefix chunk with header so receiver can reassemble
        header = f"{msg_id}|{idx}|{total}|".encode()
        payload = header + chunk

        # Encrypt the chunk with the peer’s public key
        ct = peer_pub.encrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        send_frame(conn, ct)  # send ciphertext through TCP

# Buffer to store partial chunks until full message is received
recv_buf = defaultdict(lambda: {"total": None, "parts": {}})

# Background thread that constantly listens for incoming messages
def recv_loop():
    while True:
        try:
            ct = recv_frame(conn)  # read encrypted chunk

            # Decrypt the chunk
            data = priv.decrypt(
                ct,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Try to parse header (msgid|index|total|)
            try:
                a, b, c, remainder = data.split(b"|", 3)
                mid, idx, total = int(a), int(b), int(c)

                buf = recv_buf[mid]
                buf["total"] = total
                buf["parts"][idx] = remainder

                # If we have all chunks, reassemble the full message
                if len(buf["parts"]) == total:
                    assembled = b"".join(buf["parts"][i] for i in range(1, total+1))
                    text = assembled.decode("utf-8", "replace").strip()
                    if text:
                        safe_print(f"{peer_label}: {text}")
                    del recv_buf[mid]

            # If no header, just print the decrypted text
            except Exception:
                safe_print(f"{peer_label}: {data.decode('utf-8','replace').strip()}")

        except (ConnectionError, OSError):
            break   # stop if connection is closed
        except Exception:
            continue # ignore bad chunks

# Start the receiving thread
threading.Thread(target=recv_loop, daemon=True).start()

# Main loop: user types messages, program encrypts + sends them
while True:
    try:
        msg = input(f"{my_label}: ")
    except EOFError:
        break
    send_message(msg)

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
from datetime import datetime, timedelta
import hashlib
import secrets

# ===== CRYPTO =====
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature

# ===== JWT =====
from jose import JWTError, jwt

app = FastAPI(title="Security Service", version="STELLA")

# =====================================================
# JWT CONFIG
# =====================================================
SECRET_KEY = os.environ.get("JWT_SECRET", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
security = HTTPBearer()

# =====================================================
# STORAGE
# =====================================================
BASE_DIR = "storage"
KEYS_DIR = os.path.join(BASE_DIR, "keys")
INBOX_DIR = os.path.join(BASE_DIR, "inbox")
PDF_DIR = os.path.join(BASE_DIR, "pdfs")
AES_KEY_FILE = os.path.join(BASE_DIR, "aes.key")
CHACHA_KEY_FILE = os.path.join(BASE_DIR, "chacha.key")

for d in [BASE_DIR, KEYS_DIR, INBOX_DIR, PDF_DIR]:
    os.makedirs(d, exist_ok=True)

# =====================================================
# CORS
# =====================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================
# HELPER
# =====================================================
def load_public_key(username: str):
    key_path = os.path.join(KEYS_DIR, f"{username}_pub.pem")
    hash_path = os.path.join(KEYS_DIR, f"{username}_pub.hash")

    if not os.path.exists(key_path):
        return None

    key_data = open(key_path, "rb").read()

    if os.path.exists(hash_path):
        stored = open(hash_path, "rb").read()
        if hashlib.sha256(key_data).digest() != stored:
            raise HTTPException(500, "Public key integrity failed")

    return serialization.load_pem_public_key(key_data)

def save_public_key(username: str, key_data: bytes):
    serialization.load_pem_public_key(key_data)
    open(os.path.join(KEYS_DIR, f"{username}_pub.pem"), "wb").write(key_data)
    open(os.path.join(KEYS_DIR, f"{username}_pub.hash"), "wb").write(
        hashlib.sha256(key_data).digest()
    )

def load_aes_key():
    if not os.path.exists(AES_KEY_FILE):
        open(AES_KEY_FILE, "wb").write(AESGCM.generate_key(256))
    return open(AES_KEY_FILE, "rb").read()

def load_chacha_key():
    if not os.path.exists(CHACHA_KEY_FILE):
        open(CHACHA_KEY_FILE, "wb").write(ChaCha20Poly1305.generate_key())
    return open(CHACHA_KEY_FILE, "rb").read()

def encrypt(data: bytes, cipher: str):
    nonce = secrets.token_bytes(12)
    if cipher == "chacha":
        c = ChaCha20Poly1305(load_chacha_key())
    else:
        c = AESGCM(load_aes_key())
    return nonce + c.encrypt(nonce, data, None)

def decrypt(data: bytes, cipher: str):
    nonce, ct = data[:12], data[12:]
    if cipher == "chacha":
        c = ChaCha20Poly1305(load_chacha_key())
    else:
        c = AESGCM(load_aes_key())
    return c.decrypt(nonce, ct, None)

def create_token(username: str):
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(auth.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        raise HTTPException(401, "Invalid or expired token")

def list_users():
    return [
        f.replace("_pub.pem", "")
        for f in os.listdir(KEYS_DIR)
        if f.endswith("_pub.pem")
    ]

# =====================================================
# ENDPOINTS
# =====================================================
@app.get("/")
def index():
    return {"status": "ok", "version": "STELLA"}

@app.get("/users")
def users():
    return {"users": list_users()}

@app.post("/store")
async def store(username: str = Form(...), file: UploadFile = File(...)):
    save_public_key(username, await file.read())
    return {"status": "stored", "username": username}

@app.post("/login")
async def login(username: str = Form(...), signature_hex: str = Form(...)):
    pub = load_public_key(username)
    if not pub:
        raise HTTPException(404, "User not found")

    sig = bytes.fromhex(signature_hex)
    msg = b"LOGIN"

    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, msg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise HTTPException(400, "Unsupported key")
    except InvalidSignature:
        raise HTTPException(401, "Invalid signature")

    return {"access_token": create_token(username), "token_type": "bearer"}

@app.post("/verify")
async def verify(
    username: str = Form(...),
    message: str = Form(...),
    signature_hex: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    pub = load_public_key(username)
    if not pub:
        raise HTTPException(404, "User not found")

    sig = bytes.fromhex(signature_hex)
    msg = message.encode()

    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, msg)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise HTTPException(400, "Unsupported key")
    except InvalidSignature:
        return {"valid": False}

    return {"valid": True}

@app.post("/relay")
async def relay(
    recipient: str = Form(...),
    message: str = Form(...),
    cipher: str = Form("aes"),
    sender: str = Depends(get_current_user)
):
    if not load_public_key(recipient):
        raise HTTPException(404, "Recipient not found")

    payload = f"[{sender}] {message}".encode()
    encrypted = encrypt(payload, cipher)

    inbox = os.path.join(INBOX_DIR, f"{recipient}.bin")
    with open(inbox, "ab") as f:
        f.write(len(encrypted).to_bytes(4, "big") + encrypted)

    return {"status": "sent"}

@app.get("/inbox")
async def inbox(cipher: str = "aes", user: str = Depends(get_current_user)):
    path = os.path.join(INBOX_DIR, f"{user}.bin")
    if not os.path.exists(path):
        return {"messages": []}

    messages = []
    with open(path, "rb") as f:
        while True:
            l = f.read(4)
            if not l:
                break
            data = f.read(int.from_bytes(l, "big"))
            messages.append(decrypt(data, cipher).decode())

    return {"messages": messages}

@app.post("/upload-pdf")
async def upload_pdf(
    file: UploadFile = File(...),
    signature_hex: str = Form(...),
    cipher: str = Form("aes"),
    user: str = Depends(get_current_user)
):
    content = await file.read()
    pub = load_public_key(user)

    sig = bytes.fromhex(signature_hex)

    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig, content)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, content, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, content, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise HTTPException(401, "Invalid signature")

    encrypted = encrypt(content, cipher)
    name = f"{user}_{datetime.utcnow().timestamp()}.enc"
    open(os.path.join(PDF_DIR, name), "wb").write(encrypted)

    return {"status": "uploaded", "file": name}

@app.get("/pdfs")
async def list_pdfs(user: str = Depends(get_current_user)):
    files = [f for f in os.listdir(PDF_DIR) if f.startswith(user)]
    return {"files": files}
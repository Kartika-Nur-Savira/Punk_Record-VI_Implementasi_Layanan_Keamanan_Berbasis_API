# client.py – Minimal Secure Client (Asymmetric Signature)
# Support: ED25519, EC (SECP256K1), RSA 2048

from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os

# =========================
# KEY GENERATION
# =========================
def gen_ed25519():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()

def gen_ec():
    priv = ec.generate_private_key(ec.SECP256K1())
    return priv, priv.public_key()

def gen_rsa():
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return priv, priv.public_key()

# =========================
# SAVE KEYS
# =========================
def save_private_key(priv, filename):
    with open(filename, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

def save_public_key(pub, filename):
    with open(filename, "wb") as f:
        f.write(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# =========================
# SIGN FUNCTION
# =========================
def sign_message(priv, message: bytes) -> str:
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        sig = priv.sign(message)
    elif isinstance(priv, ec.EllipticCurvePrivateKey):
        sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    elif isinstance(priv, rsa.RSAPrivateKey):
        sig = priv.sign(message, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("Unsupported key type")
    return sig.hex()

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    KEY_DIR = "keys"
    os.makedirs(KEY_DIR, exist_ok=True)

    username = input("Username: ").strip() or "user"
    algo = input("Algorithm [1=ED25519, 2=EC, 3=RSA]: ").strip()

    if algo == "2":
        priv, pub = gen_ec()
    elif algo == "3":
        priv, pub = gen_rsa()
    else:
        priv, pub = gen_ed25519()

    priv_file = os.path.join(KEY_DIR, f"{username}_priv.pem")
    pub_file = os.path.join(KEY_DIR, f"{username}_pub.pem")

    save_private_key(priv, priv_file)
    save_public_key(pub, pub_file)

    login_sig = sign_message(priv, b"LOGIN")

    print("\nRESULT")
    print("username:", username)
    print("public_key:", pub_file)
    print("login_signature:", login_sig)

    msg = input("\nMessage to sign (optional): ").strip()
    if msg:
        msg_sig = sign_message(priv, msg.encode())
        print("message_signature:", msg_sig)

    pdf_path = input("\nPath PDF to sign (optional): ").strip()

    if pdf_path:
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        pdf_sig = sign_message(priv, pdf_bytes)
        print("pdf_signature:", pdf_sig)


"""
Utilidades PEM para claves post-quantum.
Implementa el formato RFC 7468 (ASCII Armor / PEM).

Cifrado de claves privadas:
  Algoritmo KDF : scrypt  (N=2^17, r=8, p=1)  → clave AES-256 de 32 B
  Cifrado       : AES-256-GCM (autenticado)
  Payload       : salt(16B) | nonce(12B) | ciphertext+tag
"""

import base64
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# --- Parámetros scrypt ---
_SCRYPT_N   = 2 ** 17   # 131 072  → ~128 MB RAM, fuerte contra fuerza bruta
_SCRYPT_R   = 8
_SCRYPT_P   = 1
_SALT_LEN   = 16
_NONCE_LEN  = 12
_KEY_LEN    = 32


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=_KEY_LEN, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(key_bytes: bytes, password: str) -> bytes:
    """Cifra bytes de clave privada con scrypt + AES-256-GCM.

    Devuelve: salt(16B) | nonce(12B) | ciphertext+GCM_tag
    """
    salt  = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    aes_key = _derive_key(password, salt)
    ciphertext = AESGCM(aes_key).encrypt(nonce, key_bytes, None)
    return salt + nonce + ciphertext


def decrypt_private_key(payload: bytes, password: str) -> bytes:
    """Descifra payload producido por encrypt_private_key.

    Raises ValueError si la contraseña es incorrecta o el payload está corrupto.
    """
    salt       = payload[:_SALT_LEN]
    nonce      = payload[_SALT_LEN : _SALT_LEN + _NONCE_LEN]
    ciphertext = payload[_SALT_LEN + _NONCE_LEN :]
    aes_key = _derive_key(password, salt)
    try:
        return AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Contraseña incorrecta o clave privada corrupta.")


_LINE_LENGTH = 64


def encode_pem(label: str, data: bytes) -> str:
    """
    Codifica datos binarios en formato PEM.

    Args:
        label: etiqueta del bloque, ej. "ML-KEM-768 PUBLIC KEY"
        data:  bytes a codificar

    Returns:
        String PEM con cabecera, cuerpo Base64 y pie.
    """
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i:i + _LINE_LENGTH] for i in range(0, len(b64), _LINE_LENGTH)]
    body = "\n".join(lines)
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


def decode_pem(pem_data: str) -> tuple[str, bytes]:
    """
    Decodifica un bloque PEM.

    Args:
        pem_data: string PEM

    Returns:
        (label, bytes) donde label es la etiqueta del bloque.

    Raises:
        ValueError si el formato PEM es inválido.
    """
    match = re.search(
        r"-----BEGIN (.+?)-----\n(.+?)\n-----END \1-----",
        pem_data,
        re.DOTALL,
    )
    if not match:
        raise ValueError("Formato PEM inválido.")

    label = match.group(1)
    body  = match.group(2).replace("\n", "")
    return label, base64.b64decode(body)


def load_pem_file(path) -> tuple[str, bytes]:
    """Lee un fichero PEM y devuelve (label, bytes)."""
    from pathlib import Path
    return decode_pem(Path(path).read_text())

"""
Utilidades PEM para claves post-quantum.
Implementa el formato RFC 7468 (ASCII Armor / PEM).
"""

import base64
import re


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

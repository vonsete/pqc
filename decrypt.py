"""
Descifrado de fichero con ML-KEM + AES-256-GCM
===============================================
Uso:
    python decrypt.py <fichero.pem> <clave_privada.pem>

Ejemplo:
    python decrypt.py documento.pdf.pem ~/.kyber/mlkem_secret.pem

Genera: <fichero> (sin la extensión .pem)
"""

import getpass
import sys
import struct
import oqs
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pem_utils import load_pem_file, decrypt_private_key


def descifrar_fichero(ruta_cifrada: str, ruta_clave_priv: str):
    fichero_enc = Path(ruta_cifrada)
    clave_priv_path = Path(ruta_clave_priv)

    if not fichero_enc.exists():
        print(f"Error: fichero no encontrado: {fichero_enc}")
        sys.exit(1)

    if not clave_priv_path.exists():
        print(f"Error: clave privada no encontrada: {clave_priv_path}")
        sys.exit(1)

    # 1. Leer clave privada desde PEM (cifrada o en claro)
    label_key, key_payload = load_pem_file(clave_priv_path)
    if "ML-KEM" not in label_key:
        print(f"Error: se esperaba una clave ML-KEM, encontrado: {label_key}")
        sys.exit(1)

    variante = label_key.split()[0]  # "ML-KEM-1024 ENCRYPTED PRIVATE KEY" → "ML-KEM-1024"

    if "ENCRYPTED" in label_key:
        password = getpass.getpass("Contraseña de la clave privada: ")
        try:
            secret_key = decrypt_private_key(key_payload, password)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        secret_key = key_payload

    # 2. Leer y decodificar el fichero cifrado desde PEM
    label_enc, payload = load_pem_file(fichero_enc)
    if "ENCRYPTED FILE" not in label_enc:
        print(f"Error: el fichero no parece un fichero cifrado: {label_enc}")
        sys.exit(1)

    # 3. Desempaquetar el payload binario
    #    [2B len_kem_ct][kem_ct][12B nonce][datos_cifrados]
    offset = 0
    len_kem_ct = struct.unpack_from(">H", payload, offset)[0]
    offset += 2

    kem_ciphertext = payload[offset:offset + len_kem_ct]
    offset += len_kem_ct

    nonce = payload[offset:offset + 12]
    offset += 12

    datos_cifrados = payload[offset:]

    # 4. Decapsular la clave simétrica con la clave privada
    with oqs.KeyEncapsulation(variante, secret_key) as kem:
        shared_secret = kem.decap_secret(kem_ciphertext)

    # 5. Descifrar con AES-256-GCM
    aes = AESGCM(shared_secret)
    try:
        datos = aes.decrypt(nonce, datos_cifrados, None)
    except Exception:
        print("Error: descifrado fallido. Clave incorrecta o fichero corrupto.")
        sys.exit(1)

    # 6. Escribir fichero descifrado (eliminar la última extensión .pem)
    salida = fichero_enc.with_suffix("")
    if salida.exists():
        print(f"Advertencia: sobreescribiendo {salida}")
    salida.write_bytes(datos)

    print(f"Fichero cifrado   : {fichero_enc}  ({fichero_enc.stat().st_size} B)")
    print(f"Fichero descifrado: {salida}  ({len(datos)} B)")
    print(f"Algoritmo KEM     : {variante}")
    print(f"Cifrado simétrico : AES-256-GCM")
    print(f"Integridad        : OK (tag GCM verificado)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python decrypt.py <fichero.pem> <clave_privada.pem>")
        sys.exit(1)

    descifrar_fichero(sys.argv[1], sys.argv[2])

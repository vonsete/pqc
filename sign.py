"""
Firma digital de ficheros con ML-DSA-87
========================================
Uso:
    python sign.py <fichero> <clave_privada.pem>

Ejemplo:
    python sign.py documento.pdf ~/.kyber/mldsa_secret.pem

Genera: <fichero>.sig.pem  (firma en formato ASCII armor)
"""

import getpass
import sys
import oqs
from pathlib import Path
from pem_utils import load_pem_file, encode_pem, decrypt_private_key


def firmar_fichero(ruta_fichero: str, ruta_clave_priv: str):
    fichero = Path(ruta_fichero)
    clave_priv_path = Path(ruta_clave_priv)

    if not fichero.exists():
        print(f"Error: fichero no encontrado: {fichero}")
        sys.exit(1)

    if not clave_priv_path.exists():
        print(f"Error: clave privada no encontrada: {clave_priv_path}")
        sys.exit(1)

    # 1. Leer clave privada desde PEM (cifrada o en claro)
    label, key_payload = load_pem_file(clave_priv_path)
    if "ML-DSA" not in label:
        print(f"Error: se esperaba una clave ML-DSA, encontrado: {label}")
        sys.exit(1)

    variante = label.split()[0]  # "ML-DSA-87 ENCRYPTED PRIVATE KEY" → "ML-DSA-87"

    if "ENCRYPTED" in label:
        password = getpass.getpass("Contraseña de la clave privada: ")
        try:
            secret_key = decrypt_private_key(key_payload, password)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        secret_key = key_payload

    # 2. Firmar el contenido del fichero
    datos = fichero.read_bytes()
    with oqs.Signature(variante, secret_key) as sig:
        firma = sig.sign(datos)

    # 3. Guardar la firma en formato PEM
    pem_label = f"{variante} SIGNATURE"
    salida = fichero.with_suffix(fichero.suffix + ".sig.pem")
    salida.write_text(encode_pem(pem_label, firma))

    print(f"Fichero firmado : {fichero}  ({len(datos)} B)")
    print(f"Firma generada  : {salida}  ({len(firma)} B)")
    print(f"Algoritmo       : {variante}")
    print()
    print("Primeras líneas de la firma:")
    for linea in salida.read_text().splitlines()[:4]:
        print(f"  {linea}")
    print("  ...")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python sign.py <fichero> <clave_privada.pem>")
        sys.exit(1)

    firmar_fichero(sys.argv[1], sys.argv[2])

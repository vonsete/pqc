"""
Cifrado de fichero con ML-KEM-768 + AES-256-GCM
================================================
Uso:
    python encrypt.py <fichero> <clave_publica.pem>

Ejemplo:
    python encrypt.py documento.pdf ~/.kyber/mlkem_public.pem

Genera: <fichero>.pem  (salida en formato ASCII armor)

Formato interno (binario empaquetado, luego codificado en Base64/PEM):
    [2 B  longitud ciphertext KEM]
    [N B  ciphertext KEM        ]   ← encapsulación de la clave AES
    [12 B nonce AES-GCM         ]
    [M B  datos cifrados + tag  ]   ← fichero cifrado con AES-256-GCM
"""

import sys
import os
import struct
import oqs
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pem_utils import load_pem_file, encode_pem


def cifrar_fichero(ruta_fichero: str, ruta_clave_pub: str):
    fichero = Path(ruta_fichero)
    clave_pub_path = Path(ruta_clave_pub)

    if not fichero.exists():
        print(f"Error: fichero no encontrado: {fichero}")
        sys.exit(1)

    if not clave_pub_path.exists():
        print(f"Error: clave pública no encontrada: {clave_pub_path}")
        sys.exit(1)

    # 1. Leer clave pública desde PEM
    label, public_key = load_pem_file(clave_pub_path)
    if "ML-KEM" not in label:
        print(f"Error: se esperaba una clave ML-KEM, encontrado: {label}")
        sys.exit(1)

    variante = label.split()[0]  # "ML-KEM-768 PUBLIC KEY" → "ML-KEM-768"

    # 2. Encapsular clave simétrica con la clave pública del receptor
    with oqs.KeyEncapsulation(variante) as kem:
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

    # 3. Cifrar el fichero con AES-256-GCM
    nonce = os.urandom(12)
    aes = AESGCM(shared_secret)
    datos = fichero.read_bytes()
    datos_cifrados = aes.encrypt(nonce, datos, None)

    # 4. Empaquetar todo en un bloque binario
    #    [2B len_kem_ct][kem_ct][12B nonce][datos_cifrados]
    payload = (
        struct.pack(">H", len(kem_ciphertext))
        + kem_ciphertext
        + nonce
        + datos_cifrados
    )

    # 5. Codificar el payload en PEM y escribir el fichero de salida
    pem_label = f"{variante} ENCRYPTED FILE"
    salida = fichero.with_suffix(fichero.suffix + ".pem")
    salida.write_text(encode_pem(pem_label, payload))

    print(f"Fichero original : {fichero}  ({len(datos)} B)")
    print(f"Fichero cifrado  : {salida}  ({salida.stat().st_size} B)")
    print(f"Algoritmo KEM    : {variante}")
    print(f"Cifrado simétrico: AES-256-GCM")
    print(f"Clave pública    : {clave_pub_path}")
    print()
    print("Primeras líneas del fichero cifrado:")
    for linea in salida.read_text().splitlines()[:4]:
        print(f"  {linea}")
    print("  ...")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python encrypt.py <fichero> <clave_publica.pem>")
        sys.exit(1)

    cifrar_fichero(sys.argv[1], sys.argv[2])

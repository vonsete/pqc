"""
Verificación de firma digital con ML-DSA
=========================================
Uso:
    python verify.py <fichero> <firma.sig.pem> <clave_publica.pem>

Ejemplo:
    python verify.py documento.pdf documento.pdf.sig.pem ~/.kyber/mldsa_public.pem
"""

import sys
import oqs
from pathlib import Path
from pem_utils import load_pem_file


def verificar_firma(ruta_fichero: str, ruta_firma: str, ruta_clave_pub: str):
    fichero = Path(ruta_fichero)
    firma_path = Path(ruta_firma)
    clave_pub_path = Path(ruta_clave_pub)

    for ruta in (fichero, firma_path, clave_pub_path):
        if not ruta.exists():
            print(f"Error: fichero no encontrado: {ruta}")
            sys.exit(1)

    # 1. Leer clave pública desde PEM
    label_key, public_key = load_pem_file(clave_pub_path)
    if "ML-DSA" not in label_key:
        print(f"Error: se esperaba una clave ML-DSA, encontrado: {label_key}")
        sys.exit(1)

    variante = label_key.split()[0]  # "ML-DSA-87 PUBLIC KEY" → "ML-DSA-87"

    # 2. Leer firma desde PEM
    label_sig, firma = load_pem_file(firma_path)
    if "SIGNATURE" not in label_sig:
        print(f"Error: el fichero no contiene una firma válida: {label_sig}")
        sys.exit(1)

    # 3. Leer datos del fichero original
    datos = fichero.read_bytes()

    # 4. Verificar la firma
    with oqs.Signature(variante) as sig:
        valida = sig.verify(datos, firma, public_key)

    # 5. Resultado
    print(f"Fichero    : {fichero}  ({len(datos)} B)")
    print(f"Firma      : {firma_path}  ({len(firma)} B)")
    print(f"Clave      : {clave_pub_path}")
    print(f"Algoritmo  : {variante}")
    print()
    if valida:
        print("FIRMA VÁLIDA — el fichero es auténtico e íntegro.")
    else:
        print("FIRMA INVÁLIDA — el fichero fue modificado o la clave es incorrecta.")
        sys.exit(2)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python verify.py <fichero> <firma.sig.pem> <clave_publica.pem|nombre_contacto>")
        sys.exit(1)

    from keyring import resolve_dsa_key, KeyringError
    try:
        ruta_clave = resolve_dsa_key(sys.argv[3])
    except KeyringError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    verificar_firma(sys.argv[1], sys.argv[2], str(ruta_clave))

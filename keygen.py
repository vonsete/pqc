"""
Generación de claves Post-Quantum en formato PEM
  ML-KEM-1024  (intercambio de claves)   → FIPS 203  Nivel 5 (~AES-256)
  ML-DSA-87    (firma digital)           → FIPS 204  Nivel 5

Las claves se guardan en ~/.kyber/ con permisos:
  Directorio   : 700 (solo el usuario)
  Clave pública: 444 (lectura para todos)
  Clave privada: 400 (solo lectura para el usuario)

Las claves PRIVADAS se cifran con AES-256-GCM derivando la clave
mediante scrypt desde la contraseña introducida por el usuario.
"""

import getpass
import oqs
import os
import stat
import sys
from pathlib import Path
from pem_utils import encode_pem, encrypt_private_key


KEY_DIR = Path.home() / ".kyber"


def preparar_directorio(path: Path):
    if not path.exists():
        path.mkdir(mode=0o700)
        print(f"[DIR] Creado: {path}")
    else:
        permisos = stat.S_IMODE(path.stat().st_mode)
        if permisos != 0o700:
            path.chmod(0o700)
            print(f"[DIR] Permisos corregidos a 700: {path}")
        else:
            print(f"[DIR] OK (700): {path}")


def guardar_pem(path: Path, pem: str, es_privada: bool):
    """Escribe un fichero PEM con los permisos correctos."""
    modo = 0o400 if es_privada else 0o444
    # Si ya existe con permisos de solo lectura, eliminarlo antes de escribir
    if path.exists():
        path.chmod(0o600)
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, modo)
    with os.fdopen(fd, "w") as f:
        f.write(pem)
    path.chmod(modo)


def verificar_permisos(path: Path, esperado: int):
    real = stat.S_IMODE(path.stat().st_mode)
    estado = "OK" if real == esperado else f"ADVERTENCIA (esperado {oct(esperado)})"
    print(f"  {path.name:<30} {oct(real)}  {estado}")


def pedir_password() -> str:
    """Solicita y confirma la contraseña para cifrar las claves privadas."""
    while True:
        pwd = getpass.getpass("Contraseña para proteger las claves privadas: ")
        if not pwd:
            print("Error: la contraseña no puede estar vacía.", file=sys.stderr)
            continue
        confirmacion = getpass.getpass("Confirmar contraseña: ")
        if pwd != confirmacion:
            print("Error: las contraseñas no coinciden. Inténtalo de nuevo.", file=sys.stderr)
            continue
        return pwd


# --- Preparar directorio ---
preparar_directorio(KEY_DIR)

# --- Solicitar contraseña ---
password = pedir_password()
print("Derivando clave desde contraseña (scrypt N=131072)… esto puede tardar unos segundos.")

# --- ML-KEM ---
with oqs.KeyEncapsulation("ML-KEM-1024") as kem:
    mlkem_pub  = kem.generate_keypair()
    mlkem_priv = kem.export_secret_key()

mlkem_priv_cifrada = encrypt_private_key(mlkem_priv, password)
guardar_pem(KEY_DIR / "mlkem_public.pem",  encode_pem("ML-KEM-1024 PUBLIC KEY",           mlkem_pub),          es_privada=False)
guardar_pem(KEY_DIR / "mlkem_secret.pem",  encode_pem("ML-KEM-1024 ENCRYPTED PRIVATE KEY", mlkem_priv_cifrada), es_privada=True)
print(f"[ML-KEM-1024]  pública: {len(mlkem_pub)} B | privada: {len(mlkem_priv)} B (cifrada: {len(mlkem_priv_cifrada)} B)")

# --- ML-DSA ---
with oqs.Signature("ML-DSA-87") as sig:
    mldsa_pub  = sig.generate_keypair()
    mldsa_priv = sig.export_secret_key()

mldsa_priv_cifrada = encrypt_private_key(mldsa_priv, password)
guardar_pem(KEY_DIR / "mldsa_public.pem",  encode_pem("ML-DSA-87 PUBLIC KEY",           mldsa_pub),          es_privada=False)
guardar_pem(KEY_DIR / "mldsa_secret.pem",  encode_pem("ML-DSA-87 ENCRYPTED PRIVATE KEY", mldsa_priv_cifrada), es_privada=True)
print(f"[ML-DSA-87]    pública: {len(mldsa_pub)} B | privada: {len(mldsa_priv)} B (cifrada: {len(mldsa_priv_cifrada)} B)")

# --- Verificación de permisos ---
print(f"\nVerificación de permisos en {KEY_DIR}:")
verificar_permisos(KEY_DIR / "mlkem_public.pem", 0o444)
verificar_permisos(KEY_DIR / "mlkem_secret.pem", 0o400)
verificar_permisos(KEY_DIR / "mldsa_public.pem", 0o444)
verificar_permisos(KEY_DIR / "mldsa_secret.pem", 0o400)

# --- Muestra ejemplo del formato ---
print(f"\nEjemplo de clave pública ML-KEM-1024 (primeras líneas):")
pem_ejemplo = (KEY_DIR / "mlkem_public.pem").read_text().splitlines()
for linea in pem_ejemplo[:4]:
    print(f"  {linea}")
print("  ...")

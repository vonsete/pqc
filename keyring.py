"""
Keyring de claves públicas post-quantum.

Almacena claves públicas ML-KEM y ML-DSA de contactos en:
    ~/.kyber/keyring/<nombre>/mlkem_public.pem  (444)
    ~/.kyber/keyring/<nombre>/mldsa_public.pem  (444)

CLI:
    python keyring.py add <nombre> --kem <fichero.pem> [--dsa <fichero.pem>]
    python keyring.py list
    python keyring.py show <nombre>
    python keyring.py remove <nombre>
"""

import argparse
import os
import re
import shutil
import stat
import sys
from pathlib import Path

from pem_utils import load_pem_file


KEYRING_DIR = Path.home() / ".kyber" / "keyring"


class KeyringError(Exception):
    pass


def _validar_nombre(nombre: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", nombre):
        raise KeyringError(
            f"Nombre '{nombre}' no válido. "
            "Solo se permiten letras, dígitos, '-' y '_' (máximo 64 caracteres)."
        )


def _validar_clave_publica_pem(fichero: str, tipo_esperado: str) -> tuple[str, bytes]:
    """Valida un fichero PEM de clave pública.

    Args:
        fichero: ruta al fichero PEM
        tipo_esperado: "ML-KEM" o "ML-DSA"

    Returns:
        (label, data)

    Raises:
        KeyringError si la validación falla.
    """
    path = Path(fichero)

    # 1. Fichero existe
    if not path.exists():
        raise KeyringError(f"Fichero no encontrado: {path}")

    # 2. Formato PEM válido
    try:
        label, data = load_pem_file(path)
    except ValueError as e:
        raise KeyringError(f"Formato PEM inválido en {path}: {e}")

    # 3. Label NO contiene "PRIVATE" ni "ENCRYPTED"
    if "PRIVATE" in label or "ENCRYPTED" in label:
        raise KeyringError(
            f"No se pueden añadir claves privadas al keyring. "
            f"El fichero contiene: '{label}'"
        )

    # 4. Label contiene tipo_esperado
    if tipo_esperado not in label:
        raise KeyringError(
            f"Se esperaba una clave {tipo_esperado}, "
            f"pero el fichero contiene: '{label}'"
        )

    # 5. Label contiene "PUBLIC KEY"
    if "PUBLIC KEY" not in label:
        raise KeyringError(
            f"El fichero no contiene una clave pública. Label: '{label}'"
        )

    return label, data


def _guardar_clave_publica(src: Path, dst: Path) -> None:
    """Copia un fichero de clave pública con permisos 444."""
    if dst.exists():
        dst.chmod(0o600)
        dst.unlink()
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o444)
    with os.fdopen(fd, "wb") as f:
        f.write(src.read_bytes())
    dst.chmod(0o444)


def _preparar_keyring_dir() -> None:
    parent = KEYRING_DIR.parent  # ~/.kyber
    if not parent.exists():
        parent.mkdir(mode=0o700)
    if not KEYRING_DIR.exists():
        KEYRING_DIR.mkdir(mode=0o700)


def _variante_desde_label(label: str) -> str:
    """Extrae la variante del algoritmo del label PEM.

    "ML-KEM-1024 PUBLIC KEY" → "ML-KEM-1024"
    """
    return label.split()[0]


def resolve_kem_key(nombre_o_path: str) -> Path:
    """Resuelve una clave KEM pública desde nombre de contacto o ruta directa.

    Si termina en .pem → devuelve Path directo.
    Si no → busca ~/.kyber/keyring/<nombre>/mlkem_public.pem.

    Raises KeyringError si no existe.
    """
    if nombre_o_path.endswith(".pem"):
        path = Path(nombre_o_path)
        if not path.exists():
            raise KeyringError(f"Fichero de clave no encontrado: {path}")
        return path

    ruta = KEYRING_DIR / nombre_o_path / "mlkem_public.pem"
    if not ruta.exists():
        raise KeyringError(
            f"Contacto '{nombre_o_path}' no encontrado en el keyring "
            f"(buscado en {KEYRING_DIR})."
        )
    return ruta


def resolve_dsa_key(nombre_o_path: str) -> Path:
    """Resuelve una clave DSA pública desde nombre de contacto o ruta directa.

    Si termina en .pem → devuelve Path directo.
    Si no → busca ~/.kyber/keyring/<nombre>/mldsa_public.pem.

    Raises KeyringError si no existe.
    """
    if nombre_o_path.endswith(".pem"):
        path = Path(nombre_o_path)
        if not path.exists():
            raise KeyringError(f"Fichero de clave no encontrado: {path}")
        return path

    ruta = KEYRING_DIR / nombre_o_path / "mldsa_public.pem"
    if not ruta.exists():
        raise KeyringError(
            f"Contacto '{nombre_o_path}' no encontrado en el keyring "
            f"(buscado en {KEYRING_DIR})."
        )
    return ruta


# ---------------------------------------------------------------------------
# Subcomandos CLI
# ---------------------------------------------------------------------------

def cmd_add(args) -> None:
    nombre = args.nombre
    _validar_nombre(nombre)

    # Validar clave KEM (requerida)
    label_kem, data_kem = _validar_clave_publica_pem(args.kem, "ML-KEM")

    # Validar clave DSA si se proporciona
    label_dsa, data_dsa = None, None
    if args.dsa:
        label_dsa, data_dsa = _validar_clave_publica_pem(args.dsa, "ML-DSA")

    # Crear directorio del contacto
    _preparar_keyring_dir()
    contacto_dir = KEYRING_DIR / nombre
    if not contacto_dir.exists():
        contacto_dir.mkdir(mode=0o700)

    # Copiar claves
    _guardar_clave_publica(Path(args.kem), contacto_dir / "mlkem_public.pem")
    if args.dsa:
        _guardar_clave_publica(Path(args.dsa), contacto_dir / "mldsa_public.pem")

    print(f"Contacto '{nombre}' añadido al keyring.")
    variante_kem = _variante_desde_label(label_kem)
    print(f"  [KEM] mlkem_public.pem   {variante_kem:<12}  ({len(data_kem)} B)")
    if label_dsa:
        variante_dsa = _variante_desde_label(label_dsa)
        print(f"  [DSA] mldsa_public.pem   {variante_dsa:<12}  ({len(data_dsa)} B)")


def cmd_list(args) -> None:
    _preparar_keyring_dir()

    contactos = sorted(d for d in KEYRING_DIR.iterdir() if d.is_dir())

    print(f"Contactos en el keyring ({KEYRING_DIR}/):\n")
    for contacto_dir in contactos:
        print(f"  {contacto_dir.name}")

        kem_path = contacto_dir / "mlkem_public.pem"
        if kem_path.exists():
            try:
                label, _ = load_pem_file(kem_path)
                print(f"    KEM : {_variante_desde_label(label)}")
            except Exception:
                print("    KEM : (error al leer)")
        else:
            print("    KEM : (no disponible)")

        dsa_path = contacto_dir / "mldsa_public.pem"
        if dsa_path.exists():
            try:
                label, _ = load_pem_file(dsa_path)
                print(f"    DSA : {_variante_desde_label(label)}")
            except Exception:
                print("    DSA : (error al leer)")
        else:
            print("    DSA : (no disponible)")

        print()

    print(f"{len(contactos)} contacto(s).")


def cmd_show(args) -> None:
    nombre = args.nombre
    _validar_nombre(nombre)

    contacto_dir = KEYRING_DIR / nombre
    if not contacto_dir.exists():
        print(f"Error: contacto '{nombre}' no encontrado en el keyring.", file=sys.stderr)
        sys.exit(1)

    print(f"Contacto: {nombre}")
    print(f"Directorio: {contacto_dir}/\n")

    for filename, tipo in [("mlkem_public.pem", "KEM"), ("mldsa_public.pem", "DSA")]:
        path = contacto_dir / filename
        if path.exists():
            try:
                label, data = load_pem_file(path)
                variante = _variante_desde_label(label)
                perms = oct(stat.S_IMODE(path.stat().st_mode))[2:]
                print(f"  [{tipo}] {filename}   {variante:<12}  {len(data)} B   permisos: {perms}")
            except Exception as e:
                print(f"  [{tipo}] {filename}   (error al leer: {e})")
        else:
            print(f"  [{tipo}] {filename}   (no disponible)")


def cmd_remove(args) -> None:
    nombre = args.nombre
    _validar_nombre(nombre)

    contacto_dir = KEYRING_DIR / nombre
    if not contacto_dir.exists():
        print(f"Error: contacto '{nombre}' no encontrado en el keyring.", file=sys.stderr)
        sys.exit(1)

    respuesta = input(
        f"¿Eliminar contacto '{nombre}' y todas sus claves? [s/N]: "
    ).strip().lower()
    if respuesta != "s":
        print("Operación cancelada.")
        return

    shutil.rmtree(contacto_dir)
    print(f"Contacto '{nombre}' eliminado del keyring.")


# ---------------------------------------------------------------------------
# Entrada principal
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="keyring.py",
        description="Keyring de claves públicas post-quantum (ML-KEM / ML-DSA)",
    )
    subparsers = parser.add_subparsers(dest="comando", metavar="comando")
    subparsers.required = True

    # add
    p_add = subparsers.add_parser("add", help="Añadir un contacto al keyring")
    p_add.add_argument("nombre", help="Nombre del contacto")
    p_add.add_argument("--kem", required=True, metavar="fichero.pem",
                       help="Clave pública ML-KEM del contacto")
    p_add.add_argument("--dsa", required=False, metavar="fichero.pem",
                       help="Clave pública ML-DSA del contacto")
    p_add.set_defaults(func=cmd_add)

    # list
    p_list = subparsers.add_parser("list", help="Listar contactos")
    p_list.set_defaults(func=cmd_list)

    # show
    p_show = subparsers.add_parser("show", help="Mostrar detalles de un contacto")
    p_show.add_argument("nombre", help="Nombre del contacto")
    p_show.set_defaults(func=cmd_show)

    # remove
    p_remove = subparsers.add_parser("remove", help="Eliminar un contacto")
    p_remove.add_argument("nombre", help="Nombre del contacto")
    p_remove.set_defaults(func=cmd_remove)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyringError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

"""
Post-Quantum Cryptography con liboqs
====================================
Implementa ML-KEM (antes Kyber) y ML-DSA (antes Dilithium)
usando el estándar NIST FIPS 203/204.

Uso:
    python pqc_demo.py

Nota: ML-DSA NO es una variante de Kyber. Es un algoritmo de firma
digital basado en CRYSTALS-Dilithium, distinto de ML-KEM (Kyber).
"""

import oqs
import os
import hashlib


# ---------------------------------------------------------------------------
# Variantes disponibles (parámetros de seguridad NIST)
# ---------------------------------------------------------------------------
# ML-KEM:  512 → Level 1 (~AES-128), 768 → Level 3 (~AES-192), 1024 → Level 5 (~AES-256)
# ML-DSA:   44 → Level 2,             65 → Level 3,              87 → Level 5

ML_KEM_VARIANTS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
ML_DSA_VARIANTS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


# ---------------------------------------------------------------------------
# ML-KEM: Key Encapsulation Mechanism
# ---------------------------------------------------------------------------

class MLKEM:
    """
    Encapsula el flujo completo de ML-KEM:
      1. Generación de par de claves (receptor)
      2. Encapsulación de clave compartida (emisor)
      3. Decapsulación para obtener la clave compartida (receptor)
    """

    def __init__(self, variant: str = "ML-KEM-768"):
        if variant not in ML_KEM_VARIANTS:
            raise ValueError(f"Variante inválida. Opciones: {ML_KEM_VARIANTS}")
        self.variant = variant

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Genera un par de claves (pública, privada).

        Returns:
            (public_key, secret_key) en bytes
        """
        with oqs.KeyEncapsulation(self.variant) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        return public_key, secret_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """
        El emisor encapsula una clave compartida usando la clave pública del receptor.

        Args:
            public_key: clave pública del receptor

        Returns:
            (ciphertext, shared_secret) - el emisor guarda shared_secret,
            envía ciphertext al receptor
        """
        with oqs.KeyEncapsulation(self.variant) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        El receptor recupera la clave compartida usando su clave privada.

        Args:
            secret_key:  clave privada del receptor
            ciphertext:  texto cifrado recibido del emisor

        Returns:
            shared_secret: debe coincidir con la del emisor
        """
        with oqs.KeyEncapsulation(self.variant, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

    def demo(self):
        """Demostración completa del protocolo ML-KEM."""
        print(f"\n{'='*60}")
        print(f"  ML-KEM  ({self.variant})")
        print(f"{'='*60}")

        # 1. Receptor genera su par de claves
        print("\n[Receptor] Generando par de claves...")
        public_key, secret_key = self.keygen()
        print(f"  Clave pública  : {len(public_key)} bytes  → {public_key[:16].hex()}...")
        print(f"  Clave privada  : {len(secret_key)} bytes  → {secret_key[:16].hex()}...")

        # 2. Emisor encapsula la clave compartida
        print("\n[Emisor] Encapsulando clave compartida con la clave pública del receptor...")
        ciphertext, shared_secret_emisor = self.encapsulate(public_key)
        print(f"  Texto cifrado  : {len(ciphertext)} bytes  → {ciphertext[:16].hex()}...")
        print(f"  Clave compartida (emisor): {shared_secret_emisor.hex()}")

        # 3. Receptor decapsula
        print("\n[Receptor] Decapsulando para obtener la clave compartida...")
        shared_secret_receptor = self.decapsulate(secret_key, ciphertext)
        print(f"  Clave compartida (receptor): {shared_secret_receptor.hex()}")

        # 4. Verificación
        ok = shared_secret_emisor == shared_secret_receptor
        print(f"\n  ✓ Claves coinciden: {ok}")
        if not ok:
            raise RuntimeError("ERROR: Las claves compartidas no coinciden.")

        return public_key, secret_key, ciphertext, shared_secret_emisor


# ---------------------------------------------------------------------------
# ML-DSA: Digital Signature Algorithm
# ---------------------------------------------------------------------------

class MLDSA:
    """
    Encapsula el flujo completo de ML-DSA:
      1. Generación de par de claves (firmante)
      2. Firma de un mensaje (firmante)
      3. Verificación de la firma (verificador)
    """

    def __init__(self, variant: str = "ML-DSA-65"):
        if variant not in ML_DSA_VARIANTS:
            raise ValueError(f"Variante inválida. Opciones: {ML_DSA_VARIANTS}")
        self.variant = variant

    def keygen(self) -> tuple[bytes, bytes]:
        """
        Genera un par de claves (pública, privada).

        Returns:
            (public_key, secret_key) en bytes
        """
        with oqs.Signature(self.variant) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
        return public_key, secret_key

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Firma un mensaje con la clave privada.

        Args:
            secret_key: clave privada del firmante
            message:    mensaje a firmar (bytes)

        Returns:
            signature en bytes
        """
        with oqs.Signature(self.variant, secret_key) as sig:
            signature = sig.sign(message)
        return signature

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verifica una firma usando la clave pública del firmante.

        Args:
            public_key: clave pública del firmante
            message:    mensaje original
            signature:  firma a verificar

        Returns:
            True si la firma es válida, False en caso contrario
        """
        with oqs.Signature(self.variant) as sig:
            return sig.verify(message, signature, public_key)

    def demo(self):
        """Demostración completa del protocolo ML-DSA."""
        print(f"\n{'='*60}")
        print(f"  ML-DSA  ({self.variant})")
        print(f"{'='*60}")

        # 1. Firmante genera su par de claves
        print("\n[Firmante] Generando par de claves...")
        public_key, secret_key = self.keygen()
        print(f"  Clave pública : {len(public_key)} bytes  → {public_key[:16].hex()}...")
        print(f"  Clave privada : {len(secret_key)} bytes  → {secret_key[:16].hex()}...")

        # 2. Firma un mensaje
        message = b"Mensaje de prueba: Post-Quantum Cryptography con ML-DSA"
        print(f"\n[Firmante] Firmando mensaje: \"{message.decode()}\"")
        signature = self.sign(secret_key, message)
        print(f"  Firma          : {len(signature)} bytes  → {signature[:16].hex()}...")

        # 3. Verificador valida la firma
        print("\n[Verificador] Verificando firma con clave pública...")
        valid = self.verify(public_key, message, signature)
        print(f"  ✓ Firma válida : {valid}")

        # 4. Prueba con mensaje alterado (debe fallar)
        mensaje_alterado = b"Mensaje ALTERADO: ataque de manipulacion"
        valid_tampered = self.verify(public_key, mensaje_alterado, signature)
        print(f"\n[Verificador] Verificando firma sobre mensaje alterado...")
        print(f"  ✗ Firma inválida (esperado False): {valid_tampered}")

        if valid and not valid_tampered:
            print("\n  ✓ ML-DSA funciona correctamente.")
        else:
            raise RuntimeError("ERROR: Resultado inesperado en verificación.")

        return public_key, secret_key, signature


# ---------------------------------------------------------------------------
# Uso combinado: KEM + DSA → canal autenticado y secreto
# ---------------------------------------------------------------------------

def demo_canal_seguro():
    """
    Ejemplo práctico: establecer un canal seguro y autenticado.
    El receptor usa ML-KEM para acordar una clave de sesión,
    y ML-DSA para autenticar el texto cifrado enviado.
    """
    print(f"\n{'='*60}")
    print("  Canal Seguro: ML-KEM + ML-DSA")
    print(f"{'='*60}")

    # --- Infraestructura de claves ---
    kem = MLKEM("ML-KEM-768")
    dsa = MLDSA("ML-DSA-65")

    # Receptor genera par de claves KEM
    print("\n[Receptor] Generando claves KEM...")
    kem_pub, kem_priv = kem.keygen()

    # Emisor genera par de claves DSA (para autenticar)
    print("[Emisor]   Generando claves DSA...")
    dsa_pub, dsa_priv = dsa.keygen()

    # --- Emisor: encapsula + firma ---
    print("\n[Emisor] Encapsulando clave compartida...")
    ciphertext, shared_secret = kem.encapsulate(kem_pub)

    print("[Emisor] Firmando el ciphertext con su clave DSA...")
    signature = dsa.sign(dsa_priv, ciphertext)

    # --- Receptor: verifica + decapsula ---
    print("\n[Receptor] Verificando firma del emisor sobre el ciphertext...")
    es_autentico = dsa.verify(dsa_pub, ciphertext, signature)
    print(f"  ✓ Ciphertext auténtico: {es_autentico}")

    if es_autentico:
        print("[Receptor] Decapsulando para obtener la clave compartida...")
        shared_secret_receptor = kem.decapsulate(kem_priv, ciphertext)

        # Derivar clave de sesión (ej. para AES-256)
        session_key = hashlib.sha256(shared_secret_receptor).digest()
        print(f"\n  Clave de sesión AES-256: {session_key.hex()}")
        print(f"  ✓ Canal establecido correctamente.")
    else:
        print("  ERROR: ciphertext no auténtico, abortando.")


# ---------------------------------------------------------------------------
# Info de tamaños de claves/firmas
# ---------------------------------------------------------------------------

def mostrar_info():
    """Muestra el resumen de tamaños para todas las variantes."""
    print(f"\n{'='*60}")
    print("  Tamaños de claves y parámetros")
    print(f"{'='*60}")

    print("\n  ML-KEM (Key Encapsulation Mechanism):")
    print(f"  {'Variante':<15} {'Clave pública':>15} {'Clave privada':>15} {'Ciphertext':>12} {'Secreto':>10}")
    print(f"  {'-'*67}")
    for variant in ML_KEM_VARIANTS:
        with oqs.KeyEncapsulation(variant) as kem:
            d = kem.details
            print(f"  {variant:<15} {d['length_public_key']:>13} B {d['length_secret_key']:>13} B "
                  f"{d['length_ciphertext']:>10} B {d['length_shared_secret']:>8} B")

    print("\n  ML-DSA (Digital Signature Algorithm):")
    print(f"  {'Variante':<12} {'Clave pública':>15} {'Clave privada':>15} {'Firma':>10}")
    print(f"  {'-'*56}")
    for variant in ML_DSA_VARIANTS:
        with oqs.Signature(variant) as sig:
            d = sig.details
            print(f"  {variant:<12} {d['length_public_key']:>13} B {d['length_secret_key']:>13} B "
                  f"{d['length_signature']:>8} B")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Post-Quantum Cryptography — liboqs")
    print("NIST FIPS 203 (ML-KEM) + NIST FIPS 204 (ML-DSA)")

    mostrar_info()

    # Demo ML-KEM con variante estándar (nivel 3)
    kem = MLKEM("ML-KEM-768")
    kem.demo()

    # Demo ML-DSA con variante estándar (nivel 3)
    dsa = MLDSA("ML-DSA-65")
    dsa.demo()

    # Demo canal autenticado y seguro combinando ambos
    demo_canal_seguro()

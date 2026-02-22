# pqc — Post-Quantum Cryptography Toolkit

Toolkit de criptografía post-cuántica en Python basado en [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe).

Implementa los estándares NIST para criptografía resistente a computadoras cuánticas:

- **ML-KEM-1024** (NIST FIPS 203) — Key Encapsulation Mechanism, basado en CRYSTALS-Kyber
- **ML-DSA-87** (NIST FIPS 204) — Digital Signature Algorithm, basado en CRYSTALS-Dilithium

Todos las claves y ficheros cifrados se almacenan en formato **PEM ASCII armor**, compatible con herramientas estándar del ecosistema criptográfico.

---

## Changelog

### v0.3
- Nuevo módulo `keyring.py`: llavero de claves públicas de contactos (ML-KEM y ML-DSA) almacenado en `~/.kyber/keyring/`.
- `encrypt.py` y `verify.py` aceptan ahora un nombre de contacto además de una ruta de fichero `.pem`.

### v0.2
- Las claves privadas (ML-KEM y ML-DSA) se cifran en disco con **scrypt + AES-256-GCM** protegidas por contraseña. Si alguien accede al fichero `.pem` sin la contraseña, la clave privada es ilegible.
- `keygen.py` solicita una contraseña con confirmación al generar las claves.
- `decrypt.py` y `sign.py` detectan automáticamente si la clave privada está cifrada y solicitan la contraseña antes de operar.
- Compatible con claves generadas en v0.1 (sin cifrado).

### v0.1
- Generación de claves ML-KEM-1024 y ML-DSA-87 en formato PEM.
- Cifrado y descifrado de ficheros con ML-KEM + AES-256-GCM.
- Firma y verificación de ficheros con ML-DSA-87.

---

## Requisitos

- Python 3.10+
- cmake ≥ 3.20
- ninja
- gcc / build-essential

---

## Instalación

### 1. Compilar liboqs

```bash
git clone --depth 1 --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs

cmake -S /tmp/liboqs -B /tmp/liboqs/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=~/_oqs \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_USE_OPENSSL=OFF \
  -GNinja

ninja -C /tmp/liboqs/build install
```

### 2. Crear entorno virtual e instalar dependencias Python

```bash
python3 -m venv oqs_env
oqs_env/bin/pip install liboqs-python cryptography
```

### 3. Exportar la librería en cada sesión

```bash
export LD_LIBRARY_PATH=~/_oqs/lib
```

> Puedes añadir esta línea a tu `~/.bashrc` o `~/.zshrc` para no tener que repetirla.

---

## Uso

Todos los comandos asumen que estás en el directorio del proyecto y con el entorno activado:

```bash
export LD_LIBRARY_PATH=~/_oqs/lib
alias python=oqs_env/bin/python3
```

### Generar claves

Genera el par de claves ML-KEM-1024 y ML-DSA-87 en `~/.kyber/`:

```bash
python keygen.py
```

Se pedirá una contraseña para proteger las claves privadas:

```
Contraseña para proteger las claves privadas:
Confirmar contraseña:
Derivando clave desde contraseña (scrypt N=131072)… esto puede tardar unos segundos.
```

Ficheros generados:

| Fichero | Permisos | Uso |
|---|---|---|
| `~/.kyber/mlkem_public.pem` | `444` | Compartir para recibir ficheros cifrados |
| `~/.kyber/mlkem_secret.pem` | `400` | Clave privada cifrada con contraseña |
| `~/.kyber/mldsa_public.pem` | `444` | Compartir para verificar tus firmas |
| `~/.kyber/mldsa_secret.pem` | `400` | Clave privada cifrada con contraseña |

El directorio `~/.kyber/` se crea con permisos `700` (solo accesible por el usuario).

Las claves privadas se almacenan cifradas. El encabezado PEM lo indica:

```
-----BEGIN ML-KEM-1024 ENCRYPTED PRIVATE KEY-----
...
-----END ML-KEM-1024 ENCRYPTED PRIVATE KEY-----
```

### Cifrar un fichero

```bash
python encrypt.py <fichero> <clave_publica.pem|nombre_contacto>
```

Ejemplo:

```bash
python encrypt.py documento.pdf ~/.kyber/mlkem_public.pem
```

Genera `documento.pdf.pem` en el mismo directorio. Formato de salida:

```
-----BEGIN ML-KEM-1024 ENCRYPTED FILE-----
BiAHHwOKcX84mVT/FDr8fL+QslX72vEz9fT6Oxh5d3Jwt...
-----END ML-KEM-1024 ENCRYPTED FILE-----
```

### Descifrar un fichero

```bash
python decrypt.py <fichero.pem> <clave_privada.pem>
```

Ejemplo:

```bash
python decrypt.py documento.pdf.pem ~/.kyber/mlkem_secret.pem
```

Si la clave privada está cifrada (v0.2+), se pedirá la contraseña antes de descifrar:

```
Contraseña de la clave privada:
```

Recupera `documento.pdf` en el mismo directorio.

### Firmar un fichero

```bash
python sign.py <fichero> <clave_privada.pem>
```

Ejemplo:

```bash
python sign.py documento.pdf ~/.kyber/mldsa_secret.pem
```

Si la clave privada está cifrada (v0.2+), se pedirá la contraseña antes de firmar:

```
Contraseña de la clave privada:
```

Genera `documento.pdf.sig.pem` junto al fichero original:

```
-----BEGIN ML-DSA-87 SIGNATURE-----
31bXQNnhIR1Ja/Y3DuhjkQIEZjO8rQe4/py9HYin+sQ2Mwsk...
-----END ML-DSA-87 SIGNATURE-----
```

### Verificar una firma

```bash
python verify.py <fichero> <firma.sig.pem> <clave_publica.pem|nombre_contacto>
```

Ejemplo:

```bash
python verify.py documento.pdf documento.pdf.sig.pem ~/.kyber/mldsa_public.pem
```

Salida si la firma es válida:

```
Fichero    : documento.pdf  (84320 B)
Firma      : documento.pdf.sig.pem  (4627 B)
Clave      : /home/usuario/.kyber/mldsa_public.pem
Algoritmo  : ML-DSA-87

FIRMA VÁLIDA — el fichero es auténtico e íntegro.
```

Salida si el fichero fue modificado:

```
FIRMA INVÁLIDA — el fichero fue modificado o la clave es incorrecta.
```

Códigos de salida (útiles para scripting):

| Código | Significado |
|---|---|
| `0` | Firma válida |
| `1` | Error (fichero no encontrado, clave incorrecta) |
| `2` | Firma inválida (fichero manipulado) |

### Keyring de claves públicas (v0.3)

El keyring almacena las claves públicas de tus contactos en `~/.kyber/keyring/`, permitiendo usar nombres legibles (`alice`) en lugar de rutas de fichero.

#### Añadir un contacto

```bash
python keyring.py add alice --kem ruta/mlkem_public.pem --dsa ruta/mldsa_public.pem
```

Salida:

```
Contacto 'alice' añadido al keyring.
  [KEM] mlkem_public.pem   ML-KEM-1024   (1568 B)
  [DSA] mldsa_public.pem   ML-DSA-87     (2592 B)
```

La clave `--dsa` es opcional. La `--kem` es requerida.

#### Listar contactos

```bash
python keyring.py list
```

```
Contactos en el keyring (~/.kyber/keyring/):

  alice
    KEM : ML-KEM-1024
    DSA : ML-DSA-87

  bob
    KEM : ML-KEM-1024
    DSA : (no disponible)

2 contacto(s).
```

#### Mostrar detalles de un contacto

```bash
python keyring.py show alice
```

```
Contacto: alice
Directorio: /home/user/.kyber/keyring/alice/

  [KEM] mlkem_public.pem   ML-KEM-1024   1568 B   permisos: 444
  [DSA] mldsa_public.pem   ML-DSA-87     2592 B   permisos: 444
```

#### Eliminar un contacto

```bash
python keyring.py remove alice
```

```
¿Eliminar contacto 'alice' y todas sus claves? [s/N]: s
Contacto 'alice' eliminado del keyring.
```

#### Usar nombre de contacto en encrypt y verify

```bash
# Cifrar para alice (usando su nombre en lugar de la ruta del .pem)
python encrypt.py documento.pdf alice

# Verificar una firma de alice
python verify.py documento.pdf documento.pdf.sig.pem alice
```

#### Estructura en disco

```
~/.kyber/keyring/          (700)
    alice/                 (700)
        mlkem_public.pem   (444)
        mldsa_public.pem   (444)
    bob/                   (700)
        mlkem_public.pem   (444)
```

El keyring rechaza claves privadas: intentar importar un fichero con `PRIVATE` o `ENCRYPTED` en el label PEM produce un error.

---

## Cómo funciona

### Cifrado (ML-KEM + AES-256-GCM)

ML-KEM es un **KEM** (Key Encapsulation Mechanism): no cifra datos directamente, sino que establece una clave simétrica compartida de forma segura. El cifrado real del fichero se realiza con AES-256-GCM.

```
[Emisor]                                  [Receptor]
   │                                           │
   │  clave pública del receptor               │
   │◄──────────────────────────────────────────│
   │                                           │
   │  encap(pub_key) → (kem_ct, shared_secret) │
   │                                           │
   │  AES-256-GCM(shared_secret, fichero)      │
   │  → datos_cifrados                         │
   │                                           │
   │  [kem_ct | nonce | datos_cifrados]        │
   │──────────────────────────────────────────►│
   │                                           │
   │                   decap(priv_key, kem_ct) │
   │                           → shared_secret │
   │                                           │
   │        AES-256-GCM-decrypt(shared_secret) │
   │                           → fichero       │
```

El formato del payload interno (codificado en Base64/PEM):

```
┌──────────────────────────────────────────────┐
│ 2 B    longitud del ciphertext KEM           │
│ 1568 B ciphertext KEM  (ML-KEM-1024)         │
│ 12 B   nonce AES-GCM                         │
│ N B    datos cifrados + tag GCM (16 B)       │
└──────────────────────────────────────────────┘
```

### Cifrado de claves privadas (v0.2)

Las claves privadas nunca se guardan en claro. Al generarlas, se cifran con la contraseña del usuario usando:

- **KDF:** scrypt (N=131072, r=8, p=1) — requiere ~128 MB de RAM por intento, resistente a fuerza bruta por hardware especializado
- **Cifrado:** AES-256-GCM — autenticado, detecta cualquier manipulación del fichero

Estructura del payload dentro del PEM cifrado:

```
┌─────────────────────────────────────────────┐
│ 16 B   salt aleatoria (entrada a scrypt)    │
│ 12 B   nonce AES-GCM                        │
│ N B    clave privada cifrada + tag GCM      │
└─────────────────────────────────────────────┘
```

Una contraseña incorrecta produce un error de autenticación GCM antes de devolver ningún dato.

### Niveles de seguridad disponibles

| Algoritmo | Variante | Nivel NIST | Equivalencia clásica |
|---|---|---|---|
| ML-KEM | `ML-KEM-512` | 1 | ~AES-128 |
| ML-KEM | `ML-KEM-768` | 3 | ~AES-192 |
| ML-KEM | `ML-KEM-1024` | **5** | **~AES-256** |
| ML-DSA | `ML-DSA-44` | 2 | — |
| ML-DSA | `ML-DSA-65` | 3 | — |
| ML-DSA | `ML-DSA-87` | **5** | — |

Este toolkit usa las variantes de nivel 5 por defecto.

---

## Estructura del proyecto

```
pqc/
├── keygen.py       # Generación de claves PEM en ~/.kyber/
├── keyring.py      # Llavero de claves públicas de contactos
├── encrypt.py      # Cifrado de ficheros (ML-KEM + AES-256-GCM)
├── decrypt.py      # Descifrado de ficheros
├── sign.py         # Firma digital de ficheros (ML-DSA)
├── verify.py       # Verificación de firmas (ML-DSA)
├── pem_utils.py    # Codificación/decodificación PEM (RFC 7468)
└── pqc_demo.py     # Demo completo de ML-KEM y ML-DSA
```

---

## Referencias

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [Open Quantum Safe — liboqs](https://github.com/open-quantum-safe/liboqs)
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python)

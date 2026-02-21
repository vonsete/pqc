# pqc — Post-Quantum Cryptography Toolkit

Toolkit de criptografía post-cuántica en Python basado en [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe).

Implementa los estándares NIST para criptografía resistente a computadoras cuánticas:

- **ML-KEM-1024** (NIST FIPS 203) — Key Encapsulation Mechanism, basado en CRYSTALS-Kyber
- **ML-DSA-87** (NIST FIPS 204) — Digital Signature Algorithm, basado en CRYSTALS-Dilithium

Todos las claves y ficheros cifrados se almacenan en formato **PEM ASCII armor**, compatible con herramientas estándar del ecosistema criptográfico.

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

Ficheros generados:

| Fichero | Permisos | Uso |
|---|---|---|
| `~/.kyber/mlkem_public.pem` | `444` | Compartir para recibir ficheros cifrados |
| `~/.kyber/mlkem_secret.pem` | `400` | Descifrar ficheros recibidos |
| `~/.kyber/mldsa_public.pem` | `444` | Compartir para verificar tus firmas |
| `~/.kyber/mldsa_secret.pem` | `400` | Firmar documentos |

El directorio `~/.kyber/` se crea con permisos `700` (solo accesible por el usuario).

### Cifrar un fichero

```bash
python encrypt.py <fichero> <clave_publica.pem>
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

Recupera `documento.pdf` en el mismo directorio.

### Firmar un fichero

```bash
python sign.py <fichero> <clave_privada.pem>
```

Ejemplo:

```bash
python sign.py documento.pdf ~/.kyber/mldsa_secret.pem
```

Genera `documento.pdf.sig.pem` junto al fichero original:

```
-----BEGIN ML-DSA-87 SIGNATURE-----
31bXQNnhIR1Ja/Y3DuhjkQIEZjO8rQe4/py9HYin+sQ2Mwsk...
-----END ML-DSA-87 SIGNATURE-----
```

### Verificar una firma

```bash
python verify.py <fichero> <firma.sig.pem> <clave_publica.pem>
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

# EduChain - Sistema Descentralizado y Seguro de Calificaciones

**Universidad Distrital FJC**  
**Ingeniería en Telemática**  
**Asignatura: Criptología**  
**Profesor: Msc. Ing. Óscar Gabriel Espejo Mojica**
**Estudiantes: Chary , Javier Santiago Ramirez Marin, Michael Alexander Arcos Murcia
---

## 📋 Descripción del Proyecto

EduChain es un prototipo funcional de blockchain implementado en Python, diseñado específicamente para asegurar, auditar y transparentar la emisión de calificaciones académicas.

El sistema demuestra que es **matemáticamente imposible** alterar una calificación histórica sin que la red lo detecte inmediatamente.

---

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EDUCHAIN ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐        │
│  │ crypto_utils │    │ merkle_tree  │    │      BLOCKCHAIN      │
│  │     .py      │    │     .py      │    │         .py          │
│  ├──────────────┤    ├──────────────┤    ├──────────────┤        │
│  │ • SHA-256    │    │ • Build Tree │    │ • Block      │        │
│  │ • ECDSA      │    │ • Get Root   │    │ • PoW        │        │
│  │ • Firmas     │    │ • Verify     │    │ • Validate  │        │
│  └──────────────┘    └──────────────┘    └──────────────┘        │
│         │                    │                    │                │
│         └────────────────────┼────────────────────┘                │
│                              │                                      │
│                    ┌─────────▼─────────┐                           │
│                    │  smart_contract   │                           │
│                    │       .py         │                           │
│                    ├───────────────────┤                           │
│                    │ • Authorization   │                           │
│                    │ • Verify Teacher  │                           │
│                    │ • Create TX       │                           │
│                    └───────────────────┘                           │
│                              │                                      │
│                    ┌─────────▼─────────┐                           │
│                    │      demo.py      │                           │
│                    │  (4 ESCENARIOS)   │                           │
│                    └───────────────────┘                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Componentes Criptográficos Obligatorios

### 1. SHA-256 (Hash Criptográfico)

**¿Qué es?**  
SHA-256 (Secure Hash Algorithm 2) es una función hash criptográfica que produce un valor de 256 bits (64 caracteres hexadecimales).

**Propiedades:**
- **Determinista:** misma entrada → misma salida
- **Efecto avalancha:** cambio mínimo → hash completamente diferente
- **Irreversible:** no se puede obtener la entrada desde el hash
- **Colisión resistente:** difícil encontrar dos entradas con mismo hash

**En EduChain:** Cada bloque tiene su propio hash. Cambiar cualquier campo lo invalida.

```python
# Ejemplo de uso
from crypto_utils import sha256

hash_bloque = sha256("index:1|timestamp:123456|merkle:root123|...")
# Resultado: 64 caracteres hexadecimales
```

---

### 2. Árbol de Merkle

**¿Qué es?**  
El Árbol de Merkle es una estructura de datos árbol binaria que resume todas las transacciones en un bloque usando hashes.

```
                    [RAÍZ DE MERKLE]
                       /      \
              [Hash A+B]    [Hash C+D]
                /    \        /    \
          [Tx1]  [Tx2]  [Tx3]  [Tx4]
```

**Beneficios:**
- **Verificación eficiente:** probar pertenencia en O(log n)
- **Integridad:** cualquier cambio en transacciones cambia la raíz
- **Espacio:** no requiere todas las transacciones para verificación

**En EduChain:** Las transacciones de cada bloque se resumen en una raíz de 256 bits guardada en la cabecera.

```python
# Ejemplo de uso
from merkle_tree import MerkleTree

transacciones = [
    "PROF001|EST001|Calculo I|4.5",
    "PROF001|EST002|Calculo I|3.8",
]

merkle = MerkleTree(transacciones)
raiz = merkle.get_root()  # 64 caracteres hex
```

---

### 3. ECDSA (Firma Digital)

**¿Qué es?**  
ECDSA (Elliptic Curve Digital Signature Algorithm) es un algoritmo de firma digital que utiliza криптografía de curvas elípticas. Es el mismo algoritmo usado por Bitcoin.

**Curve utilizada:** secp256r1 (P-256)
- Tamaño de clave: 256 bits
- Nivel de seguridad: 128 bits (equivalente a RSA-3072)

**¿Cómo funciona?**
1. Cada usuario tiene una **clave privada** (secreto) y una **clave pública** (compartible)
2. Para firmar, se usa la clave privada
3. Para verificar, se usa la clave pública
4. Solo el poseedor de la clave privada puede crear firmas válidas

**En EduChain:** Cada nota tiene la firma del profesor. Solo su clave privada puede producirla.

```python
# Ejemplo de uso
from crypto_utils import ECDSAVerifier

# Crear par de claves
verificador = ECDSAVerifier()

# Firmar una calificación
mensaje = "PROF001|EST001|Calculo I|4.5"
firma = verificador.sign(mensaje)

# Verificar firma
es_valida = verificador.verify(mensaje, firma)
```

---

### 4. Proof of Work (PoW)

**¿Qué es?**  
Proof of Work es un mecanismo que requiere trabajo computacional para crear un bloque válido.

**En EduChain:** El hash del bloque debe iniciar con "000" (dificultad = 3).

**Proceso:**
```
1. Comenzar con nonce = 0
2. Calcular hash = SHA-256(index + timestamp + merkle_root + previous_hash + nonce)
3. Si hash inicia con "000" → ¡encontrado!
4. Si no → nonce += 1 y repetir
```

**¿Por qué es importante?**
- Evita ataques de denegación de servicio
- Hace costoso modificar el historial
- Requiere consenso computacional

```python
# El sistema busca automáticamente el nonce correcto
bloque.mine_block()  # Encuentra el nonce donde hash inicia con "000"
```

---

### 5. Smart Contract

**¿Qué es?**  
Un smart contract es un programa que ejecuta automáticamente reglas definidas. En EduChain, controla quién puede emitir calificaciones.

**Reglas del Smart Contract:**
1. Solo usuarios con rol **PROFESOR** pueden emitir transacciones
2. La clave pública debe estar registrada en el sistema
3. La firma digital debe ser válida

**En EduChain:** Solo los profesores registrados criptográficamente pueden emitir notas.

```python
# Ejemplo de uso
from smart_contract import SmartContract

sc = SmartContract()

# Registrar profesor
sc.register_professor("PROF001", "Juan Pérez", clave_publica_hex)

# Crear transacción (solo si es profesor autorizado)
tx = sc.create_transaction(profesor_verifier, "PROF001", "EST001", "Calculo", 4.5)
```

---

## 📦 Estructura del Bloque

Cada bloque contiene exactamente estos campos:

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `index` | Entero | Posición del bloque (0 = génesis) |
| `timestamp` | Float | Tiempo Unix de creación |
| `transacciones` | Lista | Registros de calificaciones |
| `merkle_root` | String (64 hex) | Raíz del árbol de Merkle |
| `hash_anterior` | String (64 hex) | Hash del bloque anterior |
| `nonce` | Entero | Valor encontrado por PoW |
| `hash` | String (64 hex) | Hash del bloque (inicia con "000") |

**⚠️ Importante:** El hash se calcula únicamente sobre la cabecera `{index, timestamp, merkle_root, hash_anterior, nonce}`, NO sobre las transacciones crudas.

---

## 🚀 Instalación y Uso

### Requisitos

```bash
pip install cryptography
```

### Ejecutar el Demo

```bash
cd EduChain_Grupo_301Distrital
python demo.py
```

El demo ejecuta los 4 escenarios obligatorios para la sustentación.

---

## 📁 Archivos del Proyecto

| Archivo | Descripción |
|---------|-------------|
| `crypto_utils.py` | SHA-256 y ECDSA |
| `merkle_tree.py` | Árbol de Merkle |
| `blockchain.py` | Bloques y cadena |
| `smart_contract.py` | Autorización de profesores |
| `demo.py` | Demo con 4 escenarios |
| `README.md` | Esta documentación |

---

## 📝 Los 4 Escenarios del Demo

### Escenario 1: Creación de la Cadena (Bloque Génesis)

- Se crea el bloque génesis (bloque 0)
- Se verifica el hash inicial "000..."
- Se muestra la cadena vacía válida

### Escenario 2: Profesor Emite Notas Válidas

- Profesor registrado crea calificaciones
- Cada calificación se firma digitalmente con ECDSA
- Se construye el árbol de Merkle
- Se mina el bloque (PoW)
- Se añade a la cadena

### Escenario 3: Ataque de Modificación Histórica

- Se intenta modificar una nota directamente
- Se demuestra que la Merkle Root no coincide
- Se demuestra que el hash del bloque no coincide
- La cadena se detecta como inválida

### Escenario 4: Intento de Emisión No Autorizada

- Estudiante intenta emitirse una nota → **RECHAZADO**
- Atacante externo intenta modificar notas → **RECHAZADO**
- Solo profesores pueden emitir calificaciones

---

## 🔒 Análisis de Seguridad

### ¿Cómo mitiga el sistema...?

#### (i) Modificación del historial?

1. **Hash SHA-256:** Cualquier cambio en transacciones → hash diferente
2. **Árbol de Merkle:** Cambios modifican la raíz
3. **Proof of Work:** Necesitarías encontrar nuevo nonce
4. **Encadenamiento:** Todos los bloques siguientes también cambian

**Resultado:** Matemáticamente imposible modificar el pasado sin detección.

#### (ii) Suplantación de identidad?

1. **ECDSA:** Solo la clave privada puede crear firmas
2. **Smart Contract:** Solo acepta claves de profesores registrados
3. **Verificación:** Cada transacción se verifica криптográficamente

**Resultado:** Nadie puede hacerse pasar por un profesor.

---

## 📊 Rúbrica de Calificación

| Categoría | Peso | Criterio |
|-----------|------|-----------|
| Primitivas Criptográficas | 25% | SHA-256 + ECDSA funcionales |
| Estructura Blockchain | 25% | Bloques + Merkle + PoW |
| Smart Contract | 20% | Solo profesores autorizados |
| Informe IEEE | 15% | Documento completo |
| Sustentación | 15% | Demo en vivo |

---

## 🛠️ Licencia

Este proyecto es para fines educativos - Universidad Distrital FJC.

---

## 👥 Autores

**Grupo 301** - Proyecto Final de Criptología

---

## 📚 Referencias

- Bitcoin: A Peer-to-Peer Electronic Cash System (Satoshi Nakamoto)
- NIST FIPS 180-4 (SHA-256)
- ECDSA (Elliptic Curve Digital Signature Algorithm)
- Merkle Trees (R. Merkle, 1979)

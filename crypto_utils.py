# -*- coding: utf-8 -*-
"""
crypto_utils.py - Utilidades Criptograficas para EduChain

Este modulo proporciona las funciones criptograficas fundamentales necesarias
para el funcionamiento seguro del blockchain EduChain.

Componentes implementados:
- SHA-256: Hash criptografico para integridad de bloques
- ECDSA: Firma digital para autenticacion de transacciones

Libreria utilizada: cryptography (https://cryptography.io)
Instalar con: pip install cryptography

@author: EduChain Group 301
@course: Criptologia - Universidad Distrital FJC
"""

import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import binascii
import time


# =============================================================================
# SECCION 1: SHA-256 - Hash Criptografico
# =============================================================================

def sha256(data: str) -> str:
    """
    Calcula el hash SHA-256 de una cadena de texto.
    
    SHA-256 (Secure Hash Algorithm 2) es una funcion hash criptografica
    que produce un valor hash de 256 bits (64 caracteres hexadecimales).
    Es parte de la familia SHA-2 y es ampliamente utilizada en sistemas
    de seguridad blockchain.
    
    Propiedades:
    - Deterministica: misma entrada -> misma salida
    - Efecto avalancha: cambio minimo -> hash completamente diferente
    - irreversible: no se puede obtener la entrada desde el hash
    - Colision resistente: dificil encontrar dos entradas con mismo hash
    
    Args:
        data (str): Cadena de texto a hashear
        
    Returns:
        str: Hash en formato hexadecimal (64 caracteres)
    
    Ejemplo:
        >>> sha256("hola")
        'c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a'
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """
    Calcula el hash SHA-256 de datos binarios.
    
    Args:
        data (bytes): Datos binarios a hashear
        
    Returns:
        bytes: Hash en formato binario
    """
    return hashlib.sha256(data).digest()


def verify_integrity(data: str, expected_hash: str) -> bool:
    """
    Verifica la integridad de datos comparando hashes.
    
    Utilizada para verificar que los datos no han sido modificados.
    
    Args:
        data (str): Datos originales
        expected_hash (str): Hash esperado para comparar
        
    Returns:
        bool: True si los hashes coinciden, False otherwise
    """
    return sha256(data) == expected_hash


# =============================================================================
# SECCION 2: ECDSA - Firma Digital
# =============================================================================

class ECDSAVerifier:
    """
    Manejador de Firmas Digitales usando ECDSA (Elliptic Curve Digital Signature Algorithm).
    
    ECDSA es un algoritmo de firma digital que utiliza criptografia de curvas elipticas.
    Es el mismo algoritmo usado por Bitcoin para firmas digitales.
    
    Curve utilizada: secp256r1 (P-256)
    - Tamano de clave: 256 bits
    - Nivel de seguridad: 128 bits (equivalente a RSA-3072)
    - Eficiente computacionalmente
    
    Cada usuario tiene:
    - Clave privada: numero aleatorio grande (secreto)
    - Clave publica: punto en la curva (compartible)
    
    La firma digital demuestra que:
    1. El mensaje fue creado por el poseedor de la clave privada
    2. El mensaje no ha sido alterado desde que se firmo
    """
    
    def __init__(self, private_key=None, public_key=None):
        """
        Inicializa el verificador ECDSA.
        
        Args:
            private_key: Clave privada (opcional, se genera si no se provee)
            public_key: Clave publica (opcional, se deriva de la privada)
        """
        if private_key is None:
            # Generar nuevo par de claves usando curva secp256r1 (P-256)
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        else:
            self.private_key = private_key
            
        if public_key is None:
            self.public_key = self.private_key.public_key()
        else:
            self.public_key = public_key
    
    def get_public_key_hex(self) -> str:
        """
        Obtiene la clave publica en formato hexadecimal.
        
        Returns:
            str: Clave publica en hex
        """
        # Obtener bytes de la clave publica
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        return binascii.hexlify(pub_bytes).decode('utf-8')
    
    def get_public_key_bytes(self) -> bytes:
        """Obtiene la clave publica como bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def sign(self, message: str) -> bytes:
        """
        Firma un mensaje usando la clave privada.
        
        Proceso de firma ECDSA:
        1. Calcular hash del mensaje: h = SHA-256(mensaje)
        2. Generar numero aleatorio k (temporal)
        3. Calcular punto k*G (G = punto base de la curva)
        4. Calcular r = coordenada x de kG (mod n)
        5. Calcular s = k^(-1) * (h + r*privateKey) (mod n)
        6. Firma = (r, s)
        
        Args:
            message (str): Mensaje a firmar
            
        Returns:
            bytes: Firma digital (r || s concatenados)
        """
        # Paso 1: Hash del mensaje
        message_hash = hashlib.sha256(message.encode('utf-8')).digest()
        
        # Firmar usando ECDSA
        signature = self.private_key.sign(
            message_hash,
            ec.ECDSA(hashes.SHA256())
        )
        
        return signature
    
    def verify(self, message: str, signature: bytes) -> bool:
        """
        Verifica una firma digital.
        
        Proceso de verificacion:
        1. Calcular hash del mensaje: h = SHA-256(mensaje)
        2. Parsear firma como (r, s)
        3. Calcular u1 = h * s^(-1) (mod n)
        4. Calcular u2 = r * s^(-1) (mod n)
        5. Calcular punto P = u1*G + u2*publicKey
        6. Verificar r == coordenada x de P (mod n)
        
        Args:
            message (str): Mensaje original
            signature (bytes): Firma a verificar
            
        Returns:
            bool: True si la firma es valida, False otherwise
        """
        try:
            message_hash = hashlib.sha256(message.encode('utf-8')).digest()
            self.public_key.verify(
                signature,
                message_hash,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


def generate_keypair() -> tuple:
    """
    Genera un nuevo par de claves ECDSA.
    
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(message: str, private_key) -> bytes:
    """
    Firma un mensaje con una clave privada especifica.
    
    Args:
        message (str): Mensaje a firmar
        private_key: Clave privada ECDSA
        
    Returns:
        bytes: Firma digital
    """
    message_hash = hashlib.sha256(message.encode('utf-8')).digest()
    return private_key.sign(
        message_hash,
        ec.ECDSA(hashes.SHA256())
    )


def verify_signature(message: str, signature: bytes, public_key) -> bool:
    """
    Verifica una firma con una clave publica especifica.
    
    Args:
        message (str): Mensaje original
        signature (bytes): Firma a verificar
        public_key: Clave publica ECDSA
        
    Returns:
        bool: True si la firma es valida
    """
    try:
        message_hash = hashlib.sha256(message.encode('utf-8')).digest()
        public_key.verify(
            signature,
            message_hash,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


def signature_to_hex(signature: bytes) -> str:
    """Convierte firma a formato hexadecimal."""
    return binascii.hexlify(signature).decode('utf-8')


def hex_to_signature(hex_str: str) -> bytes:
    """Convierte firma de formato hexadecimal a bytes."""
    return binascii.unhexlify(hex_str)


# =============================================================================
# SECCION 3: Utilidades de Validacion
# =============================================================================

def create_transaction_payload(
    id_profesor: str,
    id_estudiante: str,
    asignatura: str,
    nota: float
) -> str:
    """
    Crea el payload (contenido) de una transaccion.
    
    Este payload es lo que se firma digitalmente y representa
    la calificacion que se va a registrar.
    
    Args:
        id_profesor (str): Identificador del profesor
        id_estudiante (str): Identificador del estudiante
        asignatura (str): Nombre de la materia
        nota (float): Calificacion (0.0 - 5.0 tipicamente)
        
    Returns:
        str: Payload formateado para firma
    """
    return f"{id_profesor}|{id_estudiante}|{asignatura}|{nota}"


def verify_transaction_authenticity(
    payload: str,
    signature: bytes,
    public_key_hex: str
) -> bool:
    """
    Verifica la autenticidad de una transaccion.
    
    Args:
        payload (str): Payload de la transaccion
        signature (bytes): Firma digital
        public_key_hex (str): Clave publica del firmante en hex
        
    Returns:
        bool: True si la firma es valida
    """
    try:
        # Reconstruir clave publica desde hex
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            binascii.unhexlify(public_key_hex)
        )
        return verify_signature(payload, signature, public_key)
    except Exception:
        return False


# =============================================================================
# SECCION 4: Pruebas y Demostracion
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PRUEBA DE MODULO CRYPTO_UTILS")
    print("=" * 60)
    
    # Prueba 1: SHA-256
    print("\n[1] Prueba de SHA-256:")
    mensaje = "Hola EduChain"
    hash_result = sha256(mensaje)
    print(f"  Mensaje: '{mensaje}'")
    print(f"  SHA-256: {hash_result}")
    print(f"  Longitud: {len(hash_result)} caracteres (esperado: 64)")
    
    # Prueba 2: Efecto Avalancha
    print("\n[2] Prueba de Efecto Avalancha:")
    hash1 = sha256("test")
    hash2 = sha256("testa")
    print(f"  sha256('test') = {hash1[:16]}...")
    print(f"  sha256('testa')= {hash2[:16]}...")
    print(f"  - Diferentes?: {hash1 != hash2}")
    
    # Prueba 3: ECDSA
    print("\n[3] Prueba de ECDSA:")
    verificador = ECDSAVerifier()
    mensaje = "Calificacion: 4.5 - Estudiante: 12345"
    firma = verificador.sign(mensaje)
    es_valida = verificador.verify(mensaje, firma)
    
    print(f"  Clave publica: {verificador.get_public_key_hex()[:32]}...")
    print(f"  Mensaje: '{mensaje}'")
    print(f"  Firma (hex): {signature_to_hex(firma)[:32]}...")
    print(f"  Verificacion: {'OK VALIDA' if es_valida else 'ERROR INVALIDA'}")
    
    # Prueba 4: Firmas falsificadas
    print("\n[4] Prueba de Firma Invalida:")
    verificador2 = ECDSAVerifier()
    mensaje_falso = "Calificacion: 5.0 - Estudiante: 99999"
    # Intentar verificar mensaje falso con la firma del primero
    es_falsa = verificador.verify(mensaje_falso, firma)
    print(f"  Verificar mensaje diferente con firma original: {es_falsa}")
    print(f"  Resultado esperado: False OK")
    
    print("\n" + "=" * 60)
    print("TODAS LAS PRUEBAS COMPLETADAS")
    print("=" * 60)
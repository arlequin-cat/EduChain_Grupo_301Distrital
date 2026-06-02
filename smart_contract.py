# -*- coding: utf-8 -*-
"""
smart_contract.py - Contrato Inteligente para EduChain

Este modulo implementa la capa de contrato inteligente que controla
quien puede emitir calificaciones en el sistema.

El smart contract verifica que:
1. El profesor esta registrado en el sistema
2. La firma digital es valida (usa ECDSA)
3. Solo profesores autorizados pueden emitir transacciones

Mecanismo de autorizacion:
- Cada usuario tiene un par de claves ECDSA
- Las claves publicas de los profesores se registran en el sistema
- Para emitir una calificacion, el profesor debe:
  1. Crear el payload de la transaccion
  2. Firmarlo con su clave privada
  3. El smart contract verifica:
     a) Que la clave publica esta registrada como PROFESOR
     b) Que la firma es valida

@author: EduChain Group 301
@course: Criptologia - Universidad Distrital FJC
"""

import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import binascii
from crypto_utils import (
    ECDSAVerifier,
    sign_message, 
    verify_signature,
    create_transaction_payload,
    signature_to_hex,
    sha256
)
from merkle_tree import MerkleTree


class AuthorizationError(Exception):
    """Excepcion para errores de autorizacion."""
    pass


class SmartContract:
    """
    Contrato Inteligente para el sistema de calificaciones EduChain.
    
    Este contrato regula quien puede emitir calificaciones en la blockchain.
    Solo usuarios con rol "PROFESOR" y clave publica registrada pueden hacerlo.
    
    Roles disponibles:
    - PROFESOR: Puede crear transacciones (calificaciones)
    - ESTUDIANTE: Solo puede verificar sus calificaciones
    - ADMIN: Gestion del sistema (no implementado en esta version)
    """
    
    def __init__(self):
        """
        Inicializa el contrato inteligente.
        
        Crea un registro vacio de usuarios autorizados y carga
        los profesores predefinidos para el demo.
        """
        # Registro de usuarios: {public_key_hex: rol}
        self.authorized_users = {}
        
        # Registro de profesores: {id_profesor: public_key_hex}
        self.professors = {}
        
        # Registro de estudiantes (solo lectura)
        self.students = {}
        
        # Cargar profesores predefinidos para demo
        self._load_default_professors()
    
    def _load_default_professors(self):
        """
        Carga profesores predefinidos para el demo.
        
        En un sistema real, esto se haria mediante un proceso
        de registro seguro con verificacion de identidad.
        """
        # Generar claves de ejemplo para demostracion
        # En produccion, estas vendrian de un proceso de registro
        
        # Profesor 1 - Clave de demo
        prof1_key = ECDSAVerifier()
        self.register_professor(
            "PROF001",
            "Juan Perez",
            prof1_key.get_public_key_hex()
        )
        
        # Profesor 2 - Para diversidad
        prof2_key = ECDSAVerifier()
        self.register_professor(
            "PROF002", 
            "Maria Garcia",
            prof2_key.get_public_key_hex()
        )
        
        print("\n[INFO] Profesores registrados en el sistema:")
        for pid, pdata in self.professors.items():
            pk = pdata['public_key']
            print(f"   {pid}: {pdata['nombre']}")
            print(f"        PK: {pk[:32]}...")
    
    def register_professor(self, professor_id: str, nombre: str, public_key_hex: str):
        """
        Registra un profesor en el sistema.
        
        Args:
            professor_id (str): Identificador unico del profesor
            nombre (str): Nombre completo del profesor
            public_key_hex (str): Clave publica en formato hexadecimal
        """
        self.professors[professor_id] = {
            'nombre': nombre,
            'public_key': public_key_hex
        }
        self.authorized_users[public_key_hex] = 'PROFESOR'
    
    def register_student(self, student_id: str, nombre: str):
        """
        Registra un estudiante en el sistema.
        
        Los estudiantes pueden verificar sus calificaciones pero
        no pueden emitir transacciones.
        
        Args:
            student_id (str): Identificador unico del estudiante
            nombre (str): Nombre completo del estudiante
        """
        self.students[student_id] = {
            'nombre': nombre
        }
    
    def is_professor(self, public_key_hex: str) -> bool:
        """
        Verifica si una clave publica pertenece a un profesor registrado.
        
        Args:
            public_key_hex (str): Clave publica a verificar
            
        Returns:
            bool: True si es un profesor registrado
        """
        return public_key_hex in self.authorized_users and \
               self.authorized_users[public_key_hex] == 'PROFESOR'
    
    def is_authorized(self, public_key_hex: str) -> bool:
        """
        Verifica si una clave publica esta autorizada.
        
        Args:
            public_key_hex (str): Clave publica a verificar
            
        Returns:
            bool: True si tiene autorizacion
        """
        return public_key_hex in self.authorized_users
    
    def get_role(self, public_key_hex: str) -> str:
        """
        Obtiene el rol de una clave publica.
        
        Args:
            public_key_hex (str): Clave publica
            
        Returns:
            str: Rol del usuario (PROFESOR, ESTUDIANTE, etc.)
        """
        return self.authorized_users.get(public_key_hex, 'NO_AUTORIZADO')
    
    def create_transaction(
        self,
        professor_verifier: ECDSAVerifier,
        professor_id: str,
        student_id: str,
        subject: str,
        grade: float
    ) -> dict:
        """
        Crea una transaccion de calificacion valida.
        
        Este es el metodo principal que usan los profesores para
        emitir calificaciones. El contrato:
        1. Verifica que el profesor este registrado
        2. Crea el payload de la transaccion
        3. Firma digitalmente el payload
        4. Devuelve la transaccion completa
        
        Args:
            professor_verifier (ECDSAVerifier): Verificador con clave del profesor
            professor_id (str): ID del profesor
            student_id (str): ID del estudiante
            subject (str): Nombre de la materia
            grade (float): Calificacion (tipicamente 0.0 - 5.0)
            
        Returns:
            dict: Transaccion completa con firma
            
        Raises:
            AuthorizationError: Si el profesor no esta autorizado
        """
        # Verificar que el profesor esta registrado
        professor_pk = professor_verifier.get_public_key_hex()
        
        if not self.is_professor(professor_pk):
            raise AuthorizationError(
                f"Profesor {professor_id} no esta autorizado. "
                f"Clave publica no registrada."
            )
        
        # Verificar que el ID coincide con la clave registrada
        registered_pk = self.professors.get(professor_id, {}).get('public_key', '')
        if registered_pk != professor_pk:
            raise AuthorizationError(
                f"La clave publica no corresponde al profesor {professor_id}"
            )
        
        # Crear payload
        payload = create_transaction_payload(
            id_profesor=professor_id,
            id_estudiante=student_id,
            asignatura=subject,
            nota=grade
        )
        
        # Firmar payload
        signature = professor_verifier.sign(payload)
        
        # Crear transaccion completa
        transaction = {
            'payload': payload,
            'signature': signature_to_hex(signature),
            'public_key': professor_pk,
            'professor_id': professor_id,
            'student_id': student_id,
            'subject': subject,
            'grade': grade
        }
        
        return transaction
    
    def verify_transaction(self, transaction: dict) -> tuple:
        """
        Verifica la validez de una transaccion.
        
        Verifica:
        1. Que la firma es valida
        2. Que el firmante es un profesor registrado
        
        Args:
            transaction (dict): Transaccion a verificar
            
        Returns:
            tuple: (es_valida, mensaje)
        """
        try:
            payload = transaction['payload']
            signature_hex = transaction['signature']
            public_key_hex = transaction['public_key']
            
            # Verificar que es profesor
            if not self.is_professor(public_key_hex):
                return False, "Firmante no es un profesor autorizado"
            
            # Cargar clave publica
            try:
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(),
                    binascii.unhexlify(public_key_hex)
                )
            except Exception as e:
                return False, f"Error al cargar clave publica: {e}"
            
            # Verificar firma
            signature = binascii.unhexlify(signature_hex)
            is_valid = verify_signature(payload, signature, public_key)
            
            if not is_valid:
                return False, "Firma digital invalida"
            
            return True, "Transaccion valida"
            
        except Exception as e:
            return False, f"Error verificando transaccion: {e}"
    
    def attempt_transaction(
        self,
        verifier: ECDSAVerifier,
        user_id: str,
        student_id: str,
        subject: str,
        grade: float
    ) -> dict:
        """
        Intenta crear una transaccion (para demo de rechazo).
        
        Este metodo intenta crear una transaccion sin verificar
        si el usuario es profesor. Sirve para demostrar como
        el smart contract rechaza intentos no autorizados.
        
        Args:
            verifier (ECDSAVerifier): Verificador del usuario
            user_id (str): ID del usuario (profesor o estudiante)
            student_id (str): ID del estudiante
            subject (str): Materia
            grade (float): Calificacion
            
        Returns:
            dict: Transaccion (si se creo) o error
        """
        user_pk = verifier.get_public_key_hex()
        
        # Verificar rol
        if not self.is_authorized(user_pk):
            raise AuthorizationError(
                f"Usuario {user_id} no esta autorizado. "
                f"Rol: {self.get_role(user_pk)}"
            )
        
        if not self.is_professor(user_pk):
            raise AuthorizationError(
                f"Usuario {user_id} es {self.get_role(user_pk)}, "
                f"no puede emitir calificaciones. "
                f"Solo los profesores pueden hacerlo."
            )
        
        # Si llego aqui, es profesor
        return self.create_transaction(verifier, user_id, student_id, subject, grade)
    
    def verify_chain_authorization(self, chain_data: dict) -> tuple:
        """
        Verifica la autorizacion de todas las transacciones en una cadena.
        
        Args:
            chain_data (dict): Datos de la cadena de bloques
            
        Returns:
            tuple: (es_valida, lista_de_errores)
        """
        errors = []
        
        for block in chain_data.get('chain', []):
            for tx in block.get('transacciones', []):
                if isinstance(tx, dict):
                    is_valid, message = self.verify_transaction(tx)
                    if not is_valid:
                        errors.append(f"Bloque {block['index']}: {message}")
        
        return len(errors) == 0, errors
    
    def print_authorization_status(self, public_key_hex: str):
        """
        Imprime el estado de autorizacion de una clave publica.
        
        Args:
            public_key_hex (str): Clave publica a verificar
        """
        print("\n" + "=" * 30)
        print("ESTADO DE AUTORIZACION")
        print("=" * 30)
        
        if self.is_professor(public_key_hex):
            print(f"  [OK] PROFESOR AUTORIZADO")
            for pid, pdata in self.professors.items():
                if pdata['public_key'] == public_key_hex:
                    print(f"    ID: {pid}")
                    print(f"    Nombre: {pdata['nombre']}")
        elif self.is_authorized(public_key_hex):
            print(f"  [WARN] USUARIO AUTORIZADO (no profesor)")
            print(f"    Rol: {self.get_role(public_key_hex)}")
        else:
            print(f"  [ERROR] NO AUTORIZADO")
            print(f"    Esta clave publica no puede emitir calificaciones")
        
        print("=" * 60)


# =============================================================================
# PRUEBAS Y DEMOSTRACION
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PRUEBA DEL MODULO SMART_CONTRACT")
    print("=" * 60)
    
    # Crear contrato inteligente
    sc = SmartContract()
    
    # Obtener clave de un profesor registrado
    prof_pk = list(sc.professors.values())[0]['public_key']
    prof_id = list(sc.professors.keys())[0]
    
    print("\n[1] Verificacion de estado inicial:")
    sc.print_authorization_status(prof_pk)
    
    print("\n[2] Crear transaccion como profesor valido:")
    try:
        # Crear verificador con las claves del profesor
        # En el demo, necesitamos reconstruir desde la clave registrada
        professor_verifier = ECDSAVerifier()
        
        # Registrar este verificador como profesor
        test_prof_id = "TEST_PROF"
        sc.register_professor(
            test_prof_id,
            "Profesor de Prueba",
            professor_verifier.get_public_key_hex()
        )
        
        # Crear transaccion
        tx = sc.create_transaction(
            professor_verifier,
            test_prof_id,
            "EST001",
            "Calculo I",
            4.5
        )
        
        print(f"\n  [OK] Transaccion creada exitosamente")
        print(f"    Payload: {tx['payload']}")
        print(f"    Firma: {tx['signature'][:32]}...")
        
        # Verificar transaccion
        is_valid, msg = sc.verify_transaction(tx)
        print(f"    Verificacion: {'[OK] VALIDA' if is_valid else '[ERROR] INVALIDA'}")
        print(f"    Mensaje: {msg}")
        
    except AuthorizationError as e:
        print(f"  [ERROR] Error: {e}")
    
    print("\n[3] Intentar como estudiante (debe fallar):")
    try:
        # Crear claves de estudiante
        student_verifier = ECDSAVerifier()
        
        # Intentar crear transaccion
        sc.attempt_transaction(
            student_verifier,
            "EST999",
            "EST001",
            "Calculo I",
            5.0
        )
        print("  [ERROR] ERROR: No deberia haber permitido esto!")
        
    except AuthorizationError as e:
        print(f"  [OK] Correctamente rechazado: {e}")
    
    print("\n[4] Verificar profesor no registrado:")
    new_verifier = ECDSAVerifier()
    sc.print_authorization_status(new_verifier.get_public_key_hex())
    
    print("\n" + "=" * 60)
    print("TODAS LAS PRUEBAS COMPLETADAS")
    print("=" * 60)
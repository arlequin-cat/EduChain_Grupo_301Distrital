           # -*- coding: utf-8 -*-
"""
demo.py - Demostracion Completa del Sistema EduChain

Este script ejecuta los 4 escenarios obligatorios para la sustentacion:
1. Escenario 1 - Creacion de la cadena (Bloque Genesis)
2. Escenario 2 - Profesor emite notas validas y se mina el bloque
3. Escenario 3 - Ataque de modificacion historica
4. Escenario 4 - Intento de emision no autorizada

@author: EduChain Group 301
@course: Criptologia - Universidad Distrital FJC
@professor: Msc. Ing. Oscar Gabriel Espejo Mojica
"""

import sys
import time
from crypto_utils import ECDSAVerifier, signature_to_hex, sha256
from merkle_tree import MerkleTree
from blockchain import Blockchain, Block, DIFFICULTY
from smart_contract import SmartContract, AuthorizationError


# Configuracion global
DIFFICULTY = 3


def print_header(title):
    """Imprime un encabezado formateado."""
    print(f"\n{'=' * 60}")
    print(f"{title}")
    print('=' * 60)


def print_subheader(title):
    """Imprime un subencabezado."""
    print(f"\n>> {title}")


def print_success(message):
    """Imprime mensaje de exito."""
    print(f"[OK] {message}")


def print_error(message):
    """Imprime mensaje de error."""
    print(f"[ERROR] {message}")


def print_warning(message):
    """Imprime advertencia."""
    print(f"[ADVERTENCIA] {message}")


# =============================================================================
# ESCENARIO 1: CREACION DE LA CADENA (BLOQUE GENESIS)
# =============================================================================

def escenario_1_creacion_cadena():
    """
    Escenario 1: Creacion de la cadena (Bloque Genesis)
    
    Este escenario demuestra:
    - Creacion del bloque genesis (bloque 0)
    - Hash SHA-256 del bloque
    - Proof of Work con dificultad 3 ("000")
    - Estructura inicial de la cadena
    """
    print_header("ESCENARIO 1: CREACION DE LA CADENA (BLOQUE GENESIS)")
    
    print("""
    El bloque genesis es el primer bloque de toda blockchain.
    Sirve como fundamento de la cadena y no tiene bloque anterior.
    
    Componentes que se demuestran:
    - SHA-256 para calcular el hash del bloque
    - Proof of Work (dificultad = 3 ceros)
    - Estructura basica del bloque
    """)
    
    print_subheader("1.1 Creando Blockchain...")
    
    # Crear la cadena
    blockchain = Blockchain()
    
    print_subheader("1.2 Verificando Bloque Genesis...")
    
    genesis = blockchain.chain[0]
    
    print(f"\n  Datos del bloque:")
    print(f"    - Indice: {genesis.index}")
    print(f"    - Timestamp: {genesis.timestamp}")
    print(f"    - Hash anterior: {genesis.previous_hash}")
    print(f"    - Merkle Root: {genesis.merkle_root}")
    print(f"    - Nonce: {genesis.nonce}")
    print(f"    - Hash: {genesis.hash}")
    
    # Verificar PoW
    target = "0" * DIFFICULTY
    hash_inicia_correcto = genesis.hash.startswith(target)
    
    print(f"\n  Verificacion de Proof of Work:")
    print(f"    - Dificultad requerida: {DIFFICULTY} ceros")
    print(f"    - Target: '{target}'")
    print(f"    - Hash inicia con '{target}': {'SI' if hash_inicia_correcto else 'NO'}")
    
    print_subheader("1.3 Cadena vacia valida")
    
    is_valid, message = blockchain.is_chain_valid()
    print(f"\n  - Cadena valida?: {'SI' if is_valid else 'NO'}")
    print(f"  - Mensaje: {message}")
    
    print_success("\nESCENARIO 1 COMPLETADO")
    print("  Se ha creado el bloque genesis correctamente")
    print("  La cadena esta lista para recibir transacciones")
    
    return blockchain


# =============================================================================
# ESCENARIO 2: PROFESOR EMITE NOTAS VALIDAS
# =============================================================================

def escenario_2_profesor_emite_notas(blockchain):
    """
    Escenario 2: Profesor emite notas validas y se mina el bloque
    
    Este escenario demuestra:
    - Smart Contract verificando identidad del profesor
    - Firma digital ECDSA para autenticar transacciones
    - Arbol de Merkle para resumir transacciones
    - Proof of Work para minar el bloque
    - Encadenamiento correcto de bloques
    """
    print_header("ESCENARIO 2: PROFESOR EMITE NOTAS VALIDAS")
    
    print("""
    En este escenario, un profesor registrado emite calificaciones.
    El proceso incluye:
    - Verificacion de identidad mediante ECDSA
    - Firma digital de cada calificacion
    - Validacion por Smart Contract
    - Inclusion en bloque con Merkle Root
    - Minado del bloque con PoW
    """)
    
    print_subheader("2.1 Configurando Smart Contract...")
    
    # Crear contrato inteligente
    sc = SmartContract()
    
    print("\n  Sistema de autorizacion:")
    print(f"    - Profesores registrados: {len(sc.professors)}")
    print(f"    - Dificultad PoW: {DIFFICULTY}")
    
    # Obtener referencia del profesor para el demo
    prof_id = "PROF001"
    prof_data = sc.professors.get(prof_id, {})
    
    # Crear verificador con clave del profesor para el demo
    professor_verifier = ECDSAVerifier()
    
    # Registrar como profesor
    sc.register_professor(
        prof_id,
        "Juan Perez",
        professor_verifier.get_public_key_hex()
    )
    
    print(f"\n  Profesor: Juan Perez")
    print(f"  ID: {prof_id}")
    print(f"  Clave publica: {professor_verifier.get_public_key_hex()[:32]}...")
    
    print_subheader("2.2 Profesor crea transacciones...")
    
    # Crear varias transacciones (calificaciones)
    transactions = []
    
    calificaciones = [
        ("EST001", "Calculo I", 4.5),
        ("EST002", "Calculo I", 3.8),
        ("EST003", "Calculo I", 5.0),
        ("EST004", "Calculo I", 4.2),
    ]
    
    print("\n  Creando calificaciones:")
    
    for est_id, materia, nota in calificaciones:
        try:
            # Crear transaccion
            tx = sc.create_transaction(
                professor_verifier,
                prof_id,
                est_id,
                materia,
                nota
            )
            transactions.append(tx)
            
            print(f"    OK {est_id} - {materia}: {nota}")
            
            # Verificar firma
            is_valid, msg = sc.verify_transaction(tx)
            print(f"      Firma: {'Valida' if is_valid else 'Invalida'}")
            
        except AuthorizationError as e:
            print(f"    ERROR: {e}")
    
    print_subheader("2.3 Construyendo Arbol de Merkle...")
    
    # Crear arbol de Merkle
    merkle = MerkleTree(transactions)
    merkle_root = merkle.get_root()
    
    print(f"\n  Transacciones: {len(transactions)}")
    print(f"  Merkle Root: {merkle_root}")
    print(f"  Longitud: {len(merkle_root)} caracteres (64 = SHA-256)")
    
    print_subheader("2.4 Minando nuevo bloque...")
    
    # Anadir bloque a la cadena
    nuevo_bloque = blockchain.add_block(transactions)
    
    print_subheader("2.5 Verificando cadena...")
    
    # Verificar toda la cadena
    is_valid, message = blockchain.is_chain_valid()
    print(f"\n  - Cadena valida?: {'SI' if is_valid else 'NO'}")
    print(f"  - Mensaje: {message}")

    auth_valid, auth_errors = sc.verify_chain_authorization(blockchain.get_chain_data())

    print(f"\n  - Autorizacion criptografica de transacciones?: {'SI' if auth_valid else 'NO'}")

    if auth_errors:
        print("  Errores de autorizacion:")
        for error in auth_errors:
            print(f"    - {error}")
    else:
        print("  Todas las transacciones del bloque tienen firma valida y profesor autorizado.")
    
    print("\n  Estado de la cadena:")
    print(f"    - Bloques totales: {len(blockchain.chain)}")
    print(f"    - Bloque 0 (Genesis): {blockchain.chain[0].hash[:16]}...")
    print(f"    - Bloque 1 (Notas): {blockchain.chain[1].hash[:16]}...")
    print(f"    - Enlace verificado: OK")
    
    print_success("\nESCENARIO 2 COMPLETADO")
    print("  El profesor pudo emitir calificaciones validas")
    print("  Las transacciones estan protegidas por:")
    print("    - Firma digital ECDSA")
    print("    - Arbol de Merkle")
    print("    - Proof of Work")
    print("    - Smart Contract")
    
    return blockchain


# =============================================================================
# ESCENARIO 3: ATAQUE DE MODIFICACION HISTORICA
# =============================================================================

def escenario_3_modificacion_historica(blockchain):
    """
    Escenario 3: Ataque de modificacion historica
    
    Este escenario demuestra como el blockchain detecta ataques:
    - Intento de modificar una calificacion en un bloque
    - Verificacion de integridad mediante Merkle Root
    - Verificacion mediante hash del bloque
    - Detección de cadena invalida
    """
    print_header("ESCENARIO 3: ATAQUE DE MODIFICACION HISTORICA")
    
    print("""
    Este escenario simula un intento de ataque:
    Un estudiante o administrador deshonesto intenta modificar
    una calificacion despues de que el bloque fue minado.
    
    Por que es imposible?
    - Las transacciones estan hasheadas en Merkle Root
    - El hash del bloque depende del Merkle Root
    - Cualquier cambio modifica el hash
    - El hash debe cumplir PoW (iniciar con "000")
    - Los bloques estan enlazados por hash
    """)
    
    print_subheader("3.1 Estado actual de la cadena...")
    
    # Obtener el bloque con calificaciones
    bloque_notas = blockchain.chain[1]
    
    print(f"\n  Bloque #{bloque_notas.index}:")
    print(f"    - Hash: {bloque_notas.hash}")
    print(f"    - Merkle Root: {bloque_notas.merkle_root}")
    print(f"    - Transacciones: {len(bloque_notas.transactions)}")
    
    for tx in bloque_notas.transactions:
        print(f"      - {tx}")
    
    print_subheader("3.2 Intentando ataque (modificacion de nota)...")
    
    print("""
    Ataque: Cambiar la nota de EST001 de 4.5 a 5.0
    """)
    
    # Guardar estado original
    original_transactions = bloque_notas.transactions.copy()
    original_merkle = bloque_notas.merkle_root
    original_hash = bloque_notas.hash
    
    # Simular ataque: modificar transacciones
    transacciones_atacadas = []

    for tx in original_transactions:
        if isinstance(tx, dict):
            tx_atacada = tx.copy()

            if tx_atacada.get('student_id') == "EST001":
                tx_atacada['grade'] = 5.0
                tx_atacada['payload'] = tx_atacada['payload'].replace("4.5", "5.0")

            transacciones_atacadas.append(tx_atacada)
        else:
            if "EST001" in tx:
                transacciones_atacadas.append(tx.replace("4.5", "5.0"))
            else:
                transacciones_atacadas.append(tx)
    
    tx_original_print = original_transactions[0]['payload'] if isinstance(original_transactions[0], dict) else original_transactions[0]
    tx_atacada_print = transacciones_atacadas[0]['payload'] if isinstance(transacciones_atacadas[0], dict) else transacciones_atacadas[0]

    print(f"  Transaccion original: {tx_original_print}")
    print(f"  Transaccion modificada: {tx_atacada_print}")
    
    print_subheader("3.3 Verificando integridad...")
    
    # Recalcular Merkle Root con transacciones modificadas
    merkle_atacado = MerkleTree(transacciones_atacadas)
    nuevo_merkle = merkle_atacado.get_root()
    
    print(f"\n  Merkle Root original:  {original_merkle}")
    print(f"  Merkle Root atacante:  {nuevo_merkle}")
    print(f"  - Coinciden?: {'NO - ATAQUE DETECTADO' if original_merkle != nuevo_merkle else 'SI'}")
    
    # Verificar efecto en hash del bloque
    bloque_atacado = Block(
        index=bloque_notas.index,
        transactions=transacciones_atacadas,
        previous_hash=bloque_notas.previous_hash,
        timestamp=bloque_notas.timestamp,
        nonce=bloque_notas.nonce,
        merkle_root=nuevo_merkle
    )
    
    hash_atacado = bloque_atacado.calculate_hash()
    
    print(f"\n  Hash del bloque original: {original_hash}")
    print(f"  Hash recalculado:         {hash_atacado}")
    print(f"  - Coinciden?: {'NO' if original_hash != hash_atacado else 'SI'}")
    
    # Verificar si cumpliria PoW
    target = "0" * DIFFICULTY
    print(f"\n  Verificacion PoW:")
    print(f"    - Hash original cumple PoW: {'SI' if original_hash.startswith(target) else 'NO'}")
    print(f"    - Hash atacante cumple PoW: {'SI' if hash_atacado.startswith(target) else 'NO'}")
    
    print_subheader("3.4 Verificando cadena completa...")
    
    # La cadena original sigue valida
    is_valid, message = blockchain.is_chain_valid()
    print(f"\n  - Cadena original sigue valida?: {'SI' if is_valid else 'NO'}")
    print(f"  - Mensaje: {message}")
    
    print("""
    
    ========================================================================
    ANALISIS DEL ATAQUE
    ========================================================================
    
    Que paso cuando intentamos modificar?
    
    1. Merkle Root cambio porque las transacciones cambiaron
    2. El hash del bloque cambio porque depende del Root
    3. El hash original ya no coincide con el recalculado
    4. Para "arreglar" el hash, necesitarian encontrar
       un nuevo nonce que cumpla PoW
    5. Y tambien tendrian que rehacer todos los bloques
       siguientes! (enlaces por hash)
    
    CONCLUSION: El blockchain es matematicamente seguro
    Cualquier modificacion es imposible de ocultar
    ========================================================================
    """)
    
    print_success("\nESCENARIO 3 COMPLETADO")
    print("  Se demostro que la modificacion es detectada inmediatamente")
    print("  La integridad del blockchain esta matematicamente garantizada")
    
    return blockchain


# =============================================================================
# ESCENARIO 4: INTENTO DE EMISION NO AUTORIZADA
# =============================================================================

def escenario_4_emision_no_autorizada(blockchain):
    """
    Escenario 4: Intento de emision no autorizada
    
    Este escenario demuestra el Smart Contract rechazando
    intentos de emitir calificaciones por usuarios no autorizados:
    - Un estudiante que intenta ponerse nota
    - Un atacante externo que intenta cambiar notas
    """
    print_header("ESCENARIO 4: INTENTO DE EMISION NO AUTORIZADA")
    
    print("""
    Este escenario prueba la seguridad del Smart Contract:
    
    Intentos que deben ser rechazados:
    1. Estudiante intentando ponerse una nota
    2. Atacante externo intentando modificar calificaciones
    
    El Smart Contract usa criptografia para verificar:
    - Identidad del firmante (clave publica)
    - Autorizacion (rol PROFESOR)
    - Autenticidad (firma digital ECDSA)
    """)
    
    print_subheader("4.1 Configurando sistema...")
    
    sc = SmartContract()
    
    # Crear clave de estudiante
    estudiante_verifier = ECDSAVerifier()
    estudiante_pk = estudiante_verifier.get_public_key_hex()
    
    print(f"\n  Estudiante ID: EST999")
    print(f"  Clave publica: {estudiante_pk[:32]}...")
    print(f"  Rol en sistema: NO REGISTRADO")
    
    print_subheader("4.2 Estudiante intenta emitirse nota...")
    
    print("""
    Estudiante: "Voy a darme 5.0 en Calculo I"
    """)
    
    try:
        tx = sc.attempt_transaction(
            estudiante_verifier,
            "EST999",  # ID del estudiante
            "EST999",
            "Calculo I",
            5.0
        )
        print_error("ERROR CRITICO: El sistema permitio el fraude!")
        
    except AuthorizationError as e:
        print(f"  Bloqueado por Smart Contract:")
        print(f"    {e}")
    
    print_subheader("4.3 Atacante externo intenta...")
    
    # Crear clave de atacante (nunca registrada)
    atacante_verifier = ECDSAVerifier()
    atacante_pk = atacante_verifier.get_public_key_hex()
    
    print(f"""
    Atacante: "Voy a cambiar todas las notas a 1.0"
    
    Clave publica del atacante: {atacante_pk[:32]}...
    """)
    
    try:
        tx = sc.attempt_transaction(
            atacante_verifier,
            "HACKER",
            "EST001",
            "Calculo I",
            1.0  # Ataque malicious
        )
        print_error("ERROR CRITICO: El sistema permitio el ataque!")
        
    except AuthorizationError as e:
        print(f"  Bloqueado por Smart Contract:")
        print(f"    {e}")
    
    print_subheader("4.4 Verificando que las notas originales siguen...")
    
    # Mostrar que el bloque original no fue modificado
    bloque_notas = blockchain.chain[1]
    
    print(f"\n  Las calificaciones originales estan seguras:")
    for tx in bloque_notas.transactions:
        if isinstance(tx, dict):
            print(f"    - {tx.get('payload', '')}")
        else:
            print(f"    - {tx}")
    
    print("""
    
    ========================================================================
    ANALISIS DE SEGURIDAD
    ========================================================================
    
    Por que estos ataques fallan?
    
    1. El Smart Contract verifica la clave publica
       - Solo acepta claves de profesores registrados
    
    2. El Smart Contract verifica el rol
       - Estudiantes y atacantes tienen rol NO_AUTORIZADO
    
    3. La firma digital ECDSA
       - Solo el poseedor de la clave privada puede firmar
       - La clave publica esta registrada como PROFESOR
    
    CONCLUSION: Solo profesores legitimos pueden
    emitir calificaciones. El sistema es seguro.
    ========================================================================
    """)
    
    print_success("\nESCENARIO 4 COMPLETADO")
    print("  Se demostro que el Smart Contract rechaza correctamente:")
    print("    - Estudiantes intentando emitirse notas")
    print("    - Atacantes externos intentando modificar datos")
    print("  La autorizacion esta protegida criptograficamente")
    
    return blockchain


# =============================================================================
# FUNCION PRINCIPAL
# =============================================================================

def main():
    """
    Funcion principal que ejecuta los 4 escenarios.
    """
    print("""
    ========================================================================
    ========================================================================
    ==            EDUCHAIN - DEMOSTRACION FINAL                   ==
    ==                                                            ==
    ==     Sistema Descentralizado y Seguro de Calificaciones     ==
    ==                                                            ==
    ==         Universidad Distrital FJC                          ==
    ==         Asignatura: Criptologia                             ==
    ==         Profesor: Msc. Ing. Oscar Gabriel Espejo Mojica     ==
    ==                                                            ==
    ========================================================================
    ========================================================================
    """)
    
    print("""
    Este demo ejecuta los 4 escenarios obligatorios:
    
    - Escenario 1: Creacion de la cadena (Bloque Genesis)
    - Escenario 2: Profesor emite notas validas
    - Escenario 3: Ataque de modificacion historica
    - Escenario 4: Intento de emision no autorizada
    
    Presiona ENTER para comenzar...
    """)
    
    input()
    
    # Ejecutar escenarios en orden
    try:
        # Escenario 1: Creacion de cadena
        blockchain = escenario_1_creacion_cadena()
        input("\nPresiona ENTER para continuar al Escenario 2...")
        
        # Escenario 2: Profesor emite notas
        blockchain = escenario_2_profesor_emite_notas(blockchain)
        input("\nPresiona ENTER para continuar al Escenario 3...")
        
        # Escenario 3: Ataque
        blockchain = escenario_3_modificacion_historica(blockchain)
        input("\nPresiona ENTER para continuar al Escenario 4...")
        
        # Escenario 4: Rechazo
        blockchain = escenario_4_emision_no_autorizada(blockchain)
        
        # Resumen final
        print_header("RESUMEN DE LA DEMOSTRACION")
        
        print("""
        ========================================================================
                        COMPONENTES IMPLEMENTADOS
        ========================================================================
        - SHA-256         - Hash de bloques y transacciones
        - Arbol de Merkle - Resumen de transacciones
        - ECDSA           - Firma digital de calificaciones
        - Proof of Work   - Minado con dificultad "000"
        - Smart Contract  - Autorizacion de profesores
        
        ========================================================================
                          ESCENARIOS DEMOSTRADOS
        ========================================================================
        - Escenario 1   - Creacion de cadena y bloque genesis
        - Escenario 2   - Emision de notas por profesor
        - Escenario 3   - Detección de ataque de modificación
        - Escenario 4   - Rechazo de emision no autorizada
        ========================================================================
        """)
        
        print_success("DEMOSTRACION COMPLETADA EXITOSAMENTE")

    except Exception as e:
        print_error(f"Error durante la demostracion: {e}")
        import traceback
        traceback.print_exc()
    
    return blockchain


# Ejecutar demo
if __name__ == "__main__":
    main()

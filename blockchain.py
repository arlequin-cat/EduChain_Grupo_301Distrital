# -*- coding: utf-8 -*-
"""
blockchain.py - Implementacion del Blockchain para EduChain

Este modulo implementa la cadena de bloques propiamente dicha, con todas
las caracteristicas requeridas para el proyecto de criptologia.

Componentes implementados:
- Bloque: Estructura con todos los campos requeridos
- Cadena: Gestion de bloques enlazados
- Proof of Work: Minado con dificultad "000"
- Integracion con Merkle Tree y SHA-256

Estructura del bloque (cabecera):
- index: Posicion en la cadena
- timestamp: Tiempo Unix de creacion
- merkle_root: Raiz de Merkle de transacciones
- hash_anterior: Hash del bloque anterior
- nonce: Valor encontrado por PoW
- hash: Hash del bloque (debe iniciar con "000")

@author: EduChain Group 301
@course: Criptologia - Universidad Distrital FJC
"""

import time
import json
from crypto_utils import sha256, ECDSAVerifier, signature_to_hex
from merkle_tree import MerkleTree


# Constantes de configuracion
DIFFICULTY = 3  # Numero de ceros iniciales requeridos (000 = 3)
GENESIS_HASH = "0" * 64  # Hash inicial para el bloque genesis


class Block:
    """
    Representa un bloque individual en la cadena de bloques.
    
    Cada bloque contiene:
    - index: Numero de posicion en la cadena
    - timestamp: Tiempo de creacion (Unix epoch)
    - transacciones: Lista de transacciones del bloque
    - merkle_root: Raiz de Merkle de las transacciones
    - hash_anterior: Hash del bloque anterior
    - nonce: Valor encontrado por Proof of Work
    - hash: Hash del bloque actual
    """
    
    def __init__(
        self,
        index: int,
        transactions: list,
        previous_hash: str = None,
        timestamp: float = None,
        nonce: int = 0,
        merkle_root: str = None
    ):
        """
        Inicializa un bloque.
        
        Args:
            index (int): Posicion del bloque en la cadena
            transactions (list): Lista de transacciones
            previous_hash (str): Hash del bloque anterior
            timestamp (float): Tiempo de creacion
            nonce (int): Nonce encontrado por PoW
            merkle_root (str): Raiz de Merkle calculada
        """
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash if previous_hash else GENESIS_HASH
        self.timestamp = timestamp if timestamp else time.time()
        self.nonce = nonce
        self.merkle_root = merkle_root
        self.hash = None  # Se calcula con mine_block()
        
        # Si tenemos transactions pero no merkle_root, calcularlo
        if self.merkle_root is None and self.transactions:
            merkle = MerkleTree(self.transactions)
            self.merkle_root = merkle.get_root()
        elif self.merkle_root is None:
            self.merkle_root = sha256("")
    
    def calculate_hash(self) -> str:
        """
        Calcula el hash del bloque basandose en su cabecera.
        
        La cabecera del bloque consiste en:
        {index, timestamp, merkle_root, hash_anterior, nonce}
        
        NOTA: El hash se calcula sobre la cabecera, NO sobre las transacciones.
        Esto es similar a Bitcoin y permite verificacion eficiente.
        
        Returns:
            str: Hash SHA-256 en formato hexadecimal
        """
        header = (
            str(self.index) +
            str(self.timestamp) +
            str(self.merkle_root) +
            str(self.previous_hash) +
            str(self.nonce)
        )
        return sha256(header)
    
    def mine_block(self, difficulty: int = DIFFICULTY) -> tuple:
        """
        Ejecuta el algoritmo Proof of Work para encontrar un nonce valido.
        
        El PoW requiere que el hash del bloque inicie con un numero
        especifico de ceros (difficulty). Para difficulty=3, el hash
        debe iniciar con "000".
        
        Args:
            difficulty (int): Numero de ceros requeridos
            
        Returns:
            tuple: (hash_encontrado, nonce, intentos, tiempo)
        """
        target = "0" * difficulty
        start_time = time.time()
        attempts = 0
        
        print(f"\n[Mining] Minando bloque {self.index}...")
        print(f"   Dificultad: {difficulty} ceros")
        print(f"   Target: '{target}'...")
        
        while True:
            self.hash = self.calculate_hash()
            attempts += 1
            
            # Mostrar progreso cada cierto numero de intentos
            if attempts % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"   Intentos: {attempts:,} | Tiempo: {elapsed:.2f}s | Hash: {self.hash[:20]}...")
            
            if self.hash.startswith(target):
                elapsed = time.time() - start_time
                print(f"   [OK] BLOQUE MINADO!")
                print(f"   Nonce encontrado: {self.nonce}")
                print(f"   Intentos totales: {attempts:,}")
                print(f"   Tiempo de minado: {elapsed:.4f} segundos")
                print(f"   Hash del bloque: {self.hash}")
                return self.hash, self.nonce, attempts, elapsed
            
            self.nonce += 1
    
    def is_valid(self) -> bool:
        """
        Verifica si el bloque es valido (hash cumple PoW).
        
        Returns:
            bool: True si el hash cumple la dificultad requerida
        """
        if self.hash is None:
            return False
        target = "0" * DIFFICULTY
        return self.hash.startswith(target)
    
    def get_header(self) -> dict:
        """
        Obtiene la cabecera del bloque para serializacion.
        
        Returns:
            dict: Cabecera del bloque
        """
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'merkle_root': self.merkle_root,
            'hash_anterior': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }
    
    def to_dict(self) -> dict:
        """
        Convierte el bloque a diccionario para serializacion JSON.
        
        Returns:
            dict: Representacion completa del bloque
        """
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'transacciones': self.transactions,
            'merkle_root': self.merkle_root,
            'hash_anterior': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }
    
    def __str__(self) -> str:
        """Representacion en string del bloque."""
        return json.dumps(self.to_dict(), indent=2)
    
    def verify_merkle_integrity(self) -> bool:
        """
        Verifica la integridad de las transacciones usando Merkle Root.
        
        Returns:
            bool: True si la raiz de Merkle coincide
        """
        if not self.transactions:
            return True
        
        merkle = MerkleTree(self.transactions)
        calculated_root = merkle.get_root()
        return calculated_root == self.merkle_root
    
    def print_block(self):
        """Imprime informacion del bloque de forma legible."""
        print("\n" + "=" * 60)
        print(f"BLOQUE #{self.index}")
        print("=" * 60)
        print(f"  Timestamp:    {self.timestamp}")
        print(f"  Hash anterior: {self.previous_hash[:20]}...")
        print(f"  Merkle Root:   {self.merkle_root[:20]}...")
        print(f"  Nonce:         {self.nonce}")
        print(f"  Hash:          {self.hash if self.hash else 'SIN MINAR'}")
        print(f"  Transacciones: {len(self.transactions)}")
        
        for i, tx in enumerate(self.transactions):
            print(f"    [{i}] {tx}")
        
        print("=" * 60)


class Blockchain:
    """
    Implementacion de la cadena de bloques EduChain.
    
    Gestiona la creacion, validacion y concatenacion de bloques.
    Mantiene la integridad de toda la cadena mediante hashes encadenados.
    
    Caracteristicas:
    - Creacion del bloque genesis
    - Adicion de nuevos bloques con transacciones
    - Validacion de toda la cadena
    - Proof of Work integrado
    """
    
    def __init__(self):
        """Inicializa la cadena con el bloque genesis."""
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """
        Crea el bloque genesis (bloque 0).
        
        El bloque genesis es el primer bloque de la cadena.
        Tiene index=0, no tiene hash_anterior valido (usa ceros),
        y tipicamente no tiene transacciones o tiene una transaccion especial.
        """
        print("\n" + "=" * 30)
        print("CREANDO BLOQUE GENESIS")
        print("=" * 30)
        
        # Crear bloque genesis sin transacciones
        genesis_block = Block(
            index=0,
            transactions=[],  # Genesis puede estar vacio
            previous_hash=GENESIS_HASH,
            timestamp=time.time(),
            nonce=0,
            merkle_root=sha256("")
        )
        
        # Minar bloque genesis
        genesis_block.mine_block()
        
        self.chain.append(genesis_block)
        
        print(f"\n[OK] Bloque genesis creado exitosamente")
        print(f"  Indice: {genesis_block.index}")
        print(f"  Hash: {genesis_block.hash}")
        print(f"  Hash anterior: {genesis_block.previous_hash}")
    
    def get_latest_block(self) -> Block:
        """
        Obtiene el ultimo bloque de la cadena.
        
        Returns:
            Block: El bloque mas reciente
        """
        return self.chain[-1]
    
    def add_block(self, transactions: list) -> Block:
        """
        Anade un nuevo bloque a la cadena con las transacciones especificadas.
        
        Args:
            transactions (list): Lista de transacciones a incluir
            
        Returns:
            Block: El nuevo bloque creado y minado
        """
        latest_block = self.get_latest_block()
        
        new_block = Block(
            index=latest_block.index + 1,
            transactions=transactions,
            previous_hash=latest_block.hash,
            timestamp=time.time()
        )
        
        print("\n" + "+" * 30)
        print(f"ANADIENDO NUEVO BLOQUE #{new_block.index}")
        print("+" * 30)
        
        # Minar el bloque
        new_block.mine_block()
        
        self.chain.append(new_block)
        
        return new_block
    
    def is_chain_valid(self) -> tuple:
        """
        Valida toda la cadena de bloques.
        
        Verificaciones:
        1. Cada bloque tiene hash valido (cumple PoW)
        2. Cada bloque referencia al anterior correctamente
        3. La raiz de Merkle coincide con las transacciones
        
        Returns:
            tuple: (es_valida, mensaje_error)
        """
        if not self.chain:
            return False, "Cadena vacia"
        
        # Verificar genesis
        if self.chain[0].index != 0:
            return False, "El primer bloque no es el genesis"
        
        if not self.chain[0].hash.startswith("0" * DIFFICULTY):
            return False, "El genesis no cumple PoW"
        
        # Verificar cada bloque desde el segundo
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # 1. Verificar hash del bloque actual
            if not current_block.hash.startswith("0" * DIFFICULTY):
                return False, f"Bloque {i} no cumple PoW"
            
            # 2. Verificar enlace con bloque anterior
            if current_block.previous_hash != previous_block.hash:
                return False, f"Bloque {i} no referencia al anterior"
            
            # 3. Verificar que el hash calculado coincide
            calculated_hash = current_block.calculate_hash()
            if current_block.hash != calculated_hash:
                return False, f"Bloque {i} tiene hash modificado"
            
            # 4. Verificar integridad Merkle
            if not current_block.verify_merkle_integrity():
                return False, f"Bloque {i} tiene integridad Merkle comprometida"
        
        return True, "Cadena valida"
    
    def verify_block_integrity(self, block_index: int) -> tuple:
        """
        Verifica la integridad de un bloque especifico.
        
        Args:
            block_index (int): Indice del bloque a verificar
            
        Returns:
            tuple: (es_valido, mensaje)
        """
        if block_index < 0 or block_index >= len(self.chain):
            return False, f"Bloque {block_index} no existe"
        
        block = self.chain[block_index]
        
        # Verificar PoW
        if not block.hash.startswith("0" * DIFFICULTY):
            return False, f"Bloque {block_index} no cumple PoW"
        
        # Verificar hash
        if block.hash != block.calculate_hash():
            return False, f"Bloque {block_index} tiene hash modificado"
        
        # Verificar Merkle
        if not block.verify_merkle_integrity():
            return False, f"Bloque {block_index} tiene transacciones modificadas"
        
        # Verificar enlace
        if block_index > 0:
            if block.previous_hash != self.chain[block_index - 1].hash:
                return False, f"Bloque {block_index} no referencia correctamente"
        
        return True, f"Bloque {block_index} valido"
    
    def print_chain(self):
        """Imprime toda la cadena de bloques."""
        print("\n" + "#" * 30)
        print("CADENA DE BLOQUES EDUCHAIN")
        print("#" * 30)
        print(f"\nTotal de bloques: {len(self.chain)}")
        print(f"Dificultad PoW: {DIFFICULTY} ceros\n")
        
        for block in self.chain:
            block.print_block()
        
        # Verificacion final
        print("\n" + "?" * 30)
        print("VERIFICACION DE CADENA")
        print("?" * 30)
        
        is_valid, message = self.is_chain_valid()
        print(f"  Estado: {'[OK] VALIDA' if is_valid else '[ERROR] INVALIDA'}")
        print(f"  Mensaje: {message}")
        
        if is_valid:
            print(f"\n  [OK] La cadena de bloques esta matematicamente protegida")
            print(f"  [OK] Cualquier modificacion sera detectada inmediatamente")
    
    def get_chain_data(self) -> dict:
        """
        Obtiene todos los datos de la cadena para analisis.
        
        Returns:
            dict: Datos completos de la cadena
        """
        return {
            'blocks': len(self.chain),
            'difficulty': DIFFICULTY,
            'genesis_hash': self.chain[0].hash if self.chain else None,
            'latest_hash': self.get_latest_block().hash if self.chain else None,
            'is_valid': self.is_chain_valid()[0],
            'chain': [b.to_dict() for b in self.chain]
        }
    
    def simulate_attack(self, block_index: int, new_transaction: str) -> bool:
        """
        Simula un ataque modificando una transaccion en un bloque.
        
        Args:
            block_index (int): Indice del bloque a atacar
            new_transaction (str): Nueva transaccion a insertar
            
        Returns:
            bool: True si se detecta el ataque
        """
        if block_index >= len(self.chain):
            print(f"[ERROR] Bloque {block_index} no existe")
            return False
        
        block = self.chain[block_index]
        
        print("\n" + "!" * 30)
        print(f"SIMULANDO ATAQUE AL BLOQUE #{block_index}")
        print("!" * 30)
        
        # Guardar valores originales
        original_transactions = block.transactions.copy()
        original_merkle = block.merkle_root
        original_hash = block.hash
        
        # Modificar transaccion
        block.transactions.append(new_transaction)
        
        # Recalcular Merkle Root
        merkle = MerkleTree(block.transactions)
        new_merkle = merkle.get_root()
        
        print(f"\n  Transaccion original: {original_transactions}")
        print(f"  Transaccion modificada: {block.transactions}")
        print(f"  Merkle Root original:  {original_merkle[:20]}...")
        print(f"  Nuevo Merkle Root:      {new_merkle[:20]}...")
        
        # Restaurar (solo para demo)
        block.transactions = original_transactions
        
        # Verificar si se detecta
        is_valid, message = self.is_chain_valid()
        
        print(f"\n  - Ataque detectado?: {'[OK] SI' if not is_valid else '[ERROR] NO'}")
        print(f"  - Mensaje: {message}")
        
        return not is_valid


# =============================================================================
# PRUEBAS Y DEMOSTRACION
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PRUEBA DEL MODULO BLOCKCHAIN")
    print("=" * 60)
    
    # Crear blockchain
    bc = Blockchain()
    
    print("\n[1] Anadiendo bloque con transacciones:")
    
    # Anadir algunas transacciones
    transactions = [
        "PROF001|EST001|Calculo I|4.5",
        "PROF001|EST002|Calculo I|3.8",
        "PROF001|EST003|Calculo I|5.0",
    ]
    
    bc.add_block(transactions)
    
    print("\n[2] Anadiendo segundo bloque:")
    
    transactions2 = [
        "PROF001|EST004|Fisica I|4.2",
        "PROF001|EST005|Fisica I|3.5",
    ]
    
    bc.add_block(transactions2)
    
    # Mostrar cadena
    bc.print_chain()
    
    print("\n[3] Simulacion de ataque:")
    bc.simulate_attack(1, "HACKER|EST999|Any|5.0")
    
    print("\n" + "=" * 60)
    print("TODAS LAS PRUEBAS COMPLETADAS")
    print("=" * 60)
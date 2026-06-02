# -*- coding: utf-8 -*-
"""
merkle_tree.py - Arbol de Merkle para EduChain

El Arbol de Merkle es una estructura de datos binaria utilizada para resumir
de manera eficiente todas las transacciones en un bloque.

Estructura:
        [Raiz de Merkle]
           //      \\
       [Nodo A]    [Nodo B]
       //   \\      //   \\
   [Tx1] [Tx2] [Tx3] [Tx4]

Beneficios:
- Verificacion eficiente: probar pertenencia en O(log n)
- Integridad: cualquier cambio en transacciones cambia la raiz
- Espacio: no requiere almacenar todas las transacciones para verificacion

@author: EduChain Group 301
@course: Criptologia - Universidad Distrital FJC
"""

import hashlib
from crypto_utils import sha256


class MerkleTree:
    """
    Implementacion del Arbol de Merkle para resumir transacciones.
    
    Cada nodo del arbol contiene el hash de sus hijos.
    La raiz (Merkle Root) es un hash de 256 bits que representa
    todas las transacciones del bloque.
    """
    
    def __init__(self, transactions: list = None):
        """
        Inicializa el Arbol de Merkle.
        
        Args:
            transactions (list): Lista de transacciones (strings) a incluir
        """
        self.transactions = transactions or []
        self.leaves = []          # Hashes de las transacciones (nivel 0)
        self.tree = []            # Lista de niveles del arbol
        self.root = None          # Raiz del arbol
        
        if self.transactions:
            self.build_tree()
    
    def _hash_transaction(self, tx: str) -> str:
        """
        Hashea una transaccion individual.
        
        Args:
            tx (str): Transaccion como string
            
        Returns:
            str: Hash SHA-256 en hexadecimal
        """
        return sha256(tx)
    
    def build_tree(self):
        """
        Construye el Arbol de Merkle desde las transacciones.
        
        Proceso:
        1. Convertir cada transaccion en un hash (hojas)
        2. Emparejar hashes y hashear pares (nivel 1)
        3. Repetir hasta llegar a la raiz
        4. Si hay numero impar, duplicar el ultimo hash
        """
        # Nivel 0: Hojas = hashes de transacciones
        self.leaves = [self._hash_transaction(tx) for tx in self.transactions]
        
        if not self.leaves:
            self.root = sha256("")  # Raiz vacia
            return
        
        # Si solo hay una transaccion, la raiz es esa transaccion hasheada dos veces
        if len(self.leaves) == 1:
            # Duplicar la hoja y hashear
            self.leaves.append(self.leaves[0])
        
        # Construir niveles
        current_level = self.leaves[:]
        self.tree.append(current_level)
        
        while len(current_level) > 1:
            next_level = []
            
            # Emparejar y hashear
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                
                # Si es impar, duplicar el ultimo
                if i + 1 >= len(current_level):
                    right = current_level[i]
                else:
                    right = current_level[i + 1]
                
                # Hash del par: sha256(left || right)
                combined = left + right
                parent_hash = sha256(combined)
                next_level.append(parent_hash)
            
            self.tree.append(next_level)
            current_level = next_level
        
        # La raiz es el ultimo nivel, primer elemento
        self.root = current_level[0] if current_level else self.leaves[0]
    
    def get_root(self) -> str:
        """
        Obtiene la raiz de Merkle.
        
        Returns:
            str: Raiz en formato hexadecimal (64 caracteres)
        """
        if self.root is None:
            if self.transactions:
                self.build_tree()
            else:
                self.root = sha256("")
        return self.root
    
    def get_proof(self, transaction: str) -> list:
        """
        Genera prueba de inclusion para una transaccion.
        
        Devuelve los hashes necesarios para verificar que una
        transaccion esta en el arbol sin necesidad de todas las transacciones.
        
        Args:
            transaction (str): Transaccion a probar
            
        Returns:
            list: Lista de (hash, is_left) para verificacion
        """
        if transaction not in self.transactions:
            return []
        
        tx_hash = self._hash_transaction(transaction)
        proof = []
        
        # Encontrar la posicion de la transaccion
        position = self.leaves.index(tx_hash)
        
        # Navegar el arbol generando prueba
        level = 0
        current_position = position
        
        while level < len(self.tree) - 1:
            current_level = self.tree[level]
            next_level = self.tree[level + 1]
            
            # Determinar si es hijo izquierdo o derecho
            is_left = current_position % 2 == 0
            sibling_position = current_position + 1 if is_left else current_position - 1
            
            # Obtener hash del hermano
            if sibling_position < len(current_level):
                sibling_hash = current_level[sibling_position]
                proof.append((sibling_hash, is_left))
            else:
                # Si no hay hermano, somos el ultimo y duplicamos
                proof.append((current_level[current_position], is_left))
            
            # Subir al siguiente nivel
            current_position = current_position // 2
            level += 1
        
        return proof
    
    def verify_proof(self, transaction: str, proof: list, root: str) -> bool:
        """
        Verifica una prueba de inclusion de Merkle.
        
        Args:
            transaction (str): Transaccion a verificar
            proof (list): Prueba generada por get_proof()
            root (str): Raiz esperada del arbol
            
        Returns:
            bool: True si la transaccion esta en el arbol
        """
        if not proof:
            return self._hash_transaction(transaction) == root
        
        current_hash = self._hash_transaction(transaction)
        
        for sibling_hash, is_left in proof:
            if is_left:
                # El hash del hermano esta a la derecha: sha256(current || sibling)
                combined = current_hash + sibling_hash
            else:
                # El hash del hermano esta a la izquierda: sha256(sibling || current)
                combined = sibling_hash + current_hash
            
            current_hash = sha256(combined)
        
        return current_hash == root
    
    def verify_transaction_inclusion(self, transaction: str) -> bool:
        """
        Verifica si una transaccion esta incluida en el Arbol.
        
        Args:
            transaction (str): Transaccion a verificar
            
        Returns:
            bool: True si la transaccion esta en el Arbol
        """
        tx_hash = self._hash_transaction(transaction)
        
        # Verificar que esta en las hojas
        if tx_hash not in self.leaves:
            return False
        
        # Verificar que puede llegar a la raiz
        proof = self.get_proof(transaction)
        return self.verify_proof(transaction, proof, self.get_root())
    
    def get_tree_structure(self) -> dict:
        """
        Obtiene la estructura completa del Arbol para visualizacion.
        
        Returns:
            dict: Diccionario con niveles y nodos
        """
        structure = {
            'levels': [],
            'root': self.get_root(),
            'num_transactions': len(self.transactions)
        }
        
        for i, level in enumerate(self.tree):
            level_data = {
                'level': i,
                'nodes': len(level),
                'hashes': [h[:16] + '...' for h in level]
            }
            structure['levels'].append(level_data)
        
        return structure
    
    def print_tree(self):
        """
        Imprime el Arbol de Merkle en formato visual.
        """
        print("\n" + "=" * 60)
        print("ARBOL DE MERKLE")
        print("=" * 60)
        
        if not self.transactions:
            print("  (Sin transacciones - Arbol vacio)")
            return
        
        print(f"\nTransacciones ({len(self.transactions)}):")
        for i, tx in enumerate(self.transactions):
            print(f"  [{i}] {tx[:50]}{'...' if len(tx) > 50 else ''}")
        
        print(f"\nRaiz de Merkle: {self.root}")
        
        print("\nEstructura del Arbol:")
        for i, level in enumerate(self.tree):
            level_name = "HOJAS" if i == 0 else f"NIVEL {i}"
            print(f"\n{level_name} ({len(level)} nodos):")
            for j, h in enumerate(level):
                print(f"  [{j}] {h[:16]}...")
        
        print("\n" + "=" * 60)
    
    def recalculate_root(self, transactions: list) -> str:
        """
        Recalcula la raiz de Merkle con nuevas transacciones.
        
        Util para verificar integridad cuando se modifican transacciones.
        
        Args:
            transactions (list): Nuevas transacciones
            
        Returns:
            str: Nueva raiz de Merkle
        """
        temp_tree = MerkleTree(transactions)
        return temp_tree.get_root()
    
    def verify_integrity(self, stored_root: str) -> bool:
        """
        Verifica la integridad de las transacciones contra una raiz almacenada.
        
        Args:
            stored_root (str): Raiz almacenada en el bloque
            
        Returns:
            bool: True si la raiz coincide
        """
        current_root = self.get_root()
        return current_root == stored_root


# =============================================================================
# PRUEBAS Y DEMOSTRACION
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("PRUEBA DEL MODULO MERKLE_TREE")
    print("=" * 60)
    
    # Crear transacciones de ejemplo
    transacciones = [
        "PROF001|EST001|Calculo I|4.5",
        "PROF001|EST002|Calculo I|3.8",
        "PROF001|EST003|Calculo I|5.0",
        "PROF001|EST004|Calculo I|4.2",
    ]
    
    # Crear Arbol de Merkle
    merkle = MerkleTree(transacciones)
    
    print("\n[1] Construccion del Arbol:")
    print(f"  Numero de transacciones: {len(transacciones)}")
    print(f"  Raiz de Merkle: {merkle.get_root()}")
    print(f"  Longitud raiz: {len(merkle.get_root())} caracteres")
    
    # Imprimir estructura
    print("\n[2] Estructura del Arbol:")
    merkle.print_tree()
    
    # Prueba de verificacion de integridad
    print("\n[3] Verificacion de Integridad:")
    print(f"  Raiz almacenada en bloque: {merkle.get_root()}")
    es_valida = merkle.verify_integrity(merkle.get_root())
    print(f"  - Integridad valida?: {'OK' if es_valida else 'ERROR'}")
    
    # Prueba: Modificar una transaccion
    print("\n[4] Prueba de Ataque (Modificacion):")
    print("  Transaccion original: PROF001|EST001|Calculo I|4.5")
    print("  Transaccion modificada: PROF001|EST001|Calculo I|5.0 (fraude)")
    
    # Crear Arbol con transaccion modificada
    transacciones_falsas = [
        "PROF001|EST001|Calculo I|5.0",  # Nota cambiada de 4.5 a 5.0
        "PROF001|EST002|Calculo I|3.8",
        "PROF001|EST003|Calculo I|5.0",
        "PROF001|EST004|Calculo I|4.2",
    ]
    
    merkle_falso = MerkleTree(transacciones_falsas)
    
    print(f"  Raiz original:     {merkle.get_root()[:32]}...")
    print(f"  Raiz modificada:   {merkle_falso.get_root()[:32]}...")
    print(f"  - Detectado?:       {'OK SI - Las raices no coinciden' if merkle.get_root() != merkle_falso.get_root() else 'ERROR NO'}")
    
    # Prueba de prueba de inclusion
    print("\n[5] Prueba de Inclusion:")
    tx_a_verificar = transacciones[0]
    proof = merkle.get_proof(tx_a_verificar)
    print(f"  Transaccion: {tx_a_verificar}")
    print(f"  Longitud de prueba: {len(proof)} elementos")
    
    es_incluida = merkle.verify_proof(tx_a_verificar, proof, merkle.get_root())
    print(f"  Verificacion con prueba: {'OK VALIDA' if es_incluida else 'ERROR INVALIDA'}")
    
    print("\n" + "=" * 60)
    print("TODAS LAS PRUEBAS COMPLETADAS")
    print("=" * 60)
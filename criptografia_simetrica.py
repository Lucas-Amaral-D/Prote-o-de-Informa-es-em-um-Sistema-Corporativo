import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def gerar_chave() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def cifrar(dados: bytes, chave: bytes) -> tuple[bytes, bytes]:
    """Retorna (nonce, ciphertext). Ambos devem ser enviados ao destinatario."""
    nonce = os.urandom(12)
    return nonce, AESGCM(chave).encrypt(nonce, dados, None)


def decifrar(nonce: bytes, ciphertext: bytes, chave: bytes) -> bytes:
    """Lanca InvalidTag se os dados foram adulterados."""
    return AESGCM(chave).decrypt(nonce, ciphertext, None)
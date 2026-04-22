import os
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_SALT = 16
_NONCE = 12


def _derivar_chave(senha: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, 600_000).derive(senha.encode())


def salvar_cifrado(entrada: str, saida: str, senha: str) -> None:
    """Cifra o arquivo e salva [salt][nonce][ciphertext] em saida."""
    salt, nonce = os.urandom(_SALT), os.urandom(_NONCE)
    ct = AESGCM(_derivar_chave(senha, salt)).encrypt(nonce, Path(entrada).read_bytes(), None)
    Path(saida).write_bytes(salt + nonce + ct)


def carregar_cifrado(entrada: str, saida: str, senha: str) -> None:
    """Decifra o arquivo. Lanca ValueError se a senha for errada ou o arquivo estiver corrompido."""
    raw = Path(entrada).read_bytes()
    salt, nonce, ct = raw[:_SALT], raw[_SALT:_SALT+_NONCE], raw[_SALT+_NONCE:]
    try:
        Path(saida).write_bytes(AESGCM(_derivar_chave(senha, salt)).decrypt(nonce, ct, None))
    except InvalidTag:
        raise ValueError("Senha incorreta ou arquivo adulterado.")
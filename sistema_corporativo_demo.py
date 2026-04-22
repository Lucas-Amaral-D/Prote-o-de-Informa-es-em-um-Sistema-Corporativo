import base64, json, os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from criptografia_simetrica import gerar_chave, cifrar, decifrar
from assinatura_digital import gerar_par_chaves, assinar, verificar
from arquivos_repouso import salvar_cifrado, carregar_cifrado

SEP = "-" * 55

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

def cifrar_chave(chave: bytes, pub_pem: bytes) -> bytes:
    return serialization.load_pem_public_key(pub_pem).encrypt(chave, _OAEP)

def decifrar_chave(chave_cifrada: bytes, priv_pem: bytes) -> bytes:
    return serialization.load_pem_private_key(priv_pem, password=None).decrypt(chave_cifrada, _OAEP)

_CHAVES_PUBLICAS: dict[str, bytes] = {}

def registrar(setor: str, pub_pem: bytes) -> None:
    _CHAVES_PUBLICAS[setor] = pub_pem

def chave_publica_de(setor: str) -> bytes:
    if setor not in _CHAVES_PUBLICAS:
        raise KeyError(f"Remetente '{setor}' nao reconhecido.")
    return _CHAVES_PUBLICAS[setor]

def main():
    b64 = lambda b: base64.b64encode(b).decode()

    print(SEP)
    print("  SISTEMA CORPORATIVO - PROTECAO DE DOCUMENTOS")
    print(SEP)

    rh_priv, rh_pub = gerar_par_chaves()
    fin_priv, fin_pub = gerar_par_chaves()
    registrar("RH", rh_pub)
    registrar("FINANCEIRO", fin_pub)
    print("[OK] Chaves RSA geradas e chaves publicas registradas.\n")

    documento = b"Contrato - Ana Souza | Cargo: Analista | Salario: R$ 8.500,00"
    REMETENTE, DESTINATARIO = "RH", "FINANCEIRO"

    payload = f"{REMETENTE}->{DESTINATARIO}:".encode() + documento
    assinatura = assinar(payload, rh_priv)

    chave_sessao = gerar_chave()
    nonce, ct = cifrar(documento, chave_sessao)

    chave_cifrada = cifrar_chave(chave_sessao, fin_pub)

    envelope = {
        "remetente": REMETENTE,
        "destinatario": DESTINATARIO,
        "nonce": b64(nonce),
        "documento_cifrado": b64(ct),
        "assinatura": b64(assinatura),
        "chave_sessao_cifrada": b64(chave_cifrada),
    }

    print(f"[C1+C2+C4] Envelope enviado de {REMETENTE} para {DESTINATARIO}:")
    print(json.dumps(envelope, indent=2))
    print()

    print(SEP)
    print(f"  RECEPCAO - {envelope['destinatario']} abrindo o envelope")
    print(SEP)

    chave_rec = decifrar_chave(base64.b64decode(envelope["chave_sessao_cifrada"]), fin_priv)

    doc_rec = decifrar(base64.b64decode(envelope["nonce"]),
                       base64.b64decode(envelope["documento_cifrado"]), chave_rec)

    payload_rec = f"{envelope['remetente']}->{envelope['destinatario']}:".encode() + doc_rec
    pub_rem = chave_publica_de(envelope["remetente"])
    valido = verificar(payload_rec, base64.b64decode(envelope["assinatura"]), pub_rem)

    print(f"Documento: {doc_rec.decode()}")
    print(f"Assinatura valida: {valido}")
    print()

    doc_adulterado = doc_rec.replace(b"8.500", b"3.000")
    payload_adulterado = f"{envelope['remetente']}->{envelope['destinatario']}:".encode() + doc_adulterado
    adulterado = verificar(payload_adulterado, base64.b64decode(envelope["assinatura"]), pub_rem)
    print(f"Adulteracao detectada: {not adulterado}")

    try:
        chave_publica_de("INVASOR")
    except KeyError as e:
        print(f"Remetente falso bloqueado: {e}")

    print()
    print(SEP)
    print("  CENARIO 3 - Arquivo cifrado no servidor")
    print(SEP)

    pasta = Path("demo_arquivos")
    pasta.mkdir(exist_ok=True)
    senha = os.environ.get("SENHA_SERVIDOR", "senha_demo_2025!")

    Path(pasta / "contrato.txt").write_bytes(documento)
    salvar_cifrado(str(pasta / "contrato.txt"), str(pasta / "contrato.enc"), senha)
    carregar_cifrado(str(pasta / "contrato.enc"), str(pasta / "contrato_rec.txt"), senha)

    recuperado = Path(pasta / "contrato_rec.txt").read_bytes()
    print(f"Arquivo cifrado salvo em: {pasta / 'contrato.enc'}")
    print(f"Conteudo integro apos recuperacao: {recuperado == documento}")

    try:
        carregar_cifrado(str(pasta / "contrato.enc"), str(pasta / "x.txt"), "senha_errada")
    except ValueError as e:
        print(f"Senha errada rejeitada: {e}")


if __name__ == "__main__":
    main()
# Protecao de Informacoes em um Sistema Corporativo

Este projeto implementa uma solucao inicial para proteger documentos trocados entre setores de uma empresa, atendendo aos quatro cenarios pedidos na atividade:

- protecao do conteudo dos documentos durante a transmissao
- confirmacao de autoria e integridade
- protecao de arquivos armazenados no servidor
- troca segura de chaves sem envio manual de segredos

### O que foi implementado

1. Cenario 1 - Protecao do conteudo em transito
   - Implementado em `criptografia_simetrica.py`
   - Usa AES-256-GCM
   - Motivo: criptografia simetrica e muito rapida para arquivos e o modo GCM tambem detecta adulteracao

2. Cenario 2 - Confirmacao de autoria e integridade
   - Implementado em `assinatura_digital.py`
   - Usa RSA-PSS com SHA-256
   - O remetente assina o documento com a chave privada
   - O destinatario verifica com a chave publica confiavel do remetente
   - No fluxo principal, a assinatura cobre remetente, destinatario e documento

3. Cenario 3 - Protecao de arquivos armazenados
   - Implementado em `arquivos_repouso.py`
   - Usa AES-256-GCM com chave derivada por PBKDF2
   - O arquivo salvo em disco fica ilegivel sem a senha correta

4. Cenario 4 - Troca segura de chaves
   - Implementado em `sistema_corporativo_demo.py`
   - Usa RSA-OAEP para cifrar a chave AES de sessao
   - Assim, a chave simetrica nao precisa ser enviada manualmente por e-mail, planilha ou mensagem

### Combinacao das tecnicas exigidas

O projeto combina corretamente:

- criptografia simetrica: AES-256-GCM
- criptografia assimetrica: RSA-OAEP
- assinatura digital: RSA-PSS com SHA-256

### Veredito

O trabalho esta alinhado com o enunciado e cumpre os requisitos principais da atividade, tanto na parte conceitual quanto na implementacao em codigo.

## Estrutura do Projeto

- `criptografia_simetrica.py`: funcoes de criptografia simetrica para proteger documentos em transito
- `assinatura_digital.py`: geracao de chaves RSA, assinatura e verificacao
- `arquivos_repouso.py`: cifragem e recuperacao de arquivos armazenados no servidor
- `sistema_corporativo_demo.py`: demonstracao completa integrando os quatro cenarios
- `requirements.txt`: dependencia do projeto

## Como a Solucao Funciona

### Fluxo geral

1. O setor remetente cria o documento.
2. O sistema monta um payload com remetente, destinatario e conteudo.
3. O remetente assina esse payload com sua chave privada RSA.
4. O documento e cifrado com uma chave simetrica AES de sessao.
5. A chave AES e cifrada com a chave publica RSA do destinatario.
6. O envelope e enviado pela rede.
7. O destinatario usa sua chave privada para recuperar a chave AES.
8. O destinatario decifra o documento.
9. O destinatario usa a chave publica confiavel do remetente para verificar a assinatura.
10. Para armazenamento em servidor, o arquivo e cifrado com AES-GCM usando chave derivada por PBKDF2.

### Pseudofluxo simples

```text
RH cria documento
RH assina(remetente + destinatario + documento)
RH cifra documento com AES
RH cifra chave AES com RSA publico do Financeiro
RH envia envelope

Financeiro recebe envelope
Financeiro decifra chave AES com RSA privado
Financeiro decifra documento com AES
Financeiro verifica assinatura com RSA publico do RH

Servidor cifra arquivo armazenado com AES-GCM + PBKDF2
```

## Tecnologias e Escolhas Criptograficas

### AES-256-GCM

Usado para proteger o conteudo dos documentos porque:

- e rapido para arquivos e textos maiores
- usa a mesma chave para cifrar e decifrar
- o modo GCM fornece confidencialidade e integridade

### RSA-PSS com SHA-256

Usado para assinatura digital porque:

- a chave privada do remetente prova autoria
- a chave publica permite verificacao pelo destinatario
- qualquer alteracao no conteudo invalida a assinatura

### RSA-OAEP

Usado para cifrar a chave AES porque:

- RSA nao e adequado para arquivos grandes
- mas e adequado para proteger pequenos segredos, como uma chave de sessao
- resolve o problema da troca segura de chaves

### PBKDF2

Usado no armazenamento porque:

- deriva uma chave forte a partir de uma senha
- utiliza salt aleatorio
- dificulta ataques de forca bruta e dicionario

## Como Executar

### 1. Instalar dependencia

```powershell
pip install -r requirements.txt
```

### 2. Rodar a demonstracao completa

```powershell
python sistema_corporativo_demo.py
```

## O que a demonstracao mostra

Ao executar o script principal, voce vera:

- geracao das chaves RSA dos setores
- criacao de um envelope com documento cifrado
- recuperacao da chave AES pelo destinatario
- decifragem do documento
- validacao da assinatura digital
- deteccao de adulteracao
- bloqueio de remetente nao reconhecido
- cifragem e recuperacao de arquivo armazenado no servidor
- rejeicao de senha errada no cenario de repouso

## Saida esperada

Resultados esperados na execucao:

- `Assinatura valida: True`
- `Adulteracao detectada: True`
- `Conteudo integro apos recuperacao: True`
- rejeicao de senha incorreta no teste de arquivo armazenado


## Conclusao

- criptografia simetrica para proteger o conteudo
- assinatura digital para autoria e integridade
- criptografia assimetrica para troca segura de chaves
- cifragem em repouso para proteger arquivos armazenados


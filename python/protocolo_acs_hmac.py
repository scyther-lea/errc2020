#!/usr/bin/env python3

#                   ** NOTA **

# Implementacao simplificada do protocolo ACS (com HMAC).
# Esta implementacao eh meramente para fins didaticos.
# Serve para ilustrar a complexidade entre a especificacao,
# verificacao e implementacao. A implementacacao deveria,
# tambem, passar por uma verificacao de codigo.
#
# Implementacao testada no Debian 10 e Python 3.7.3.
#
# Nao ha nenhum tipo de garantia com relacao a este codigo.

#                   ** NOTA **

import sys
import socket
import random
import time
import hmac
import hashlib
import secrets
from Crypto.Cipher import AES
import base64, os

char_de_padding = "{"   # char utilizado para padding
padding_e_secrets = 16  # 16 bytes ou multiplo de 16 bytes
bytes_da_mensagem = 109 # nonce cifrado + HMAC

def uso():
    print("Uso: " + sys.argv[0] + " <ip> <porta> <servidor|cliente> <Alice|Bob> <chave_secreta> <n_trocas_de_chave>")
    sys.exit(-1)

def gera_nonce_32b_hex():
    global padding_e_secrets
    return secrets.token_hex(padding_e_secrets)

def aes_decifrar(chave_secreta, mensagem_cifrada):
    global char_de_padding
    cipher = AES.new(chave_secreta)
    dado_decifrado = cipher.decrypt(mensagem_cifrada)
    dado_decifrado = dado_decifrado.decode()
    dado_sem_padding = dado_decifrado.rstrip(char_de_padding)
    return dado_sem_padding

def aes_cifrar(chave_secreta, mensagem):
    global char_de_padding
    global padding_e_secrets
    cipher = AES.new(chave_secreta)
    mensagem_com_padding = mensagem + (char_de_padding * ((padding_e_secrets-len(mensagem)) % padding_e_secrets))
    mensagem_cifrada = cipher.encrypt(mensagem_com_padding)
    return mensagem_cifrada

def aes_atualiza_chave(chave_secreta):
    global padding_e_secrets
    if len(chave_secreta) < padding_e_secrets:
        chave_secreta = chave_secreta + (char_de_padding * ((padding_e_secrets-len(chave_secreta)) % padding_e_secrets))
    else:
        chave_secreta = chave_secreta[:padding_e_secrets]
    return chave_secreta

def hash_nova_chave(chave_secreta, nonce):
    gerador_hash = hashlib.new('sha256')
    gerador_hash.update(bytes(chave_secreta+nonce,encoding='utf-8'));
    chave_secreta = aes_atualiza_chave(gerador_hash.hexdigest())
    return chave_secreta

def servidor(ip, porta, entidade, chave_secreta, n_trocas_de_chave):

    sock = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    endereco_servidor = (ip, porta)
    
    print ("inciando servidor no IP %s e PORTA %s" % endereco_servidor)
    
    sock.bind(endereco_servidor)
    sock.listen(5)
    
    print ("aguardando conexao do cliente ... ")
    cliente, endereco = sock.accept()
    print (" cliente %s endereco %s conectado " % (cliente, endereco))

    for i in range(n_trocas_de_chave):

        mensagem = cliente.recv(bytes_da_mensagem)
        mensagem = mensagem.decode('utf-8')

        if mensagem:
            print ("[" + entidade + ":" + str(i) + "] mensagem: " + mensagem)
            mensagem_cifrada, hmac_da_msg = mensagem.split()
            print ("[" + entidade + ":" + str(i) + "] chave: " + chave_secreta)
            gerador_hmac = hmac.new(
                bytes(chave_secreta, encoding='utf-8'),
                bytes(mensagem_cifrada, encoding='utf-8'),
                hashlib.sha256
                )
            hmac_gerado = gerador_hmac.hexdigest()
            if (hmac_da_msg == hmac_gerado):
                mensagem_cifrada = base64.b64decode(mensagem_cifrada)
                nonce = aes_decifrar(chave_secreta, mensagem_cifrada)

                print ("[" + entidade + ":" + str(i) + "] nonce: " + nonce)

                chave_secreta = hash_nova_chave(chave_secreta, nonce)
            else:
                print ("[" + entidade + ":" + str(i) + "] ERRO no verificacao do HMAC")
        else:
            print ("[" + entidade + ":" + str(i) + "] ERRO no recebimento da mensagem")
        print (" ")

    sock.close()
     
def cliente(ip, porta, entidade, chave_secreta, n_trocas_de_chave):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    endereco_servidor = (ip, porta)

    print("conectando ao servidor no %s porta %s" % endereco_servidor)

    sock.connect(endereco_servidor)
    
    for i in range(n_trocas_de_chave):

        nonce = gera_nonce_32b_hex()

        print ("[" + entidade + ":" + str(i) + "] chave: " + chave_secreta)
        print ("[" + entidade + ":" + str(i) + "] nonce: " + nonce)

        mensagem = aes_cifrar(chave_secreta, nonce)
        mensagem = base64.b64encode(mensagem)
        hmac_sha256 = hmac.new(
                bytes(chave_secreta, encoding='utf-8'),
                mensagem,
                hashlib.sha256
        )
        hmac_mensagem = hmac_sha256.hexdigest()

        print ("[" + entidade + ":" + str(i) + "] hmac: " + hmac_mensagem)

        sock.sendall(mensagem + b' ' + hmac_mensagem.encode('utf-8'))

        chave_secreta = hash_nova_chave(chave_secreta, nonce)

        print (" ")

    sock.close()

def main():

    if len(sys.argv) < 7:
        uso()

    chave_secreta = aes_atualiza_chave(sys.argv[5])

    if sys.argv[3] == "servidor":
        servidor(
                sys.argv[1], # ip
                int(sys.argv[2]), # porta
                sys.argv[4], # entidade (Alice|Bob)
                chave_secreta, # chave secreta
                int(sys.argv[6])  # numero de trocas de chave
                )
    elif sys.argv[3] == "cliente":
        cliente(
                sys.argv[1], # ip
                int(sys.argv[2]), # porta
                sys.argv[4], # entidade (Alice|Bob)
                chave_secreta, # chave secreta
                int(sys.argv[6])  # numero de trocas de chave
                )
    else:
        uso()

if __name__ == "__main__":
    main()

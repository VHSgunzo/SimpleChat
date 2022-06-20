#!/bin/python
import socket
from time import sleep
from threading import Thread


def send_message(message, socket):
    for send_attempt in range(3):
        try:
            socket.send(message)
            return True
        except BrokenPipeError:
            pass
    else:
        print('[!] Не удалось доставить сообщение одному из клиентов')
        if socket in client_sockets:
            client_sockets.remove(socket)
        socket.close()
        return False


def listen_for_client(client):
    while True:
        try:
            client_message = client.recv(4096)
            for client_socket in client_sockets:
                send_message(client_message, client_socket)
        except Exception:
            print('[-] Клиент отключился')
            if client in client_sockets:
                client_sockets.remove(client)
            client.close()
            quit()
        sleep(0.1)


if __name__ == '__main__':
    server_host = '0.0.0.0'
    server_port = 5002
    try:
        client_sockets = []
        server_socket = socket.socket()
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((server_host, server_port))
        server_socket.listen(5)
        print(f'[*] Сервер запущен: [{server_host}:{server_port}]')
        while True:
            client_socket, client_address = server_socket.accept()
            client_address = ':'.join(map(str, client_address))
            print(f'[+] Новый клиент: [{client_address}]')
            client_sockets.append(client_socket)
            server_thread = Thread(target=listen_for_client, args=(client_socket,))
            server_thread.daemon = True
            server_thread.start()
    except (KeyboardInterrupt, EOFError):
        print()
        for client_socket in client_sockets:
            client_socket.close()
        server_socket.close()
        quit()

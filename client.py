#!/bin/python
import urwid
import socket
import secrets
import binascii
from time import sleep, time
from datetime import datetime
from collections import deque
from cryptography.exceptions import InvalidTag
from threading import Thread, Lock, current_thread
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class FocusMixin(object):
    def mouse_event(self, size, event, button, x, y, focus):
        if focus and hasattr(self, '_got_focus') and self._got_focus:
            self._got_focus()
        return super(FocusMixin, self).mouse_event(size, event, button, x, y, focus)


class ListView(FocusMixin, urwid.ListBox):
    def __init__(self, model, got_focus, max_size=None):
        urwid.ListBox.__init__(self, model)
        self._got_focus = got_focus
        self.max_size = max_size
        self._lock = Lock()

    def add(self, line):
        with self._lock:
            was_on_end = self.get_focus()[1] == len(self.body) - 1
            if self.max_size and len(self.body) > self.max_size:
                del self.body[0]
            self.body.append(urwid.Text(line))
            last = len(self.body) - 1
            if was_on_end:
                self.set_focus(last, 'above')


class Input(FocusMixin, urwid.Edit):
    signals = ['line_entered']

    def __init__(self, got_focus=None):
        urwid.Edit.__init__(self)
        self.history = deque(maxlen=1000)
        self._history_index = -1
        self._got_focus = got_focus

    def keypress(self, size, key):
        if key == 'enter':
            line = self.edit_text.strip()
            if line:
                urwid.emit_signal(self, 'line_entered', line)
                self.history.append(line)
            self._history_index = len(self.history)
            self.edit_text = u''
        if key == 'up':
            self._history_index -= 1
            if self._history_index < 0:
                self._history_index = 0
            else:
                self.edit_text = self.history[self._history_index]
        if key == 'down':
            self._history_index += 1
            if self._history_index >= len(self.history):
                self._history_index = len(self.history)
                self.edit_text = u''
            else:
                self.edit_text = self.history[self._history_index]
        else:
            urwid.Edit.keypress(self, size, key)


class Chat(urwid.Frame):
    PALLETE = [('reversed', urwid.BLACK, urwid.LIGHT_CYAN),
               ('normal', urwid.LIGHT_CYAN, urwid.BLACK),
               ('error', urwid.LIGHT_RED, urwid.BLACK),
               ('green', urwid.DARK_GREEN, urwid.BLACK),
               ('blue', urwid.LIGHT_BLUE, urwid.BLACK),
               ('magenta', urwid.DARK_MAGENTA, urwid.BLACK), ]

    def __init__(self, title='', input_prompt=None, max_size=1000):
        self._quit_cmd = ('/q', '/quit')
        self._help_cmd = ('/h', '/help')
        self.header = urwid.Text(title)
        self.model = urwid.SimpleListWalker([])
        self.body = ListView(self.model, lambda: self._update_focus(False), max_size=max_size)
        self.input = Input(lambda: self._update_focus(True))
        foot = urwid.Pile([urwid.AttrMap(urwid.Text(input_prompt), 'reversed'),
                           urwid.AttrMap(self.input, 'normal')])
        urwid.Frame.__init__(self,
                             urwid.AttrWrap(self.body, 'normal'),
                             urwid.AttrWrap(self.header, 'reversed'),
                             foot)
        self.set_focus_path(['footer', 1])
        self._focus = True
        urwid.connect_signal(self.input, 'line_entered', self.on_line_entered)
        self._output_styles = [style[0] for style in self.PALLETE]
        self.eloop = None

    def loop(self, handle_mouse=False):
        self.eloop = urwid.MainLoop(self, self.PALLETE, handle_mouse=handle_mouse)
        self._eloop_thread = current_thread()
        self.eloop.run()

    def on_line_entered(self, line):
        if line in self._quit_cmd:
            raise urwid.ExitMainLoop()
        elif line in self._help_cmd:
            quit_cmds = ' | '.join(self._quit_cmd)
            help_cmds = ' | '.join(self._help_cmd)
            help_output = '\n[ %s ] - выход\n' % quit_cmds
            help_output += '[ %s ] - вывести это сообщение\n' % help_cmds
            self.output(help_output, 'normal')
        else:
            message_to_send = line
            date_now = datetime.now().strftime('%Y.%m.%d %H:%M:%S')
            message_to_send = f'[{date_now}][ {user_name} ]: {message_to_send}'
            message_to_send = encrypt(message_to_send.encode(), secret_key)
            client_socket.send(message_to_send)

    def output(self, line, style=None):
        if style and style in self._output_styles:
            line = (style, line)
        self.body.add(line)
        if self.eloop and self._eloop_thread != current_thread():
            self.eloop.draw_screen()

    def _update_focus(self, focus):
        self._focus = focus

    def switch_focus(self):
        if self._focus:
            self.set_focus('body')
            self._focus = False
        else:
            self.set_focus_path(['footer', 1])
            self._focus = True

    def keypress(self, size, key):
        if key == 'tab':
            self.switch_focus()
        return urwid.Frame.keypress(self, size, key)


def encrypt(message: bytes, key: bytes) -> bytes:
    current_time = int(time()).to_bytes(8, 'big')
    algorithm = algorithms.AES(key)
    iv = secrets.token_bytes(algorithm.block_size // 8)
    cipher = Cipher(algorithm, modes.GCM(iv), backend=crypto_backend)
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(current_time)
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return b64e(current_time + iv + cipher_text + encryptor.tag)


def decrypt(token: bytes, key: bytes, ttl=None) -> bytes:
    algorithm = algorithms.AES(key)
    try:
        data = b64d(token)
    except (TypeError, binascii.Error):
        raise InvalidTag
    timestamp, iv, tag = data[:8], data[8:algorithm.block_size // 8 + 8], data[-16:]
    if ttl is not None:
        current_time = int(time())
        time_encrypted, = int.from_bytes(data[:8], 'big')
        if time_encrypted + ttl < current_time or current_time + 60 < time_encrypted:
            raise InvalidTag
    cipher = Cipher(algorithm, modes.GCM(iv, tag), backend=crypto_backend)
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(timestamp)
    cipher_text = data[8 + len(iv):-16]
    return decryptor.update(cipher_text) + decryptor.finalize()


def listen_for_messages(socket):
    while True:
        received_message = socket.recv(4096)
        if received_message:
            try:
                received_message = decrypt(received_message, secret_key).decode()
                chat.output(received_message, 'green')
            except (ValueError, InvalidTag):
                pass
        else:
            chat.output('[!] Сервер не отвечает', 'error')
            quit()
        sleep(0.1)


def try_connect_to_server(host, port):
    client_socket = socket.socket()
    print(f'[*] Подключение к {host}:{port}...')
    while True:
        try:
            client_socket.connect((host, port))
            print('[+] Успешно подключено')
            break
        except (ConnectionRefusedError, TimeoutError):
            print('[!] Ошибка подключения')
        sleep(2)
    return client_socket


def start_client_thread(thread_target, socket):
    client_thread = Thread(target=thread_target, args=(socket,))
    client_thread.daemon = True
    client_thread.start()
    return client_thread


if __name__ == '__main__':
    server_host = '127.0.0.1'
    server_port = 5002
    # user_name = 'user'
    # Для создания secret_key запустить secret_keygen.py
    secret_key = b'H\x9a\xcc\x02\xf0\x01{o\xf3D\xd6\x1c$\xcd\x00\\\xca*H\x90\xbe\xd1\xf6q\x0b/I\x9b\xaeoi\x92'
    try:
        # while not (server_host := input('[?] Введите IP или имя сервера (127.0.0.1) : ')):
        #     print('[!] Необходимо ввести IP или имя сервера\n')
        # while not (server_port := int(input('[?] Введите порт (5002): '))):
        #     print('[!] Необходимо ввести порт\n')
        while not (user_name := input('[?] Введите свое имя : ')):
            print('[!] Необходимо ввести своё имя\n')
        chat = Chat(input_prompt=f'[ {user_name} ] Введите сообщение (Tab чтобы переключить фокус на чат):')
        crypto_backend = default_backend()
        client_socket = try_connect_to_server(server_host, server_port)
        client_thread = start_client_thread(listen_for_messages, client_socket)
        chat.loop()
    except (KeyboardInterrupt, ValueError):
        try:
            client_socket.close()
            quit()
        except NameError:
            pass

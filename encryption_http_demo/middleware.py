import base64
import binascii
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography import exceptions
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Scope, Receive, Send, Message


class _BufferTag:
    """
    Separate tag from bytes, assuming that tag is appended to end of data.

    :param length: tag length
    """

    def __init__(self, length: int):
        self._buf = b''
        self._len = length
        self._is_finalize = False

    def update(self, s: bytes) -> bytes:
        """
        Input data bytes and return non-tag part ciphertext.

        :param s: data bytes
        :return: ciphertext
        """
        if self._is_finalize:
            raise ValueError('finalized')
        self._buf += s
        front = self._buf[:-self._len]
        self._buf = self._buf[-self._len:]
        return front

    def finalize(self) -> bytes:
        """
        Get tag bytes and disable continue to update.

        :return: tag bytes
        """
        self._is_finalize = True
        return self._buf


class ExceptionWrapper(Exception):
    pass


class EncryptionMiddleware:
    """
    AES-256-GCM encryption, nonce and tag length will be stored in HTTP headers,
    the key of nonce is `ENCRYPTION-NONCE`, and the key of tag length is `ENCRYPTION-TAG-LENGTH`.

    :param secret_key: This must be kept secret.
    """

    def __init__(self, app: ASGIApp, secret_key: str | bytes) -> None:
        self.app = app

        # Ensure the key length is 256
        if isinstance(secret_key, str):
            secret_key = secret_key.encode('utf-8')
        self._secret_key = hashlib.sha256(secret_key).digest()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        receive_nonce_value = b''
        receive_tag_length_value = b''
        error_msg = ''
        # Get once(iv) and tag length from headers
        for k, v in scope['headers']:
            if k.upper() == b'ENCRYPTION-NONCE':
                receive_nonce_value = v
            elif k.upper() == b'ENCRYPTION-TAG-LENGTH':
                receive_tag_length_value = v
        receive_nonce = b''
        try:
            receive_nonce = base64.b64decode(receive_nonce_value)
            assert len(receive_nonce) == 16, 'length of ENCRYPTION-NONCE must be 16'
        except binascii.Error:
            error_msg = 'can not decode ENCRYPTION-NONCE'
        except AssertionError as err:
            error_msg = str(err)
        receive_tag_length = 0
        try:
            receive_tag_length = int(receive_tag_length_value)
            assert 1 <= receive_tag_length <= 16, 'ENCRYPTION-TAG-LENGTH must be between 1 and 16'
        except ValueError:
            error_msg = 'ENCRYPTION-TAG-LENGTH must be number'
        except AssertionError as err:
            error_msg = str(err)

        send_nonce = os.urandom(16)
        send_algorithm = algorithms.AES(self._secret_key)
        send_cipher = Cipher(send_algorithm, mode=modes.GCM(send_nonce))
        send_encryptor = send_cipher.encryptor()
        if not error_msg:
            async def send_wrapper(message: Message) -> None:
                if message['type'] == 'http.response.start':
                    message['headers'].append((b'ENCRYPTION-NONCE', base64.b64encode(send_nonce)))
                    message['headers'].append((b'ENCRYPTION-TAG-LENGTH', b'16'))
                if message['type'] == 'http.response.body':
                    message['body'] = send_encryptor.update(message['body'])
                    if not message.get('more_body'):
                        message['body'] += send_encryptor.finalize() + send_encryptor.tag
                await send(message)

            buf = _BufferTag(receive_tag_length)
            receive_algorithm = algorithms.AES(self._secret_key)
            # Set the second parameter of GCM to None, because the tag cannot be obtained immediately.
            receive_cipher = Cipher(receive_algorithm, mode=modes.GCM(receive_nonce))
            receive_decryptor = receive_cipher.decryptor()

            async def receive_wrapper() -> Message:
                message = await receive()
                data = buf.update(message['body'])
                try:
                    message['body'] = receive_decryptor.update(data)
                    if not message.get('more_body'):
                        # Call `finalize_with_tag` instead of `finalize` to delay validation of the authentication tag.
                        message['body'] += receive_decryptor.finalize_with_tag(buf.finalize())
                except exceptions.InvalidTag as error:
                    raise ExceptionWrapper('invalid tag') from error
                return message

            try:
                await self.app(scope, receive_wrapper, send_wrapper)
                return
            except ExceptionWrapper as err:
                error_msg = str(err)

        encrypted = send_encryptor.update(
            error_msg.encode('utf-8')) + send_encryptor.finalize() + send_encryptor.tag
        err_response = PlainTextResponse(encrypted, status_code=422,
                                    headers={'ENCRYPTION-NONCE': base64.b64encode(send_nonce).decode('utf-8'),
                                             'ENCRYPTION-TAG-LENGTH': '16'})
        await err_response(scope, receive, send)

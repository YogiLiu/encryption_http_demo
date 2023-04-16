__all__ = ['application']

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse, StreamingResponse
from starlette.routing import Route
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

        receive_nonce = b''
        receive_tag_length = 0
        # Get once(iv) and tag length from headers
        for k, v in scope['headers']:
            if k.upper() == b'ENCRYPTION-NONCE':
                receive_nonce = base64.b64decode(v)
            if k.upper() == b'ENCRYPTION-TAG-LENGTH':
                receive_tag_length = int(v)
        buf = _BufferTag(receive_tag_length)
        if receive_nonce == b'':
            err_res = PlainTextResponse('empty nonce', status_code=422)
            await err_res(scope, receive, send)
            return
        if receive_tag_length == 0:
            err_res = PlainTextResponse('zero-length tag', status_code=422)
            await err_res(scope, receive, send)
            return
        receive_algorithm = algorithms.AES(self._secret_key)
        # Set the second parameter of GCM to None, because the tag cannot be obtained immediately.
        receive_cipher = Cipher(receive_algorithm, mode=modes.GCM(receive_nonce))
        receive_decryptor = receive_cipher.decryptor()

        async def receive_wrapper() -> Message:
            # FIXME: How to return an error response if an error occurs during decryption?
            # https://www.starlette.io/middleware/#pure-asgi-middleware
            message = await receive()
            data = buf.update(message['body'])
            message['body'] = receive_decryptor.update(data)
            if not message.get('more_body'):
                # Call `finalize_with_tag` instead of `finalize` to delay validation of the authentication tag.
                message['body'] += receive_decryptor.finalize_with_tag(buf.finalize())
            return message

        send_nonce = os.urandom(16)
        send_algorithm = algorithms.AES(self._secret_key)
        send_cipher = Cipher(send_algorithm, mode=modes.GCM(send_nonce))
        send_encryptor = send_cipher.encryptor()

        async def send_wrapper(message: Message) -> None:
            if message['type'] == 'http.response.start':
                message['headers'].append((b'ENCRYPTION-NONCE', base64.b64encode(send_nonce)))
                message['headers'].append((b'ENCRYPTION-TAG-LENGTH', b'16'))
            if message['type'] == 'http.response.body':
                message['body'] = send_encryptor.update(message['body'])
                if not message.get('more_body'):
                    message['body'] += send_encryptor.finalize() + send_encryptor.tag
            await send(message)

        await self.app(scope, receive_wrapper, send_wrapper)


async def plain(request: Request) -> Response:
    data = await request.body()
    return PlainTextResponse(content=data)


async def stream(request: Request) -> Response:
    body = await request.body()

    async def inner():
        for i in range(len(body)):
            yield body[i:i+1]

    return StreamingResponse(content=inner())


application = Starlette(
    routes=[
        Route('/plain', plain, methods=['POST']),
        Route('/stream', stream, methods=['POST']),
    ],
    middleware=[
        Middleware(EncryptionMiddleware, secret_key='secret_key')
    ]
)

import base64
import hashlib
import random
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from httpx import AsyncClient

from encryption_http_demo.web import application


class TestEncryption(unittest.IsolatedAsyncioTestCase):
    raw = random.randbytes(1024)
    key = hashlib.sha256('secret_key'.encode('utf-8')).digest()
    aesgcm = AESGCM(key)
    nonce = b'1' * 16
    encrypted = aesgcm.encrypt(nonce, raw, None)

    async def asyncSetUp(self) -> None:
        self.secret_key = b'secret_key'
        self.client = AsyncClient(app=application, base_url='http://testserver', timeout=1)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def test_plain(self):
        res = await self.client.post('/plain', content=self.encrypted,
                                     headers={'ENCRYPTION-NONCE': base64.b64encode(self.nonce),
                                              'ENCRYPTION-TAG-LENGTH': b'16'})
        res_nonce = res.headers['ENCRYPTION-NONCE'].encode('utf-8')
        self.assertEqual(self.raw, self.aesgcm.decrypt(base64.b64decode(res_nonce), res.content, None))

    async def test_empty_nonce(self):
        res = await self.client.post('/plain', content=self.encrypted,
                                     headers={'ENCRYPTION-TAG-LENGTH': b'16'})
        self.assertEqual(422, res.status_code)
        self.assertEqual('empty nonce', res.text)

    async def test_zero_length_tag(self):
        res = await self.client.post('/plain', content=self.encrypted,
                                     headers={'ENCRYPTION-NONCE': base64.b64encode(self.nonce),
                                              'ENCRYPTION-TAG-LENGTH': b'0'})
        self.assertEqual(422, res.status_code)
        self.assertEqual('zero-length tag', res.text)

    async def test_stream(self):
        async def inner():
            for i in range(len(self.encrypted)):
                yield self.encrypted[i:i+1]
        res = await self.client.post('/stream', content=inner(),
                                     headers={'ENCRYPTION-NONCE': base64.b64encode(self.nonce),
                                              'ENCRYPTION-TAG-LENGTH': b'16'})
        res_nonce = res.headers['ENCRYPTION-NONCE'].encode('utf-8')
        self.assertEqual(self.raw, self.aesgcm.decrypt(base64.b64decode(res_nonce), res.content, None))

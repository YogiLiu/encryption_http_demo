__all__ = ['application']

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse, StreamingResponse
from starlette.routing import Route

from encryption_http_demo.middleware import EncryptionMiddleware


async def plain(request: Request) -> Response:
    data = await request.body()
    return PlainTextResponse(content=data)


async def stream(request: Request) -> Response:
    body = await request.body()

    async def inner():
        for i in range(len(body)):
            yield body[i:i + 1]

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

"""Bound unauthenticated enrollment bodies before JSON parsing."""

from starlette.responses import JSONResponse


class EnrollmentBodyLimit:
    def __init__(self, app, max_bytes: int = 64 * 1024):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        enrollment = path == "/api/agent/v1/enroll" or path.startswith("/api/agent/v1/register")
        if scope["type"] != "http" or not enrollment:
            await self.app(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await JSONResponse({"detail": "بدنهٔ ثبت‌نام بیش از حد مجاز است."}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def bounded_receive():
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, bounded_receive, send)

"""Local HTTP adapter. Upload bytes stay in memory and are never logged."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from packet_trail.analysis import analyze
from packet_trail.parser import MAX_CAPTURE_BYTES, CaptureError

ROOT = Path(__file__).parent
MAX_REQUEST_BYTES = MAX_CAPTURE_BYTES + 64 * 1024
SAMPLES = [
    {
        "id": "normal",
        "name": "Steady conversations",
        "description": "144 synthetic packets: short TCP exchanges and DNS-port UDP traffic over 19 seconds.",
    },
    {
        "id": "syn-burst",
        "name": "A concentrated SYN burst",
        "description": "The same baseline with 240 initial SYNs in one UTC second. Both heuristic flags should appear.",
    },
]


class RequestTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Count actual streamed bytes too; Content-Length alone is not a bound."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != "/api/analyze":
            await self.app(scope, receive, send)
            return
        total = 0

        async def bounded_receive() -> Message:
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > MAX_REQUEST_BYTES:
                raise RequestTooLarge
            return message

        try:
            length = dict(scope["headers"]).get(b"content-length")
            if length and int(length) > MAX_REQUEST_BYTES:
                raise RequestTooLarge
            await self.app(scope, bounded_receive, send)
        except RequestTooLarge:
            await JSONResponse({"detail": "Upload exceeds the 8 MiB capture limit"}, status_code=413)(
                scope, receive, send
            )


class MemoryMultipartParser(MultiPartParser):
    # The body limit is smaller than this spool threshold, so accepted or
    # rejected uploads cannot roll over to an on-disk temporary file.
    spool_max_size = MAX_REQUEST_BYTES + 1


app = FastAPI(title="Packet Trail", version="1.0.0", description="Offline classic-PCAP evidence analysis")
app.add_middleware(BodyLimitMiddleware)


@app.middleware("http")
async def privacy_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    )
    return response


@app.exception_handler(CaptureError)
async def invalid_capture(request: Request, error: CaptureError) -> JSONResponse:
    return JSONResponse({"detail": str(error)}, status_code=422)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": "1.0.0", "mode": "offline"}


@app.get("/api/samples")
async def samples() -> list[dict]:
    return SAMPLES


@app.get("/api/samples/{sample_id}/analyze")
async def sample_analysis(sample_id: str) -> dict:
    if sample_id not in {sample["id"] for sample in SAMPLES}:
        raise HTTPException(404, "Unknown sample")
    return await run_in_threadpool(
        analyze, (ROOT / "samples" / f"{sample_id}.pcap").read_bytes(), f"{sample_id}.pcap"
    )


@app.get("/api/samples/{sample_id}/download")
async def sample_download(sample_id: str) -> FileResponse:
    if sample_id not in {sample["id"] for sample in SAMPLES}:
        raise HTTPException(404, "Unknown sample")
    return FileResponse(
        ROOT / "samples" / f"{sample_id}.pcap",
        media_type="application/vnd.tcpdump.pcap",
        filename=f"{sample_id}.pcap",
    )


@app.post("/api/analyze")
async def upload_analysis(request: Request) -> dict:
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise HTTPException(415, "Send one capture as a multipart field named 'file'")
    parser = MemoryMultipartParser(request.headers, request.stream(), max_files=1, max_fields=0)
    try:
        form = await parser.parse()
    except MultiPartException as error:
        raise HTTPException(400, str(error)) from error
    except BaseException:
        for temporary in parser._files_to_close_on_error:
            temporary.close()
        raise
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise HTTPException(400, "A single file field named 'file' is required")
        data = await upload.read(MAX_CAPTURE_BYTES + 1)
        if len(data) > MAX_CAPTURE_BYTES:
            raise HTTPException(413, "Capture exceeds the 8 MiB limit")
        name = (upload.filename or "capture.pcap").replace("\\", "/").rsplit("/", 1)[-1][:120]
        return await run_in_threadpool(analyze, data, name)
    finally:
        await form.close()


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(ROOT / "static" / "index.html")


app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

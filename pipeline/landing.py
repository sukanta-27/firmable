import hashlib
import time
from datetime import UTC, datetime
from pathlib import Path

import zstandard

from pipeline.meta import Manifest

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
CHUNK = 1 << 22


class LandingError(Exception):
    pass


def land(path: Path) -> Manifest:
    """Hash, integrity-check and count the lines of a source file in one read.

    The line count is taken here, independently of the parser, so bronze can prove
    it neither dropped nor invented records.
    """
    started = time.time()
    with path.open("rb") as f:
        compression = "zstd" if f.read(4) == ZSTD_MAGIC else "none"
        f.seek(0)
        sha = hashlib.sha256()
        newlines = 0
        last = b""
        # Frames are fed by hand because zstandard's stream_reader returns a truncated
        # file's partial content without raising.
        dctx = zstandard.ZstdDecompressor()
        dobj = dctx.decompressobj()
        mid_frame = False
        while chunk := f.read(CHUNK):
            sha.update(chunk)
            if compression == "none":
                newlines += chunk.count(b"\n")
                last = chunk[-1:]
                continue
            while chunk:
                try:
                    out = dobj.decompress(chunk)
                except zstandard.ZstdError as e:
                    raise LandingError(f"{path}: corrupt zstd data: {e}") from e
                mid_frame = True
                if out:
                    newlines += out.count(b"\n")
                    last = out[-1:]
                if dobj.eof:
                    chunk = dobj.unused_data
                    dobj = dctx.decompressobj()
                    mid_frame = False
                else:
                    chunk = b""
        if mid_frame:
            raise LandingError(f"{path}: zstd stream ends mid-frame (truncated download?)")

    lines = newlines + (1 if last not in (b"", b"\n") else 0)
    return Manifest(
        file_id=sha.hexdigest(),
        source_uri=str(path.resolve()),
        size_bytes=path.stat().st_size,
        compression=compression,
        received_at=datetime.now(UTC),
        lines=lines,
        landing_seconds=time.time() - started,
    )

"""Remove or mask selected headers in a bodyless HTTP/1.1 excerpt."""

import argparse
from pathlib import Path
import re
import stat
import sys
import tempfile


_OWS = " \t"
_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_NAME = re.compile(_TOKEN)
_START_LINE = re.compile(
    rf"(?:{_TOKEN} [^ \t]+ HTTP/1\.1|HTTP/1\.1 [0-9]{{3}}(?: .*)?)"
)
_INVALID_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_AUTH = re.compile(r"(Basic|Bearer)[ \t]+[A-Za-z0-9._~+/\-]+=*", re.IGNORECASE | re.ASCII)
_COOKIE_OCTETS = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*")
_TARGETS = {"authorization", "cookie", "set-cookie"}
_FLAGS = {"secure", "httponly"}
_SAME_SITE = {"strict", "lax", "none"}
_MASK = "MASKED"


class FragmentError(ValueError):
    """The input does not contain a supported HTTP header block."""


def _mask_authorization(value: str) -> str | None:
    match = _AUTH.fullmatch(value.strip(_OWS))
    return f"{match[1]} {_MASK}" if match else None


def _mask_cookie_pair(pair: str) -> str | None:
    name, separator, value = pair.strip(_OWS).partition("=")
    name, value = name.rstrip(_OWS), value.lstrip(_OWS)
    if not separator or not _NAME.fullmatch(name):
        return None

    # HTTP cookie values may be optionally enclosed in double quotes.
    contents = value
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        contents = value[1:-1]
    if not _COOKIE_OCTETS.fullmatch(contents):
        return None
    return f"{name}={_MASK if contents else value}"


def _mask_cookie(value: str) -> str | None:
    masked_pairs = []
    for pair in value.split(";"):
        masked = _mask_cookie_pair(pair)
        if masked is None:
            return None
        masked_pairs.append(masked)
    return "; ".join(masked_pairs)


def _mask_set_cookie(value: str) -> str | None:
    pair, *attributes = value.split(";")
    masked = _mask_cookie_pair(pair)
    if masked is None:
        return None

    kept = [masked]
    for attribute in attributes:
        name, separator, argument = attribute.strip(_OWS).partition("=")
        name, argument = name.rstrip(_OWS), argument.lstrip(_OWS)
        if not _NAME.fullmatch(name):
            return None
        key = name.lower()
        if key in _FLAGS:
            if separator:
                return None
            kept.append(name)
        elif key == "samesite":
            if not separator:
                return None
            if argument.lower() in _SAME_SITE:
                kept.append(f"{name}={argument}")
    return "; ".join(kept)


_MASK_HEADER = {
    "authorization": _mask_authorization,
    "cookie": _mask_cookie,
    "set-cookie": _mask_set_cookie,
}


def process_fragment(text: str, mode: str) -> str:
    """Return the transformed excerpt or raise FragmentError for a malformed block."""
    if mode not in {"remove", "mask"}:
        raise ValueError("mode must be remove or mask")

    # Split only on LF, retaining CR so that each original line ending survives.
    lines = text.split("\n")
    if len(lines) < 3 or lines[-1] or lines[-2] not in ("", "\r"):
        raise FragmentError("missing final blank line or unexpected message body")

    start = lines[0].removesuffix("\r")
    if _INVALID_CONTROL.search(start) or not _START_LINE.fullmatch(start):
        raise FragmentError("invalid HTTP/1.1 start line")

    output = [lines[0]]
    for raw in lines[1:-2]:
        line = raw.removesuffix("\r")
        if line.startswith((" ", "\t")):
            raise FragmentError("folded header line")
        name, separator, value = line.partition(":")
        if not separator or not _NAME.fullmatch(name) or _INVALID_CONTROL.search(value):
            raise FragmentError("invalid header line or unexpected message body")
        key = name.lower()
        if key not in _TARGETS:
            output.append(raw)
        elif mode == "mask":
            masked = _MASK_HEADER[key](value)
            if masked is not None:
                suffix = "\r" if raw.endswith("\r") else ""
                output.append(f"{name}: {masked}{suffix}")
    return "\n".join(output + lines[-2:])


def _write_file(path: Path, data: bytes) -> None:
    """Replace a regular file only after writing the complete output."""
    path = path.resolve()
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        mode = None
    if mode is not None and not stat.S_ISREG(mode):
        raise OSError("output path is not a regular file")

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".mask-http-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        if mode is not None:
            temporary.chmod(stat.S_IMODE(mode) & 0o777)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("remove", "mask"))
    parser.add_argument("-i", "--input", default="-", help="input file (default: stdin)")
    parser.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    args = parser.parse_args(argv)

    try:
        source = sys.stdin.buffer.read() if args.input == "-" else Path(args.input).read_bytes()
        text = source.decode("utf-8", errors="surrogateescape")
        result = process_fragment(text, args.mode).encode("utf-8", errors="surrogateescape")
        if args.output == "-":
            sys.stdout.buffer.write(result)
            sys.stdout.buffer.flush()
        else:
            _write_file(Path(args.output), result)
    except FragmentError as error:
        print(f"mask_http: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("mask_http: input or output error", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""RS256 JWTs with a JWKS, in pure Python (dev only).

Real deployments get keys from Keycloak; this module exists so the PoC runs without
installing anything and so agentgateway can verify tokens through a JWKS URL.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

# DER prefix of DigestInfo for SHA-256 (RFC 8017 §9.2, note 1)
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_E = 65537


class TokenError(Exception):
    pass


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int_b64(value: int) -> str:
    return b64url(value.to_bytes((value.bit_length() + 7) // 8, "big"))


def _b64_int(text: str) -> int:
    return int.from_bytes(unb64url(text), "big")


# --- RSA ------------------------------------------------------------------------------

_SMALL_PRIMES = [p for p in range(3, 2000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def _probable_prime(n: int, rounds: int = 40) -> bool:
    if any(n % p == 0 for p in _SMALL_PRIMES):
        return n in _SMALL_PRIMES
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if math.gcd(candidate - 1, _E) == 1 and _probable_prime(candidate):
            return candidate


def _emsa_pkcs1_v15(data: bytes, k: int) -> int:
    t = _SHA256_PREFIX + hashlib.sha256(data).digest()
    return int.from_bytes(b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t, "big")


@dataclass(frozen=True)
class RsaKey:
    kid: str
    n: int
    d: int
    p: int
    q: int

    @classmethod
    def generate(cls, bits: int = 2048) -> "RsaKey":
        while True:
            p, q = _prime(bits // 2), _prime(bits // 2)
            if p != q and (p * q).bit_length() == bits:
                break
        d = pow(_E, -1, (p - 1) * (q - 1))
        return cls(secrets.token_hex(8), p * q, d, p, q)

    def to_dict(self) -> dict[str, Any]:
        return {"kid": self.kid, "n": str(self.n), "d": str(self.d), "p": str(self.p), "q": str(self.q)}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RsaKey":
        return cls(data["kid"], int(data["n"]), int(data["d"]), int(data["p"]), int(data["q"]))

    def public_jwk(self) -> dict[str, str]:
        return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid, "n": _int_b64(self.n), "e": _int_b64(_E)}

    def sign(self, data: bytes) -> bytes:
        k = (self.n.bit_length() + 7) // 8
        m = _emsa_pkcs1_v15(data, k)
        # CRT: about 3x faster than pow(m, d, n)
        s1, s2 = pow(m, self.d % (self.p - 1), self.p), pow(m, self.d % (self.q - 1), self.q)
        s = s2 + self.q * ((pow(self.q, -1, self.p) * (s1 - s2)) % self.p)
        return s.to_bytes(k, "big")


def verify_rs256(jwk: dict[str, Any], data: bytes, signature: bytes) -> bool:
    n, e = _b64_int(jwk["n"]), _b64_int(jwk["e"])
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    return pow(int.from_bytes(signature, "big"), e, n) == _emsa_pkcs1_v15(data, k)


# --- JWT ------------------------------------------------------------------------------

def encode(claims: dict[str, Any], key: RsaKey) -> str:
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": key.kid}, separators=(",", ":")).encode())
    payload = b64url(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signing_input = f"{header}.{payload}"
    return f"{signing_input}.{b64url(key.sign(signing_input.encode()))}"


def unverified_claims(token: str) -> dict[str, Any]:
    return json.loads(unb64url(token.split(".")[1]))


def decode(token: str, find_key: Callable[[str], dict[str, Any] | None], *,
           audience: str | Iterable[str], issuer: str) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
        header = json.loads(unb64url(header_b64))
        claims = json.loads(unb64url(payload_b64))
        signature = unb64url(signature_b64)
    except ValueError as e:
        raise TokenError("malformed token") from e
    if header.get("alg") != "RS256":
        raise TokenError("unsupported alg")
    jwk = find_key(header.get("kid", ""))
    if jwk is None:
        raise TokenError("unknown signing key")
    if not verify_rs256(jwk, f"{header_b64}.{payload_b64}".encode(), signature):
        raise TokenError("bad signature")
    if claims.get("iss") != issuer:
        raise TokenError("issuer mismatch")
    if claims.get("exp", 0) < time.time():
        raise TokenError("token expired")
    wanted = {audience} if isinstance(audience, str) else set(audience)
    aud = claims.get("aud")
    if not wanted & set(aud if isinstance(aud, list) else [aud]):
        raise TokenError(f"audience mismatch (expected {sorted(wanted)})")
    return claims

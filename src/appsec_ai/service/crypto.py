"""Cifrado en reposo de los datos del cliente (resultados de escaneos, correcciones y caché del triage).

Fernet (AES-128-CBC + HMAC-SHA256). DATA_ENCRYPTION_KEY admite varias claves separadas por comas:
la primera cifra y todas descifran, lo que permite rotar la clave sin perder datos.
Genera una con: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

import json

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

SEALED = "appsec-ai:fernet:v1"


class DecryptionError(RuntimeError):
    pass


class Cipher:
    def __init__(self, keys: str):
        parts = [k.strip() for k in keys.split(",") if k.strip()]
        if not parts:
            raise ValueError("DATA_ENCRYPTION_KEY vacía")
        self._fernet = MultiFernet([Fernet(k.encode()) for k in parts])

    @classmethod
    def from_keys(cls, keys: str) -> "Cipher | None":
        return cls(keys) if keys.strip() else None

    def encrypt(self, data: bytes) -> bytes:
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        try:
            return self._fernet.decrypt(token)
        except InvalidToken:
            raise DecryptionError("no se puede descifrar: clave incorrecta o datos alterados") from None


def seal(cipher: Cipher | None, obj):
    """Valor JSON para guardar en la base de datos: cifrado si hay clave, tal cual si no."""
    if cipher is None or obj is None:
        return obj
    token = cipher.encrypt(json.dumps(obj, ensure_ascii=False).encode()).decode()
    return {"_sealed": SEALED, "data": token}


def unseal(cipher: Cipher | None, value):
    """Inverso de seal. Las filas antiguas sin cifrar se devuelven tal cual."""
    if not (isinstance(value, dict) and value.get("_sealed") == SEALED):
        return value
    if cipher is None:
        raise DecryptionError("hay datos cifrados pero DATA_ENCRYPTION_KEY no está configurada")
    return json.loads(cipher.decrypt(value["data"].encode()))

import pytest
from cryptography.fernet import Fernet

from appsec_ai.service.crypto import Cipher, DecryptionError, seal, unseal


def test_seal_roundtrip_and_plaintext_rows_still_readable():
    c = Cipher(Fernet.generate_key().decode())
    data = {"findings": [{"snippet": "return eval(answer)"}]}
    sealed = seal(c, data)
    assert "eval" not in str(sealed)
    assert unseal(c, sealed) == data
    assert unseal(c, {"findings": []}) == {"findings": []}  # filas anteriores al cifrado
    assert seal(None, data) is data and seal(c, None) is None


def test_key_rotation_reads_old_data_and_writes_with_new_key():
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    sealed_old = seal(Cipher(old), {"a": 1})
    rotated = Cipher(f"{new},{old}")
    assert unseal(rotated, sealed_old) == {"a": 1}
    assert unseal(Cipher(new), seal(rotated, {"b": 2})) == {"b": 2}


def test_wrong_or_missing_key_fails_loudly():
    sealed = seal(Cipher(Fernet.generate_key().decode()), {"a": 1})
    with pytest.raises(DecryptionError, match="clave incorrecta"):
        unseal(Cipher(Fernet.generate_key().decode()), sealed)
    with pytest.raises(DecryptionError, match="no está configurada"):
        unseal(None, sealed)
    assert Cipher.from_keys(" ") is None

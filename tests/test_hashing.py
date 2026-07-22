import hashlib

from consentml.hashing import hash_subject_id


def test_hash_is_sha256_hex_of_utf8():
    assert (
        hash_subject_id("user@example.com")
        == hashlib.sha256(b"user@example.com").hexdigest()
    )


def test_hash_is_deterministic():
    assert hash_subject_id("abc") == hash_subject_id("abc")


def test_non_string_ids_are_coerced_to_str():
    assert hash_subject_id(42) == hash_subject_id("42")

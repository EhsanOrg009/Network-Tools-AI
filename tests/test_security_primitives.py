"""Untrusted credential text must fail authentication without crashing."""

import pytest

from netagent.security import hash_secret, sign_task, verify_admin_token, verify_task_signature


@pytest.mark.parametrize("presented", ["invalid-é", "توکن نامعتبر", "wrong"])
def test_invalid_admin_tokens_return_false(presented):
    expected = "administrator-token-long"
    assert not verify_admin_token(presented, expected, None)
    assert not verify_admin_token(presented, None, hash_secret(expected))


def test_explicit_unicode_admin_token_still_authenticates():
    token = "توکن-مدیر-پیکربندی-صریح"
    assert verify_admin_token(token, token, None)
    assert verify_admin_token(token, None, hash_secret(token))


@pytest.mark.parametrize("signature", ["é" * 64, "امضای نامعتبر", "0" * 64])
def test_invalid_signatures_return_false(signature):
    payload = {"task_id": "test"}
    assert not verify_task_signature(payload, "test-key", signature)
    assert verify_task_signature(payload, "test-key", sign_task(payload, "test-key"))

"""Behavior tests for Ed25519 bundle signature verification."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

nacl = pytest.importorskip("nacl")

from nacl.signing import SigningKey  # noqa: E402

from edictum import Edictum  # noqa: E402
from edictum._exceptions import EdictumConfigError  # noqa: E402
from edictum.server.verification import BundleVerificationError, verify_bundle_signature  # noqa: E402

VALID_BUNDLE_YAML = b"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-bundle
defaults:
  mode: enforce
contracts:
  - id: deny-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      effect: deny
      message: "Destructive command denied."
"""


@pytest.fixture
def key_pair():
    sk = SigningKey.generate()
    vk = sk.verify_key
    return sk, vk


def _sign(yaml_bytes: bytes, signing_key: SigningKey) -> str:
    """Sign YAML bytes and return base64-encoded signature."""
    signed = signing_key.sign(yaml_bytes)
    return base64.b64encode(signed.signature).decode("ascii")


def _b64(yaml_bytes: bytes = VALID_BUNDLE_YAML) -> str:
    return base64.b64encode(yaml_bytes).decode("ascii")


def _make_client_mock(*, bundle_name="default", signature=None):
    client = MagicMock()
    client.bundle_name = bundle_name
    client.env = "production"
    client.tags = None
    response = {"yaml_bytes": _b64()}
    if signature is not None:
        response["signature"] = signature
    client.get = AsyncMock(return_value=response)
    client.close = AsyncMock()
    return client


def _make_source_mock():
    source = MagicMock()
    source.connect = AsyncMock()
    source.close = AsyncMock()
    return source


def _server_patches():
    return (
        patch("edictum.server.client.EdictumServerClient"),
        patch("edictum.server.audit_sink.ServerAuditSink"),
        patch("edictum.server.approval_backend.ServerApprovalBackend"),
        patch("edictum.server.backend.ServerBackend"),
        patch("edictum.server.contract_source.ServerContractSource"),
    )


# --- Positive tests ---


class TestValidSignature:
    """verify_bundle_signature accepts valid Ed25519 signatures."""

    def test_valid_signature_passes(self, key_pair):
        """A correctly signed bundle passes verification without error."""
        sk, vk = key_pair
        signature_b64 = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        # Should not raise
        verify_bundle_signature(VALID_BUNDLE_YAML, signature_b64, public_key_hex)

    @pytest.mark.asyncio
    async def test_from_server_with_verification(self, key_pair):
        """from_server() with verify_signatures=True accepts a validly signed bundle."""
        sk, vk = key_pair
        signature_b64 = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock(signature=signature_b64)
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
                verify_signatures=True,
                signing_public_key=public_key_hex,
            )

            assert len(guard._state.preconditions) == 1
            await guard.close()


# --- Security tests ---


class TestTamperedBundle:
    """Tampered bundles are rejected."""

    @pytest.mark.security
    def test_tampered_bundle_rejected(self, key_pair):
        """Modifying the bundle after signing causes verification failure."""
        sk, vk = key_pair
        signature_b64 = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        tampered = VALID_BUNDLE_YAML.replace(b"rm -rf", b"echo hello")

        with pytest.raises(BundleVerificationError, match="tampered"):
            verify_bundle_signature(tampered, signature_b64, public_key_hex)

    @pytest.mark.security
    def test_wrong_key_rejected(self):
        """Signing with key A and verifying with key B fails."""
        sk_a = SigningKey.generate()
        sk_b = SigningKey.generate()
        vk_b = sk_b.verify_key

        signature_b64 = _sign(VALID_BUNDLE_YAML, sk_a)
        public_key_hex = vk_b.encode().hex()

        with pytest.raises(BundleVerificationError, match="tampered"):
            verify_bundle_signature(VALID_BUNDLE_YAML, signature_b64, public_key_hex)


class TestMissingSignature:
    """Missing signatures are rejected when verification is enabled."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_missing_signature_rejected(self, key_pair):
        """Server response without signature raises EdictumConfigError."""
        _sk, vk = key_pair
        public_key_hex = vk.encode().hex()

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            # No signature in response
            mock_cls.return_value = _make_client_mock(signature=None)
            mock_src_cls.return_value = _make_source_mock()

            with pytest.raises(EdictumConfigError, match="does not include a signature"):
                await Edictum.from_server(
                    "https://example.com",
                    "key",
                    "agent-1",
                    bundle_name="default",
                    auto_watch=False,
                    verify_signatures=True,
                    signing_public_key=public_key_hex,
                )


class TestInvalidEncodings:
    """Invalid signature or key encodings are rejected."""

    @pytest.mark.security
    def test_invalid_signature_encoding_rejected(self, key_pair):
        """Garbage base64 signature raises BundleVerificationError."""
        _sk, vk = key_pair
        public_key_hex = vk.encode().hex()

        with pytest.raises(BundleVerificationError, match="base64"):
            verify_bundle_signature(VALID_BUNDLE_YAML, "not-valid-b64!!!", public_key_hex)

    @pytest.mark.security
    def test_invalid_public_key_rejected(self, key_pair):
        """Garbage hex public key raises BundleVerificationError."""
        sk, _vk = key_pair
        signature_b64 = _sign(VALID_BUNDLE_YAML, sk)

        with pytest.raises(BundleVerificationError, match="hex"):
            verify_bundle_signature(VALID_BUNDLE_YAML, signature_b64, "not-valid-hex!!!")

    @pytest.mark.security
    def test_empty_signature_rejected(self, key_pair):
        """Empty string signature raises BundleVerificationError."""
        _sk, vk = key_pair
        public_key_hex = vk.encode().hex()

        with pytest.raises(BundleVerificationError, match="empty"):
            verify_bundle_signature(VALID_BUNDLE_YAML, "", public_key_hex)


class TestSSEVerification:
    """SSE updates are verified when verify_signatures is enabled."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sse_unsigned_bundle_rejected(self, key_pair):
        """SSE update without signature is rejected when verification is enabled."""
        sk, vk = key_pair
        signature_b64 = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock(signature=signature_b64)

            # SSE watch yields an unsigned bundle — should be rejected
            async def mock_watch():
                yield {"yaml_bytes": _b64()}  # No signature field

            source = _make_source_mock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                verify_signatures=True,
                signing_public_key=public_key_hex,
            )

            # Wait for the SSE task to process the unsigned bundle
            await guard._sse_task

            # The initial contracts (1 precondition from from_server) should
            # remain unchanged — the unsigned SSE update was rejected.
            assert len(guard._state.preconditions) == 1
            await guard.close()

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sse_tampered_bundle_rejected(self, key_pair):
        """SSE update with invalid signature is rejected."""
        sk, vk = key_pair
        initial_sig = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        # Sign original YAML, but send different YAML in SSE
        tampered_yaml = VALID_BUNDLE_YAML.replace(b"rm -rf", b"echo hello")

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock(signature=initial_sig)

            async def mock_watch():
                yield {
                    "yaml_bytes": _b64(tampered_yaml),
                    "signature": initial_sig,  # Signature is for VALID_BUNDLE_YAML, not tampered
                }

            source = _make_source_mock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                verify_signatures=True,
                signing_public_key=public_key_hex,
            )

            await guard._sse_task

            # Original contracts preserved — tampered update rejected
            assert len(guard._state.preconditions) == 1
            await guard.close()

    @pytest.mark.asyncio
    async def test_sse_valid_signed_bundle_accepted(self, key_pair):
        """SSE update with valid signature is accepted and contracts reload."""
        sk, vk = key_pair
        initial_sig = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        # New bundle with a different contract
        new_yaml = b"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: updated-bundle
defaults:
  mode: enforce
contracts:
  - id: deny-delete
    type: pre
    tool: delete_file
    when:
      args.path:
        contains: "/etc"
    then:
      effect: deny
      message: "System file deletion denied."
  - id: deny-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      effect: deny
      message: "Destructive command denied."
"""
        new_sig = _sign(new_yaml, sk)

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            mock_cls.return_value = _make_client_mock(signature=initial_sig)

            async def mock_watch():
                yield {
                    "yaml_bytes": _b64(new_yaml),
                    "signature": new_sig,
                }

            source = _make_source_mock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                verify_signatures=True,
                signing_public_key=public_key_hex,
            )

            await guard._sse_task

            # New contracts loaded — 2 preconditions now
            assert len(guard._state.preconditions) == 2
            await guard.close()


class TestSSEAssignmentChanged:
    """SSE _assignment_changed path verification tests."""

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_assignment_changed_tampered_rejected(self, key_pair):
        """SSE _assignment_changed with tampered re-fetch is rejected."""
        sk, vk = key_pair
        initial_sig = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        tampered_yaml = VALID_BUNDLE_YAML.replace(b"rm -rf", b"echo hello")

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock(signature=initial_sig)
            # Re-fetch returns tampered YAML with the original (now invalid) signature
            client.get = AsyncMock(
                side_effect=[
                    # First call: initial bundle fetch in from_server()
                    {"yaml_bytes": _b64(), "signature": initial_sig},
                    # Second call: re-fetch triggered by _assignment_changed
                    {"yaml_bytes": _b64(tampered_yaml), "signature": initial_sig},
                ]
            )
            mock_cls.return_value = client

            async def mock_watch():
                yield {"_assignment_changed": True, "bundle_name": "new-bundle"}

            source = _make_source_mock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                verify_signatures=True,
                signing_public_key=public_key_hex,
            )

            await guard._sse_task

            # Original contracts preserved — tampered re-fetch rejected
            assert len(guard._state.preconditions) == 1
            await guard.close()

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_assignment_changed_unsigned_rejected(self, key_pair):
        """SSE _assignment_changed with unsigned re-fetch is rejected."""
        sk, vk = key_pair
        initial_sig = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock(signature=initial_sig)
            client.get = AsyncMock(
                side_effect=[
                    # First call: initial bundle fetch
                    {"yaml_bytes": _b64(), "signature": initial_sig},
                    # Second call: re-fetch without signature
                    {"yaml_bytes": _b64()},
                ]
            )
            mock_cls.return_value = client

            async def mock_watch():
                yield {"_assignment_changed": True, "bundle_name": "new-bundle"}

            source = _make_source_mock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                verify_signatures=True,
                signing_public_key=public_key_hex,
            )

            await guard._sse_task

            # Original contracts preserved — unsigned re-fetch rejected
            assert len(guard._state.preconditions) == 1
            await guard.close()

    @pytest.mark.asyncio
    async def test_assignment_changed_valid_accepted(self, key_pair):
        """SSE _assignment_changed with valid signed re-fetch is accepted."""
        sk, vk = key_pair
        initial_sig = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        new_yaml = b"""\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: reassigned-bundle
defaults:
  mode: enforce
contracts:
  - id: deny-delete
    type: pre
    tool: delete_file
    when:
      args.path:
        contains: "/etc"
    then:
      effect: deny
      message: "System file deletion denied."
  - id: deny-rm
    type: pre
    tool: bash
    when:
      args.command:
        contains: "rm -rf"
    then:
      effect: deny
      message: "Destructive command denied."
"""
        new_sig = _sign(new_yaml, sk)

        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            client = _make_client_mock(signature=initial_sig)
            client.get = AsyncMock(
                side_effect=[
                    # First call: initial bundle fetch
                    {"yaml_bytes": _b64(), "signature": initial_sig},
                    # Second call: re-fetch with valid new signature
                    {"yaml_bytes": _b64(new_yaml), "signature": new_sig},
                ]
            )
            mock_cls.return_value = client

            async def mock_watch():
                yield {"_assignment_changed": True, "bundle_name": "new-bundle"}

            source = _make_source_mock()
            source.watch = mock_watch
            mock_src_cls.return_value = source

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                verify_signatures=True,
                signing_public_key=public_key_hex,
            )

            await guard._sse_task

            # New contracts loaded and bundle_name updated
            assert len(guard._state.preconditions) == 2
            assert guard._server_client.bundle_name == "new-bundle"
            await guard.close()


# --- Config tests ---


class TestConfigValidation:
    """Configuration parameter validation."""

    @pytest.mark.asyncio
    async def test_verify_without_public_key_raises(self):
        """verify_signatures=True without signing_public_key raises ValueError."""
        with pytest.raises(ValueError, match="signing_public_key is required"):
            await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
                verify_signatures=True,
                signing_public_key=None,
            )

    @pytest.mark.asyncio
    async def test_verify_false_skips_verification(self):
        """Default verify_signatures=False does not require a signature."""
        p_client, p_sink, p_approval, p_backend, p_source = _server_patches()
        with p_client as mock_cls, p_sink, p_approval, p_backend, p_source as mock_src_cls:
            # No signature in response — should still work
            mock_cls.return_value = _make_client_mock(signature=None)
            mock_src_cls.return_value = _make_source_mock()

            guard = await Edictum.from_server(
                "https://example.com",
                "key",
                "agent-1",
                bundle_name="default",
                auto_watch=False,
            )

            assert len(guard._state.preconditions) == 1
            await guard.close()

    def test_pynacl_not_installed_error(self, key_pair):
        """When PyNaCl is not installed, ImportError with install instructions."""
        sk, vk = key_pair
        signature_b64 = _sign(VALID_BUNDLE_YAML, sk)
        public_key_hex = vk.encode().hex()

        with patch.dict("sys.modules", {"nacl": None, "nacl.signing": None, "nacl.exceptions": None}):
            with pytest.raises(ImportError, match="edictum\\[verified\\]"):
                verify_bundle_signature(VALID_BUNDLE_YAML, signature_b64, public_key_hex)

"""
Asymmetric cryptographic signing and verification utilities for forensic custody chains.
"""
# SPDX-License-Identifier: LicenseRef-PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 Aditya Kumar, trading as Kronagent · https://kronagent.com
# Source-available, not open source. Commercial use requires a licence —
# see LICENSE or contact licensing@kronagent.com

from __future__ import annotations

import abc
import os
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

if TYPE_CHECKING:
    from .config import Settings


class Signer(abc.ABC):
    """Abstract cryptographic signing and verification provider."""

    @abc.abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Sign a message, returning raw signature bytes."""

    @abc.abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against a message. Returns True if valid, False otherwise."""


class LocalAsymmetricSigner(Signer):
    """Local RSA Asymmetric Signer utilizing cryptography primitives."""

    def __init__(self, key_path: str = "kronagent_key.pem") -> None:
        self.key_path = key_path
        self._private_key = self._load_or_generate_key()
        self._public_key = self._private_key.public_key()

    def _load_or_generate_key(self) -> rsa.RSAPrivateKey:
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as fh:
                return serialization.load_pem_private_key(
                    fh.read(),
                    password=None,
                )

        # Generate a new 2048-bit RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.key_path, "wb") as fh:
            fh.write(pem)
        return private_key

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False


class KmsSigner(Signer):
    """AWS KMS Signer wrapper utilizing boto3 kms:Sign and kms:Verify APIs."""

    def __init__(self, key_id: str, region: str = "us-east-1") -> None:
        self.key_id = key_id
        self.region = region
        import boto3
        self._client = boto3.client("kms", region_name=region)

    def sign(self, message: bytes) -> bytes:
        res = self._client.sign(
            KeyId=self.key_id,
            Message=message,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        return res["Signature"]

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            res = self._client.verify(
                KeyId=self.key_id,
                Message=message,
                MessageType="RAW",
                Signature=signature,
                SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
            )
            return res.get("SignatureValid", False)
        except Exception:
            return False


def get_signer(settings: Settings) -> Signer:
    """Factory resolver returning the configured Signer implementation."""
    if getattr(settings, "kms_key_id", ""):
        return KmsSigner(settings.kms_key_id, region=settings.aws_region)

    # The local pem lives beside the database if one is configured, else in the
    # state directory. In the working directory of a container it would be
    # regenerated on every restart, and nothing signed before it would verify.
    key_dir = (os.path.dirname(settings.db_path) if settings.db_path
               else getattr(settings, "state_dir", ""))
    key_path = os.path.join(key_dir, "kronagent_key.pem") if key_dir else "kronagent_key.pem"
    return LocalAsymmetricSigner(key_path)

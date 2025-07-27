#!/usr/bin/env python3
"""
Generate test certificates for X.509 Verifier.

Creates:
 - certs/trust_store/rootCA.key, rootCA.pem         (10-year self-signed CA)
 - certs/test_certs/good/good.key, valid_chain.pem  (valid leaf)
 - certs/test_certs/bad_expired/expired.key,
      expired_chain.pem                              (2020-01-01 → 2020-01-02)
 - certs/test_certs/bad_untrusted/untrustedCA.key,
      untrustedCA.pem, untrusted.key,
      untrusted_chain.pem                            (untrusted-CA leaf)

Usage:
   pip install cryptography
   python3 scripts/generate_test_certs.py
"""

import sys
from pathlib import Path
import datetime

try:
   from cryptography import x509
   from cryptography.x509.oid import NameOID
   from cryptography.hazmat.primitives import hashes, serialization
   from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
   print("ERROR: install the cryptography lib:\n  pip install cryptography")
   sys.exit(1)

def write_key(path: Path, key: rsa.RSAPrivateKey):
   path.write_bytes(
      key.private_bytes(
         serialization.Encoding.PEM,
         serialization.PrivateFormat.TraditionalOpenSSL,
         serialization.NoEncryption(),
      )
   )

def write_cert(path: Path, cert: x509.Certificate):
   path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

def make_name(common_name: str) -> x509.Name:
   """
   Build an X.509 Name using a generic US/New York address.
   """
   return x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "New York"),
      x509.NameAttribute(NameOID.LOCALITY_NAME, "New York"),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
      x509.NameAttribute(NameOID.COMMON_NAME, common_name),
   ])

def ensure_dirs(*dirs):
   for d in dirs:
      d.mkdir(parents=True, exist_ok=True)

def main():
   root        = Path(__file__).resolve().parent.parent
   trust_dir   = root / "certs" / "trust_store"
   good_dir    = root / "certs" / "test_certs" / "good"
   exp_dir     = root / "certs" / "test_certs" / "bad_expired"
   untrust_dir = root / "certs" / "test_certs" / "bad_untrusted"

   ensure_dirs(trust_dir, good_dir, exp_dir, untrust_dir)

   # 1) Root CA (10-year validity)
   ca_key  = rsa.generate_private_key(65537, 4096)
   ca_name = make_name("MyRootCA")
   ca_cert = (
      x509.CertificateBuilder()
         .subject_name(ca_name)
         .issuer_name(ca_name)
         .public_key(ca_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
         .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
         .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
         )
         .sign(ca_key, hashes.SHA256())
   )
   write_key(trust_dir / "rootCA.key", ca_key)
   write_cert(trust_dir / "rootCA.pem", ca_cert)

   # 2) Good leaf cert (valid now → +365 days)
   good_key   = rsa.generate_private_key(65537, 2048)
   good_name  = make_name("valid.example.com")
   good_cert  = (
      x509.CertificateBuilder()
         .subject_name(good_name)
         .issuer_name(ca_cert.subject)
         .public_key(good_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
         .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
         .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
         )
         .add_extension(
            x509.KeyUsage(
               digital_signature=True,
               key_encipherment=True,
               content_commitment=False,
               data_encipherment=False,
               key_agreement=False,
               key_cert_sign=False,
               crl_sign=False,
               encipher_only=False,
               decipher_only=False
            ),
            critical=True
         )
         .sign(ca_key, hashes.SHA256())
   )
   write_key(good_dir / "good.key", good_key)
   write_cert(good_dir / "valid_chain.pem", good_cert)

   # 3) Expired leaf cert (2020-01-01 → 2020-01-02)
   exp_key   = rsa.generate_private_key(65537, 2048)
   exp_name  = make_name("expired.example.com")
   exp_cert  = (
      x509.CertificateBuilder()
         .subject_name(exp_name)
         .issuer_name(ca_cert.subject)
         .public_key(exp_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.datetime(2020, 1, 1, 0, 0, 0))
         .not_valid_after(datetime.datetime(2020, 1, 2, 0, 0, 0))
         .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
         )
         .sign(ca_key, hashes.SHA256())
   )
   write_key(exp_dir / "expired.key", exp_key)
   write_cert(exp_dir / "expired_chain.pem", exp_cert)

   # 4) Untrusted CA + leaf cert
   utca_key  = rsa.generate_private_key(65537, 4096)
   utca_name = make_name("UntrustedCA")
   utca_cert = (
      x509.CertificateBuilder()
         .subject_name(utca_name)
         .issuer_name(utca_name)
         .public_key(utca_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
         .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
         .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
         )
         .sign(utca_key, hashes.SHA256())
   )
   write_key(untrust_dir / "untrustedCA.key", utca_key)
   write_cert(untrust_dir / "untrustedCA.pem", utca_cert)

   un_key   = rsa.generate_private_key(65537, 2048)
   un_name  = make_name("untrusted.example.com")
   un_cert  = (
      x509.CertificateBuilder()
         .subject_name(un_name)
         .issuer_name(utca_cert.subject)
         .public_key(un_key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
         .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
         .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
         )
         .sign(utca_key, hashes.SHA256())
   )
   write_key(untrust_dir / "untrusted.key", un_key)
   write_cert(untrust_dir / "untrusted_chain.pem", un_cert)

   print("Test certificates generated successfully.")

if __name__ == "__main__":
   main()
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

def verify_signature(message: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    try:
        
        # Load public key
        public_key = serialization.load_pem_public_key(public_key_pem)

        # Verify signature
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )

        print("✅ Signature is valid.")
        return True

    except InvalidSignature:
        print("❌ Signature is invalid.")
        return False

    except Exception as e:
        print(f"⚠️ Error loading key or verifying: {e}")
        return False


public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEECh18NUbHaK/ksLDNbHqwubSNgSX\nNl6uPb+tK79JzJY8p3/HDkK5MB2PzoIq1bE8Fouuo313S0sw9JH8Bcnfrw==\n-----END PUBLIC KEY-----\n"

verify_signature()


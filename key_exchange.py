from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_ecc_keypair():

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_public_key(signing_private_key, public_key_to_sign):

    pub_bytes = public_key_to_sign.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    signature = signing_private_key.sign(pub_bytes, ec.ECDSA(hashes.SHA256()))
    return signature

def verify_signature(signing_public_key, signature, received_public_key):

    pub_bytes = received_public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    signing_public_key.verify(signature, pub_bytes, ec.ECDSA(hashes.SHA256()))
    return True

def compute_shared_secret(my_private_key, peer_public_key):

    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

def derive_session_key(shared_secret, info=b"mqtt-session-key"):

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    session_key = hkdf.derive(shared_secret)
    return session_key

def perform_full_key_exchange(name_a="Alice", name_b="Bob"):

    id_priv_a, id_pub_a = generate_ecc_keypair()
    id_priv_b, id_pub_b = generate_ecc_keypair()

    eph_priv_a, eph_pub_a = generate_ecc_keypair()
    eph_priv_b, eph_pub_b = generate_ecc_keypair()

    sig_a = sign_public_key(id_priv_a, eph_pub_a)
    sig_b = sign_public_key(id_priv_b, eph_pub_b)

    verify_signature(id_pub_a, sig_a, eph_pub_a)
    verify_signature(id_pub_b, sig_b, eph_pub_b)

    secret_a = compute_shared_secret(eph_priv_a, eph_pub_b)
    secret_b = compute_shared_secret(eph_priv_b, eph_pub_a)
    assert secret_a == secret_b, "ECDH secrets do not match"

    session_key = derive_session_key(secret_a)

    return {
        "session_key": session_key,
        "identity_keys": {
            name_a: (id_priv_a, id_pub_a),
            name_b: (id_priv_b, id_pub_b),
        },
        "ephemeral_keys": {
            name_a: (eph_priv_a, eph_pub_a),
            name_b: (eph_priv_b, eph_pub_b),
        },
    }
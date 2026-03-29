# Secure MQTT Communication for IoT
## Authenticated ECC Key Exchange + AES-GCM Encryption

---

## How to run

```bash
pip install cryptography
python demo.py
```

---

## How MQTT Works

MQTT (Message Queuing Telemetry Transport) is a lightweight messaging protocol designed for IoT devices. It uses a **publish-subscribe** model with three roles:

- **Broker:** A central server that receives all messages and routes them to the right recipients. It does not generate messages itself. It only matches published messages to subscribed topics and forwards them. Think of it as a post office: it reads the address (topic) on each envelope (message) and delivers it, but it does not open the envelope.

- **Publisher:** A client that sends messages to the broker on a specific **topic** (e.g., `"weather"`). The publisher does not need to know who is listening. It simply sends data to the broker and trusts that the broker will deliver it.

- **Subscriber:** A client that tells the broker which topics it is interested in. Whenever the broker receives a message on a matching topic, it forwards that message to the subscriber.

**The security problem:** By default, MQTT payloads are sent in plaintext. The broker can read every message, and anyone intercepting network traffic can too. Our project solves this by encrypting messages at the publisher before they reach the broker, and decrypting them at the subscriber after delivery. The broker only ever handles opaque encrypted bytes.

---

## Project Structure

| File               | Purpose                                             |
|--------------------|-----------------------------------------------------|
| `key_exchange.py`  | Authenticated ECDH key exchange + HKDF key derivation |
| `encryption.py`    | AES-256-GCM encryption with counter-based nonces    |
| `decryption.py`    | AES-256-GCM decryption with replay attack detection  |
| `mqtt_env.py`      | Broker, Publisher, and Subscriber classes            |
| `demo.py`          | Main demo that runs the full secure communication pipeline |

---

## How Each Module Works

### 1. `key_exchange.py` — Authenticated Key Exchange

Establishes a shared AES-256 session key between Publisher and Subscriber using authenticated ECDH.

The flow inside `perform_full_key_exchange()`:
1. Both parties generate **long-term identity key pairs** (ECC P-256) used to prove their identity.
2. Both generate **ephemeral key pairs** (fresh per session) for forward secrecy.
3. Each party **signs** its ephemeral public key with its identity private key (ECDSA), proving ownership.
4. Each party **verifies** the other's signature before trusting the ephemeral key. This prevents MITM attacks.
5. Both compute the **ECDH shared secret** independently. The Diffie-Hellman property guarantees both arrive at the same value.
6. The raw secret is passed through **HKDF** (extract-and-expand) to derive a clean 256-bit AES session key.

**Key functions:**
- `generate_ecc_keypair()` — creates a P-256 key pair
- `sign_public_key()` — ECDSA signature over a public key
- `verify_signature()` — verifies the signature (raises exception on failure)
- `compute_shared_secret()` — ECDH exchange
- `derive_session_key()` — HKDF-SHA256 derivation
- `perform_full_key_exchange()` — runs all steps end-to-end

---

### 2. `encryption.py` — AES-GCM Encryption

Encrypts MQTT payloads using AES-256-GCM, which provides confidentiality, integrity, and authentication in a single operation. AES-GCM produces a 128-bit authentication tag alongside the ciphertext. If even one bit is modified, the tag will not match on the receiving end.

The MQTT topic is passed as **Associated Authenticated Data (AAD)**: it is not encrypted (so the broker can route by topic) but is covered by the authentication tag (so an attacker cannot redirect a message to a different topic).

A monotonic counter is used as the nonce and is embedded in each packet for replay detection by the receiver.

**Packet format:** `[4B counter] [12B nonce] [ciphertext] [16B GCM tag]`

**Key class:** `Encryptor` — initialize with the session key, call `encrypt(plaintext, topic)`.

---

### 3. `decryption.py` — AES-GCM Decryption + Replay Protection

Decrypts packets from `encryption.py` and enforces two security checks:

- **Replay protection:** Tracks the highest accepted counter. Any packet with a counter less than or equal to the last accepted value is rejected (raises `ReplayAttack`).
- **Integrity verification:** AES-GCM automatically verifies the authentication tag during decryption. If the ciphertext or AAD has been tampered with, decryption fails (raises `Tampered`).

**Key class:** `Decryptor` — initialize with the same session key, call `decrypt(packet, topic)`.

---

### 4. `mqtt_env.py` — MQTT Environment

Contains the three MQTT roles as Python classes:

- **Broker:** Maintains a dictionary of topic subscriptions. When `publish()` is called, it forwards the encrypted payload to all registered callbacks. It never has access to the session key.
- **Publisher:** Wraps `Encryptor`. Encrypts each message before passing it to the broker.
- **Subscriber:** Wraps `Decryptor`. Receives encrypted bytes from the broker and decrypts them, handling `ReplayAttack` and `Tampered` exceptions.

---

### 5. `demo.py` — Full Demonstration

Runs the complete pipeline in 5 steps:
1. Authenticated key exchange between Publisher and Subscriber
2. MQTT environment setup (Broker, Publisher, Subscriber)
3. Normal encrypted communication (Publisher sends, Subscriber decrypts)
4. Replay attack test (old packet re-sent, rejected by counter check)
5. Tamper detection test (modified packet, rejected by GCM tag verification)

---

## Library Used

| Library | Version | Purpose |
|---------|---------|---------|
| `cryptography` | >= 41.0 | ECC, ECDSA, ECDH, HKDF, AES-GCM |

---

## Threat Model Summary

| Threat | Mitigation | Where in code |
|--------|-----------|---------------|
| MITM during key exchange | ECDSA-signed ephemeral keys | `key_exchange.py` — `sign_public_key()`, `verify_signature()` |
| Eavesdropping | AES-256-GCM encryption | `encryption.py` — `Encryptor.encrypt()` |
| Message tampering | GCM authentication tag | `decryption.py` — `Decryptor.decrypt()` raises `Tampered` |
| Replay attacks | Monotonic counter verification | `decryption.py` — counter check in `decrypt()` |
| Broker compromise | End-to-end encryption (broker never sees plaintext) | `mqtt_env.py` — broker only forwards encrypted bytes |
| Topic redirection | MQTT topic used as AAD | `encryption.py` / `decryption.py` — AAD parameter |

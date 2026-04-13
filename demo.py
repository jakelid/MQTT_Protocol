import struct
from key_exchange import perform_full_key_exchange
from mqtt_env import Broker, Publisher, Subscriber

if __name__ == "__main__":

    # Step 1 -> Authenticated Key Exchange (ECDH + ECDSA)
    print("\n" + "=" * 65)
    print("Step 1: Authenticated Key Exchange (ECDH + ECDSA)")
    print("=" * 65)

    exchange_result = perform_full_key_exchange(
        name_a="Publisher", name_b="Subscriber"
    )
    session_key = exchange_result["session_key"]

    print(f"\nShared session key established: {session_key.hex()}")
    print("Both Publisher and Subscriber now share the same AES-256 key.")

    # Step 2 -> Environment Setup (Broker, Publisher, Subscriber)
    print("\n" + "=" * 65)
    print("Step 2: Environment Setup")
    print("=" * 65)

    broker = Broker()
    publisher = Publisher("Publisher", broker, session_key)
    subscriber = Subscriber("Subscriber", broker, session_key)

    topic = "weather"
    subscriber.subscribe(topic)

    # Step 3 -> Encrypted Communication between Publisher and Subscriber
    print("\n" + "=" * 65)
    print("Step 3: Encrypted Communication")
    print("=" * 65)

    messages = [
        "Temperature: 30C",
        "Raining: 50%",
    ]

    saved_packets = []
    for msg in messages:
        packet = publisher.publish(topic, msg)
        saved_packets.append(packet)

    print(f"\nSubscriber received {len(subscriber.received_messages)} messages:")
    for i, m in enumerate(subscriber.received_messages):
        print(f"\t{i + 1}. {m}")

    # Step 4 -> Replay Attack Test
    print("\n" + "=" * 65)
    print("Step 4: Replay Attack Test")
    print("=" * 65)
    print("\nAn attacker captures packet #0 and re-sends it to the broker...")

    broker.publish(topic, saved_packets[0])

    # Step 5 -> Tamper Detection Test
    print("\n" + "=" * 65)
    print("Step 5: Tamper Detection Test")
    print("=" * 65)
    print("\nAn attacker intercepts a new message and flips a byte...")

    fresh_packet = publisher.publish(topic, "Attacker's message")

    tampered_packet = bytearray(fresh_packet)
    tampered_packet[20] ^= 0xFF
    tampered_packet = bytes(tampered_packet)

    print("\nAttacker sends the tampered packet to the broker")

    original_counter = struct.unpack(">I", fresh_packet[:4])[0]
    tampered_packet = (struct.pack(">I", original_counter + 100)
                       + tampered_packet[4:])

    broker.publish(topic, tampered_packet)
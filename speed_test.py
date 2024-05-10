from rsa import RSA, User
import time


def test_rsa(bit_length):
    print("")
    print("")
    print(f"Testing RSA with {bit_length}-bit keys...")
    start_time = time.time()
    rsa = RSA(bit_length)
    alice = User(rsa, "Alice")
    bob = User(rsa, "Bob")
    alice.send_message("Hello, Bob!", bob)
    bob.send_message("Hi, Alice!", alice)
    elapsed_time = time.time() - start_time
    print(f"Test completed in {elapsed_time:.2f} seconds\n")


def main():
    for bit_length in [128, 256, 512, 1024]:
        test_rsa(bit_length)


if __name__ == "__main__":
    main()
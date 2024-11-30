import os
import time
import socket

def test_file_monitor(directory):
    print("[TEST] Starting file monitor test...")
    
    # Create a new file
    test_file_path = os.path.join(directory, "test_large_file.txt")
    print(f"[TEST] Creating file: {test_file_path}")
    with open(test_file_path, "wb") as f:
        # Write 2MB of random data to simulate a large file
        f.write(os.urandom(2 * 1024 * 1024))
    
    time.sleep(2)

    # Modify the file
    print(f"[TEST] Modifying file: {test_file_path}")
    with open(test_file_path, "ab") as f:
        f.write(b"More data added to test file monitoring.")

    time.sleep(2)

    # Clean up
    print(f"[TEST] Deleting file: {test_file_path}")
    os.remove(test_file_path)

    print("[TEST] File monitor test completed.\n")

def test_network_monitor():
    print("[TEST] Starting network monitor test...")

    # Create a UDP socket to send a large packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target_ip = "127.0.0.1"
    target_port = 9999

    # Generate a large packet (1600 bytes)
    large_packet = b"A" * 1600

    try:
        print(f"[TEST] Sending large packet to {target_ip}:{target_port}...")
        sock.sendto(large_packet, (target_ip, target_port))
        print("[TEST] Large packet sent.")
    except Exception as e:
        print(f"[ERROR] Failed to send packet: {e}")
    finally:
        sock.close()

    print("[TEST] Network monitor test completed.\n")

if __name__ == "__main__":
    # Specify the directory monitored by the ransomware detection script
    monitored_directory = "/home/huzaifa/Desktop/HoneyPot_Testing/Testing_HoneyPot"

    # Run file monitor test
    test_file_monitor(monitored_directory)

    # Run network monitor test
    test_network_monitor()

    print("[ALL TESTS COMPLETED]")

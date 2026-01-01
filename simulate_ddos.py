#!/usr/bin/env python3
"""
DDoS Attack Simulation Script
Generates high-volume traffic to test IDS DDoS detection
"""

import socket
import time
import sys
from datetime import datetime

def simulate_ddos(target_ip, target_port=80, num_requests=150, duration=1):
    """
    Simulate a DDoS attack by sending multiple requests quickly
    
    Args:
        target_ip: Target IP address
        target_port: Target port (default 80)
        num_requests: Number of requests to send (default 150)
        duration: Time window in seconds (default 1)
    """
    print("=" * 60)
    print("          DDoS Attack Simulation")
    print("=" * 60)
    print(f"\n[*] Target: {target_ip}:{target_port}")
    print(f"[*] Requests: {num_requests}")
    print(f"[*] Duration: {duration} second(s)")
    print(f"[*] Rate: {num_requests/duration:.0f} requests/sec")
    print(f"\n[!] Starting in 3 seconds...")
    print("[!] Make sure the IDS is running to capture this traffic!\n")
    
    time.sleep(3)
    
    successful = 0
    failed = 0
    start_time = time.time()
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting DDoS simulation...")
    
    for i in range(num_requests):
        try:
            # Create a TCP connection attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)  # Very short timeout
            
            # Try to connect (will likely fail, but generates SYN packets)
            try:
                sock.connect((target_ip, target_port))
                successful += 1
            except (socket.timeout, ConnectionRefusedError, OSError):
                # Connection refused/timeout is expected for closed ports
                # But the packet is still sent and captured by IDS
                successful += 1
            finally:
                sock.close()
                
            # Progress indicator
            if (i + 1) % 25 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                print(f"[*] Progress: {i + 1}/{num_requests} packets ({rate:.0f} pkt/s)")
                
        except Exception as e:
            failed += 1
            if failed < 5:  # Only print first few errors
                print(f"[!] Error: {e}")
    
    end_time = time.time()
    elapsed = end_time - start_time
    actual_rate = num_requests / elapsed if elapsed > 0 else 0
    
    print(f"\n{'=' * 60}")
    print("                 Simulation Complete")
    print("=" * 60)
    print(f"[+] Total packets sent: {num_requests}")
    print(f"[+] Time elapsed: {elapsed:.2f} seconds")
    print(f"[+] Actual rate: {actual_rate:.0f} packets/sec")
    print(f"[+] Successful: {successful}")
    print(f"[+] Failed: {failed}")
    print(f"\n[*] Check the IDS dashboard for DDoS alerts!")
    print(f"[*] Expected: DDoS alert if rate > 100 requests/sec\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 simulate_ddos.py <target_ip> [port] [num_requests]")
        print("\nExamples:")
        print("  python3 simulate_ddos.py 172.27.252.208")
        print("  python3 simulate_ddos.py 172.27.252.208 80 200")
        print("\nNote: Run this from a DIFFERENT machine for best results")
        print("      (same machine traffic may be optimized by kernel)")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    num_requests = int(sys.argv[3]) if len(sys.argv) > 3 else 150
    
    try:
        simulate_ddos(target_ip, target_port, num_requests)
    except KeyboardInterrupt:
        print("\n\n[!] Simulation interrupted by user")
        sys.exit(0)

if __name__ == "__main__":
    main()

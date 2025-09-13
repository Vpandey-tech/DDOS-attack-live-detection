import scapy.all as scapy
import sys

# --- Configuration ---
# You might need to change the INTERFACE name.
# Common names are "Wi-Fi", "Ethernet", "en0".
CAPTURE_DURATION_SECONDS = 300  # 300 seconds = 5 minutes
OUTPUT_FILENAME = "normal_traffic.pcap"
INTERFACE = "WiFi" 

# --- Main Script ---
print("--- Network Traffic Capture Tool ---")
print(f"[*] Capturing traffic on interface: '{INTERFACE}' for {CAPTURE_DURATION_SECONDS} seconds.")
print("[*] During the capture, please perform your normal internet activities (e.g., browse websites, watch a short video).")
print(f"[*] A file named '{OUTPUT_FILENAME}' will be created.")
print("-----------------------------------------")

try:
    # Sniff packets from the network
    packets = scapy.sniff(iface=INTERFACE, timeout=CAPTURE_DURATION_SECONDS, prn=lambda x: print(f"Packet captured...", end='\r'))

    # Save the captured packets to a file
    scapy.wrpcap(OUTPUT_FILENAME, packets)

    print(f"\n\n[+] Success! Traffic capture complete.")
    print(f"[+] Your normal network data has been saved to '{OUTPUT_FILENAME}'.")

except Exception as e:
    print(f"\n\n[!] An Error Occurred: {e}")
    print("[!] Please check two things:")
    print("    1. Is the INTERFACE name ('Wi-Fi') correct for your system?")
    print("    2. Do you have the necessary permissions? Try running this terminal or command prompt as an Administrator.")
    sys.exit(1)
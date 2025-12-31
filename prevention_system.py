
import subprocess
import logging
import ipaddress
import socket
from typing import List, Set, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PreventionSystem:
    """
    Handles active blocking of malicious IP addresses using Windows Firewall.
    Includes safety mechanisms to prevent self-lockout or blocking of critical infrastructure.
    """
    
    def __init__(self, simulation_mode: bool = True):
        self.simulation_mode = simulation_mode
        self.blocked_ips: Set[str] = set()
        self.whitelisted_ips: Set[str] = self._generate_whitelist()
        self.rule_name_prefix = "DDOS_AUTO_BLOCK_"

    def _generate_whitelist(self) -> Set[str]:
        """
        Generates a set of critical IPs that should never be blocked.
        Includes localhost, local gateway, standard DNS, and local network reserved ranges.
        """
        whitelist = {
            "127.0.0.1",
            "0.0.0.0",
            "8.8.8.8",   # Google DNS
            "8.8.4.4",
            "1.1.1.1",   # Cloudflare DNS
            "192.168.1.1" # Common Gateway (should be dynamic in prod, but good default)
        }
        
        # Add local machine's IP
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            whitelist.add(local_ip)
        except Exception:
            pass
            
        return whitelist

    def toggle_mode(self, simulation: bool):
        """Switches between Simulation (Log only) and Active (Firewall block) modes."""
        self.simulation_mode = simulation
        mode_str = "SIMULATION" if simulation else "ACTIVE"
        logger.info(f"Prevention System switched to {mode_str} mode.")

    def is_safe_ip(self, ip: str) -> bool:
        """Checks if an IP is in the whitelist or is a private/reserved address that shouldn't be blocked blindly."""
        if ip in self.whitelisted_ips:
            return True
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            # In a real enterprise scenario, you might NOT want to whitelist all private IPs,
            # but for a local demo/test to avoid breaking the LAN, it's safer.
            if ip_obj.is_loopback or ip_obj.is_link_local:
                return True
        except ValueError:
            return True # Invalid IP, safe to say "don't block" because we can't anyway
            
        return False

    def block_ip(self, ip_address: str, reason: str = "High Threat Detected") -> bool:
        """
        Attempts to block an IP address.
        Returns True if action was taken (or simulated), False if ignored (whitelist/error).
        """
        if self.is_safe_ip(ip_address):
            logger.warning(f"BLOCKED ACTION PREVENTED: Attempted to block whitelisted IP {ip_address}")
            return False

        if ip_address in self.blocked_ips:
            return True # Already blocked

        rule_name = f"{self.rule_name_prefix}{ip_address}"
        
        if self.simulation_mode:
            logger.info(f"[SIMULATION] Would block IP: {ip_address} | Reason: {reason}")
            self.blocked_ips.add(ip_address)
            return True

        # ACTIVE MODE - Execute Netsh command
        try:
            # Command: netsh advfirewall firewall add rule name="DDOS_BLOCK_1.2.3.4" dir=in action=block remoteip=1.2.3.4
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address}",
                "enable=yes"
            ]
            
            # Use proactive approach: check if rule exists first? No, 'add rule' might duplicate or fail if exists.
            # We'll just try to add it.
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                logger.info(f"SUCCESS: Blocked IP {ip_address} via Windows Firewall.")
                self.blocked_ips.add(ip_address)
                return True
            else:
                logger.error(f"FAILED to block IP {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"EXCEPTION when blocking IP {ip_address}: {e}")
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """Removes the blocking rule for an IP."""
        if ip_address not in self.blocked_ips:
            return False

        rule_name = f"{self.rule_name_prefix}{ip_address}"

        if self.simulation_mode:
            logger.info(f"[SIMULATION] Would unblock IP: {ip_address}")
            self.blocked_ips.discard(ip_address)
            return True

        try:
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                logger.info(f"SUCCESS: Unblocked IP {ip_address}")
                self.blocked_ips.discard(ip_address)
                return True
            else:
                # If rule not found, we still remove from our set
                if "No rules match" in result.stdout:
                     self.blocked_ips.discard(ip_address)
                     return True
                logger.error(f"FAILED to unblock IP {ip_address}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"EXCEPTION when unblocking IP {ip_address}: {e}")
            return False

    def get_blocked_ips(self) -> List[str]:
        return list(self.blocked_ips)

    def clear_all_blocks(self):
        """Removes all rules created by this session."""
        ips_to_remove = list(self.blocked_ips)
        for ip in ips_to_remove:
            self.unblock_ip(ip)

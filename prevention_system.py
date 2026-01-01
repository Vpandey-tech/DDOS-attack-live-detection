import subprocess
import logging
import ipaddress
import socket
import threading
import time
from typing import List, Set, Optional
from threading import RLock

import json
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
    handlers=[
        logging.FileHandler("prevention_system.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PreventionSystem:
    """
    Production-Grade Active Blocking System.
    Features:
    - Thread-safe operations
    - Non-blocking execution
    - Verification & Retry logic
    - Safety whitelists
    - Persistent State (JSON)
    """
    
    def __init__(self, simulation_mode: bool = True):
        self.simulation_mode = simulation_mode
        self._lock = RLock()
        self.blocked_ips: Set[str] = set()
        self.whitelisted_ips: Set[str] = self._generate_whitelist()
        self.rule_name_prefix = "DDOS_AUTO_BLOCK_"
        self.state_file = "blocked_ips.json"
        
        # Load previous state
        self._load_state()

    def _load_state(self):
        """Load blocked IPs from local storage to restore state on restart."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_ips = set(data.get('blocked_ips', []))
                logger.info(f"🔄 Restored {len(self.blocked_ips)} blocked IPs from storage.")
            except Exception as e:
                logger.error(f"Failed to load state: {e}")

    def _save_state(self):
        """Save blocked IPs to local storage."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump({'blocked_ips': list(self.blocked_ips)}, f)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")


    def _generate_whitelist(self) -> Set[str]:
        """
        Generates a robust set of critical IPs that should never be blocked.
        """
        whitelist = {
            "127.0.0.1", "0.0.0.0", "localhost",
            "8.8.8.8", "8.8.4.4",  # Google DNS
            "1.1.1.1",             # Cloudflare DNS
        }
        
        # Add local machine's IP and Gateway
        try:
            hostname = socket.gethostname()
            # Get all IPs associated with this host
            info = socket.getaddrinfo(hostname, None)
            for item in info:
                ip = item[4][0]
                if ':' not in ip: # IPv4 preference for now
                    whitelist.add(ip)
                    
            # Try to find default gateway (Windows specific)
            try:
                # This is a basic way to get gateway, for prod use `netifaces` or similar
                cmd = subprocess.run("ipconfig", capture_output=True, text=True)
                for line in cmd.stdout.split('\n'):
                    if "Default Gateway" in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            gw = parts[1].strip()
                            if gw and gw != "0.0.0.0":
                                whitelist.add(gw)
            except Exception:
                pass
                
        except Exception as e:
            logger.error(f"Error generating whitelist: {e}")
            
        logger.info(f"System Whitelist Initialized: {whitelist}")
        return whitelist

    def toggle_mode(self, simulation: bool):
        """Switches between Simulation (Log only) and Active (Firewall block) modes."""
        with self._lock:
            self.simulation_mode = simulation
            mode_str = "SIMULATION" if simulation else "ACTIVE"
            logger.info(f"Prevention System switched to {mode_str} mode.")

    def is_safe_ip(self, ip: str) -> bool:
        """Checks if an IP is in the whitelist or is a safe private range."""
        if ip in self.whitelisted_ips:
            return True
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            # In production, blocking loopback/link-local is critical to avoid self-DoS
            if ip_obj.is_loopback or ip_obj.is_link_local:
                return True
            # Optional: Allow all private IPs in testing? Context dependent.
            # if ip_obj.is_private: return True 
        except ValueError:
            return True # Invalid IP safe to ignore
            
        return False

    def _run_command_safe(self, cmd: List[str], retries: int = 2) -> bool:
        """
        Execute system commands safely with retries.
        """
        for attempt in range(retries + 1):
            try:
                # Use a timeout to prevent hanging indefiniteuly
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    check=False,
                    timeout=5 
                )
                
                if result.returncode == 0:
                    return True
                
                logger.warning(f"Command failed (Attempt {attempt+1}/{retries+1}): {' '.join(cmd)} | Error: {result.stderr.strip()}")
                
            except subprocess.TimeoutExpired:
                logger.error(f"Command timed out (Attempt {attempt+1}): {' '.join(cmd)}")
            except Exception as e:
                logger.error(f"Command exception (Attempt {attempt+1}): {e}")
            
            time.sleep(1) # Backoff before retry
            
        return False

    def _async_block_task(self, ip_address: str, rule_name: str):
        """Background task to perform the blocking IO."""
        success = False
        
        # 1. Define Command
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address}",
            "enable=yes"
        ]
        
        # 2. Execute
        if self._run_command_safe(cmd):
            # 3. Verify
            verify_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
            if self._run_command_safe(verify_cmd, retries=0):
                logger.info(f"✅ SUCCESS: Blocked IP {ip_address} via Windows Firewall.")
                success = True
            else:
                logger.error(f"❌ VERIFICATION FAILED: Rule for {ip_address} seemed to apply but cannot be found.")
        else:
            logger.error(f"❌ FAILURE: Could not apply firewall rule for {ip_address} after retries.")

        # 4. Update State ensure consistency
        if not success:
            with self._lock:
                self.blocked_ips.discard(ip_address)
                self._save_state()

    def block_ip(self, ip_address: str, reason: str = "High Threat Detected") -> bool:
        """
        Initiates blocking of an IP address. Returns True if accepted for processing.
        """
        if self.is_safe_ip(ip_address):
            logger.warning(f"🛡️ SAFETY: Block blocked for safe IP {ip_address}")
            return False

        with self._lock:
            if ip_address in self.blocked_ips:
                return True # Already being handled

            self.blocked_ips.add(ip_address)
            self._save_state()
        
        rule_name = f"{self.rule_name_prefix}{ip_address}"
        
        if self.simulation_mode:
            logger.info(f"[SIMULATION] 🚫 Would block IP: {ip_address} | Reason: {reason}")
            return True

        # Run firewall operation in a separate thread to avoid blocking the main flow
        t = threading.Thread(target=self._async_block_task, args=(ip_address, rule_name), name=f"Blocker-{ip_address}")
        t.daemon = True # Allow app exit even if threads are running
        t.start()
        
        return True

    def unblock_ip(self, ip_address: str) -> bool:
        """Removes the blocking rule for an IP."""
        with self._lock:
            if ip_address not in self.blocked_ips:
                return False
            self.blocked_ips.discard(ip_address)
            self._save_state()

        rule_name = f"{self.rule_name_prefix}{ip_address}"

        if self.simulation_mode:
            logger.info(f"[SIMULATION] 🔓 Would unblock IP: {ip_address}")
            return True

        # Async unblock
        def _task():
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            if self._run_command_safe(cmd):
                logger.info(f"✅ UNBLOCKED: Removed rule for {ip_address}")
            else:
                logger.warning(f"⚠️ Unblock warning: Could not delete rule for {ip_address} (might barely exist)")

        t = threading.Thread(target=_task, name=f"Unblocker-{ip_address}")
        t.daemon = True
        t.start()
        return True

    def get_blocked_ips(self) -> List[str]:
        with self._lock:
            return list(self.blocked_ips)

    def clear_all_blocks(self):
        """Removes all rules created by this session."""
        logger.info("🧹 Cleaning up all active blocks...")
        with self._lock:
            ips_to_remove = list(self.blocked_ips)
            self.blocked_ips.clear()
            
        # We can run this in parallel for speed if many IPs
        for ip in ips_to_remove:
            # We call the internal task logic or unblock_ip directly
            # Since we cleared the set, unblock_ip checks would fail, so we bypass strict checks
            rule_name = f"{self.rule_name_prefix}{ip}"
            
            def _cleanup_task(r_name):
                 cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={r_name}"]
                 subprocess.run(cmd, capture_output=True, check=False)
            
            t = threading.Thread(target=_cleanup_task, args=(rule_name,))
            t.daemon = True
            t.start()

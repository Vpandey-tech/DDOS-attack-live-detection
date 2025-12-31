
import unittest
from unittest.mock import patch, MagicMock
from prevention_system import PreventionSystem

class TestPreventionSystem(unittest.TestCase):
    def setUp(self):
        self.ps = PreventionSystem(simulation_mode=True)
        # Mock whitelist to be predictable
        self.ps.whitelisted_ips = {"127.0.0.1", "8.8.8.8"}

    def test_whitelist_check(self):
        self.assertTrue(self.ps.is_safe_ip("127.0.0.1"))
        self.assertTrue(self.ps.is_safe_ip("8.8.8.8"))
        self.assertFalse(self.ps.is_safe_ip("1.2.3.4"))

    def test_simulation_block(self):
        # Should return True and add to set, but NOT call netsh
        with patch('subprocess.run') as mock_run:
            result = self.ps.block_ip("1.2.3.4", reason="Test")
            self.assertTrue(result)
            self.assertIn("1.2.3.4", self.ps.blocked_ips)
            mock_run.assert_not_called()

    def test_active_block_whitelisted(self):
        self.ps.toggle_mode(simulation=False)
        with patch('subprocess.run') as mock_run:
            result = self.ps.block_ip("127.0.0.1")
            self.assertFalse(result)
            mock_run.assert_not_called()

    def test_active_block_malicious(self):
        self.ps.toggle_mode(simulation=False)
        with patch('subprocess.run') as mock_run:
            # Mock successful netsh execution
            mock_run.return_value.returncode = 0
            
            result = self.ps.block_ip("10.10.10.10")
            
            self.assertTrue(result)
            self.assertIn("10.10.10.10", self.ps.blocked_ips)
            # Verify netsh command structure
            args, _ = mock_run.call_args
            cmd_list = args[0]
            self.assertEqual(cmd_list[0], "netsh")
            self.assertEqual(cmd_list[7], "action=block")
            self.assertIn("remoteip=10.10.10.10", cmd_list)

if __name__ == '__main__':
    unittest.main()

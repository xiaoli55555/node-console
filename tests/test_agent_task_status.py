import json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from agent import agent

class AgentTaskStatus(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)
        p=patch.object(agent,'DHCP_STATE',self.path);p.start();self.addCleanup(p.stop)
    def test_idle_is_verified(self):
        with patch.object(agent.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='inactive\n')):
            self.assertTrue(agent.dhcp_task_status(185)['idle_verified'])
    def test_live_unit_never_reported_idle(self):
        with patch.object(agent.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='activating\n')):
            self.assertEqual(agent.dhcp_task_status(185)['state'],'running')
    def test_unknown_unit_state_does_not_release(self):
        with patch.object(agent.subprocess,'run',return_value=SimpleNamespace(returncode=1,stdout='')):
            self.assertEqual(agent.dhcp_task_status(185)['state'],'unknown')
    def test_persistent_terminal_result_replays(self):
        (self.path/'dhcp-result.json').write_text(json.dumps({'id':185,'state':'changed','new_ip':'42.2.1.2'}))
        self.assertEqual(agent.dhcp_task_status(185)['new_ip'],'42.2.1.2')
    def test_stopped_running_record_becomes_failure(self):
        (self.path/'dhcp-result.json').write_text(json.dumps({'id':185,'state':'running'}))
        with patch.object(agent.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='failed\n')):
            self.assertEqual(agent.dhcp_task_status(185)['state'],'failed')

    def test_missing_unit_is_confirmed_idle_not_unknown(self):
        with patch.object(agent.subprocess,'run',return_value=SimpleNamespace(returncode=4,stdout='LoadState=not-found\nActiveState=inactive\n')):
            self.assertEqual(agent.dhcp_task_status(185)['state'],'not_started')
    def test_real_systemd_active_output(self):
        with patch.object(agent.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=active\n')):
            self.assertEqual(agent.dhcp_task_status(185)['state'],'running')

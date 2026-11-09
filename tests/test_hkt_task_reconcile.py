import unittest
from test_hkt_dhcp import HKTAPI
import server

class TaskReconcile(unittest.TestCase):
    setUp=HKTAPI.setUp
    post=HKTAPI.post
    node=HKTAPI.node
    report=HKTAPI.report
    generate=HKTAPI.generate
    trigger=HKTAPI.trigger
    def prepare(self):
        n=self.node();cfg=self.generate(n)
        cid=self.trigger(n,cfg).json['command_id']
        return n,cid
    def status(self,n,**kw):
        return self.report(n,capabilities=['hkt_dhcp','hkt_task_status'],**kw)
    def test_lost_delivery_is_queried_and_same_id_redelivered(self):
        n,cid=self.prepare()
        first=self.status(n).json
        self.assertEqual(first['command']['id'],cid)
        self.assertEqual(first['dhcp_task_query']['id'],cid)
        second=self.status(n,dhcp_task_status={'id':cid,'state':'not_started','idle_verified':True}).json
        self.assertEqual(second['command']['id'],cid)
        with server.connect() as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM commands WHERE server_id=?',(n['id'],)).fetchone()[0],1)
    def test_running_is_not_redispatched(self):
        n,cid=self.prepare();self.status(n)
        for _ in range(10):
            r=self.status(n,dhcp_task_status={'id':cid,'state':'running'}).json
            self.assertIsNone(r['command']);self.assertEqual(r['dhcp_task_query']['id'],cid)
    def test_terminal_result_is_reconciled(self):
        n,cid=self.prepare();self.status(n)
        r=self.status(n,dhcp_task_status={'id':cid,'state':'failed','error':'test failure'}).json
        self.assertIsNone(r['dhcp_task_query'])
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'failed')
        self.assertEqual(self.trigger(n,self.generate(n)).status_code,202)
    def test_idle_must_be_verified(self):
        n,cid=self.prepare();self.status(n)
        r=self.status(n,dhcp_task_status={'id':cid,'state':'not_started'}).json
        self.assertIsNone(r['command'])
    def test_pending_new_protocol_task_does_not_expire_before_delivery(self):
        n,cid=self.prepare()
        with server.connect() as db:db.execute('UPDATE commands SET created=created-200 WHERE id=?',(cid,))
        r=self.status(n).json;self.assertEqual(r['command']['id'],cid)
    def test_lost_ack_response_recovers_without_new_job(self):
        n,cid=self.prepare();self.status(n)
        headers={'Authorization':'Bearer '+n['token']}
        for _ in range(3):
            self.assertEqual(self.admin.post(f'/api/agent/commands/{cid}/ack',json={},headers=headers).status_code,200)
        r=self.status(n,dhcp_task_status={'id':cid,'state':'not_started','idle_verified':True}).json
        self.assertEqual(r['command']['id'],cid)
    def test_unknown_keeps_query_and_never_dispatches_duplicate(self):
        n,cid=self.prepare();self.status(n)
        for _ in range(20):
            r=self.status(n,dhcp_task_status={'id':cid,'state':'unknown'}).json
            self.assertIsNone(r['command']);self.assertEqual(r['dhcp_task_query']['id'],cid)
    def test_other_agent_cannot_reconcile_job(self):
        n,cid=self.prepare();self.status(n);other=self.node('other')
        self.status(other,dhcp_task_status={'id':cid,'state':'failed'})
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(cid,)).fetchone()[0],'issued')
    def test_late_terminal_response_does_not_finish_new_job(self):
        n,cid=self.prepare();self.status(n)
        self.status(n,dhcp_task_status={'id':cid,'state':'failed'})
        newer=self.trigger(n,self.generate(n)).json['command_id'];self.status(n)
        r=self.status(n,dhcp_task_status={'id':cid,'state':'changed'}).json
        self.assertEqual(r['dhcp_task_query']['id'],newer)
        with server.connect() as db:self.assertEqual(db.execute('SELECT status FROM commands WHERE id=?',(newer,)).fetchone()[0],'issued')

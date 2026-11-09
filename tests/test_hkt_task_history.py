import unittest
from test_hkt_task_reconcile import TaskReconcile
import server
import hkt_dhcp

class TaskHistory(unittest.TestCase):
    setUp=TaskReconcile.setUp
    post=TaskReconcile.post
    node=TaskReconcile.node
    report=TaskReconcile.report
    generate=TaskReconcile.generate
    trigger=TaskReconcile.trigger
    prepare=TaskReconcile.prepare
    status=TaskReconcile.status
    def detail(self,n,cid,after=0):
        return self.admin.get(f'/api/admin/servers/{n["id"]}/hkt-dhcp/tasks/{cid}?after={after}')
    def test_stages_and_no_credentials(self):
        n,cid=self.prepare();self.status(n)
        self.status(n,dhcp_task_status={'id':cid,'state':'running','attempts':1})
        self.status(n,dhcp_task_status={'id':cid,'state':'failed','error':'secret-token-example'})
        r=self.detail(n,cid);self.assertEqual(r.status_code,200)
        stages=[e['stage'] for e in r.json['events']]
        for stage in ('queued','issued','status_query','accepted','execution','failed'):self.assertIn(stage,stages)
        self.assertTrue(r.json['history_complete']);self.assertNotIn('secret-token-example',r.text)
    def test_repeat_status_is_not_log_storm(self):
        n,cid=self.prepare();self.status(n)
        for _ in range(30):self.status(n,dhcp_task_status={'id':cid,'state':'running'})
        self.assertLess(len(self.detail(n,cid).json['events']),12)
    def test_ownership_and_admin_required(self):
        n,cid=self.prepare();other=self.node('other')
        self.assertEqual(self.detail(other,cid).status_code,404)
        self.assertNotEqual(self.alice.get(f'/api/admin/servers/{n["id"]}/hkt-dhcp/tasks').status_code,200)
    def test_event_pagination_is_complete(self):
        n,cid=self.prepare()
        with server.connect() as db:
            for i in range(205):hkt_dhcp.task_event(db,n['id'],cid,'execution',{'state':'running','attempts':i},1000+i)
        first=self.detail(n,cid).json;self.assertTrue(first['has_more'])
        second=self.detail(n,cid,first['next_after']).json
        ids=[e['id'] for e in first['events']+second['events']]
        self.assertEqual(len(ids),206);self.assertEqual(len(ids),len(set(ids)))
    def test_task_list_pagination(self):
        n,cid=self.prepare()
        with server.connect() as db:
            job=db.execute('SELECT user_id FROM commands WHERE id=?',(cid,)).fetchone()
            for i in range(24):db.execute("INSERT INTO commands(server_id,user_id,action,status,created,updated) VALUES(?,?,'hkt_dhcp','failed',?,?)",(n['id'],job['user_id'],1000+i,1000+i))
        url=f'/api/admin/servers/{n["id"]}/hkt-dhcp/tasks'
        first=self.admin.get(url).json;second=self.admin.get(url+'?before='+str(first['next_before'])).json
        self.assertEqual(len(first['tasks'])+len(second['tasks']),25)

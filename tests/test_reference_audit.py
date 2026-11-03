"""Regression checks for the three release-blocking review findings."""
import sqlite3
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import test_detection_recheck as fixture
import detection_recheck as recheck


class ReferenceAudit(unittest.TestCase):
 setUp=fixture.IndependentRecheck.setUp
 source=fixture.IndependentRecheck.source
 post=fixture.IndependentRecheck.post
 plan=fixture.IndependentRecheck.plan
 incident_run=fixture.IndependentRecheck.incident_run
 setup_plan=fixture.IndependentRecheck.setup_plan
 reference=fixture.IndependentRecheck.reference
 execute=fixture.IndependentRecheck.execute

 def test_independent_node_is_included_in_reference_check(self):
  self.setup_plan();self.execute('unreachable')
  with self.connect() as db:
   row=db.execute('SELECT * FROM detection_rechecks').fetchone()
   import json
   self.assertEqual({x['node_id'] for x in json.loads(row['reference_details'])},{'1','2','3'})
   self.assertEqual(row['node'],'3');self.assertEqual(row['state'],'confirmed')
   self.assertEqual(row['applied'],1)

 def test_provider_target_poll_releases_sqlite_writer_lock(self):
  self.setup_plan()
  self.reference()
  with self.connect() as db:
   db.execute('UPDATE detection_rechecks SET poll_at=0')
   path=db.execute('PRAGMA database_list').fetchone()[2]
  locked=[]
  def slow_provider(*args):
   other=sqlite3.connect(path,timeout=0)
   try:
    other.execute('BEGIN IMMEDIATE');other.rollback();locked.append(False)
   except sqlite3.OperationalError as error:
    self.assertIn('locked',str(error));locked.append(True)
   finally:other.close()
   return {'done':False}
  with patch('detectors.boce',side_effect=slow_provider):recheck.tick(self.connect,self.cipher)
  self.assertEqual(locked,[False])

 def test_midnight_new_probe_cost_is_attributed_to_submission_day(self):
  self.setup_plan()
  midnight=int(datetime(2026,11,4,tzinfo=timezone(timedelta(hours=8))).timestamp())
  with self.connect() as db:
   db.execute('UPDATE detection_runs SET created=?,cost=1',(midnight-2,))
   db.execute('UPDATE detection_plans SET daily_limit=1')
   run=db.execute('SELECT * FROM detection_runs').fetchone();plan=db.execute('SELECT * FROM detection_plans').fetchone()
   self.assertTrue(recheck._budget(db,run,plan,midnight+2,1))
   recheck._reserve_cost(db,run,1,midnight+2) # Actual reservation timestamp belongs to today.
   run=db.execute('SELECT * FROM detection_runs').fetchone()
   self.assertFalse(recheck._budget(db,run,plan,midnight+3,1))

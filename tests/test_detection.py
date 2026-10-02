import copy,json,unittest
from pathlib import Path
from lab.engine import detect,timestamp


class Detection(unittest.TestCase):
    def setUp(self):
        self.events=json.loads(Path('data/events.json').read_text())
        self.at=timestamp('2026-01-15T10:10:00Z')
    def test_baseline_findings_and_evidence(self):
        results=detect(self.events,self.at)
        self.assertEqual([r['rule'] for r in results],['AUTH-001','AUTH-001','AZ-001','IAM-001','IAM-001'])
        self.assertEqual(next(r for r in results if r['rule']=='AZ-001')['evidence'],['delete-01'])
    def test_threshold_below_ten(self):
        self.assertFalse(detect(self.events[:9],self.at))
    def test_exact_threshold(self):
        self.assertEqual(detect(self.events[:10],self.at)[0]['distinct_users'],5)
    def test_distinct_users_case_insensitive(self):
        for e in self.events[:10]: e['UserPrincipalName']='User@example.test'
        self.assertFalse(detect(self.events[:10],self.at))
    def test_fixed_bin_blind_spot(self):
        rows=copy.deepcopy(self.events[:10])
        for i,e in enumerate(rows): e['TimeGenerated']='2026-01-15T10:'+('04:59Z' if i<5 else '05:00Z')
        self.assertFalse(detect(rows,self.at))
    def test_excludes_old_events(self):
        self.assertFalse(detect(self.events,timestamp('2026-01-15T12:00:00Z')))
    def test_failed_role_change_ignored(self):
        rows=[e for e in self.events if e['Id']=='role-01']; rows[0]['Result']='failure'
        self.assertFalse(detect(rows,self.at))
    def test_app_initiator_preserved(self):
        rows=[e for e in self.events if e['Id']=='pim-01']
        self.assertEqual(detect(rows,self.at)[0]['actor'],'00000000-0000-0000-0000-000000000001')
    def test_approved_caller_case(self):
        rows=[e for e in self.events if e['Id']=='approved-01']; rows[0]['Caller']='CHANGE-BOT@example.test'
        self.assertFalse(detect(rows,self.at))
    def test_empty_auth_identity_ignored(self):
        for e in self.events[:10]: e['UserPrincipalName']=''
        self.assertFalse(detect(self.events[:10],self.at))
    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError): timestamp('2026-01-15T10:00:00')
    def test_extreme_timestamp_rejected_as_value_error(self):
        with self.assertRaises(ValueError):
            timestamp('9999-12-31T23:59:59-14:00')

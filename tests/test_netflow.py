import unittest
from netflow_inspector import inspect

class NetflowTests(unittest.TestCase):
    def test_aggregates_totals(self):
        r=inspect([{"src_ip":"a","dst_ip":"b","protocol":"tcp","bytes":"10","packets":"2"}])
        self.assertEqual(r["total_bytes"],10)
        self.assertEqual(r["protocols"]["tcp"],1)
    def test_empty_input(self):
        self.assertEqual(inspect([])["flows"],0)
if __name__ == "__main__": unittest.main()

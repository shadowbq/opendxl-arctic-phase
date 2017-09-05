import unittest
import vcr

from pkg_resources import parse_version

from ratd.api import Atd


class ArcticPhaseTests(unittest.TestCase):

    # Create & Authenticate for subsequent tests
    def setUp(self):
        self.myatd = Atd('atd.localhost.localdomain')
        error_control, data = self.myatd.connect('admin', 'password!')
        self.assertEqual(1, error_control)

    def test_config(self):
        error_control, data = self.myatd.heartbeat()
        self.assertEqual(1, error_control)

    def test_config(self):
        error_control, data = self.myatd.heartbeat()
        self.assertEqual(1, error_control)

    # Get the vmprofilelist
    def test_md5(self):
        error_control, data = self.myatd.get_vmprofiles()
        self.assertEqual(1, error_control)

    # Upload file to ATD Server
    def test_upload(self):
        error_control, data = self.myatd.upload_file('test/data/putty/putty_upx.exe', 24)  # Make this a windows Profile

        if error_control == 0:
            self.assertFalse(True)
        else:
            # print '\nFile %s uploaded\n'%data['file']
            self.assertIsInstance(data['jobId'], int)
            self.assertIsInstance(data['taskId'], int)
            self.assertIsInstance(data['md5'], unicode)
            self.assertIsInstance(data['size'], int)
            self.assertRegexpMatches(data['mimeType'], 'application')

    def test_fetchreport(self):
        error_control, data = self.myatd.get_report(8062)
        if error_control == 1:
            self.assertIsInstance(data['Summary']['Verdict']['Severity'], unicode)
            self.assertIsInstance(data['Summary']['Verdict']['Description'], unicode)
        else:
            self.assertFalse(True)



    if __name__ == '__main__':
        unittest.main()

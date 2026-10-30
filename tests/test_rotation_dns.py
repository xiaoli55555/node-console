import unittest
from unittest.mock import patch
import rotation_dns
from ip_dns import IntegrationError

class RotationDNSPicker(unittest.TestCase):
    def test_domain_validation_and_normalization(self):
        self.assertEqual(rotation_dns.domain_name(' Example.COM. '),'example.com')
        for bad in ('https://example.com','example.com/path','a..com','-bad.com','localhost',''):
            with self.assertRaises(IntegrationError):rotation_dns.domain_name(bad)
    def test_records_pagination_keeps_lines_and_filters_aaaa(self):
        rows=[{'Type':'A','Status':'ENABLE','RecordId':str(i),'Line':'cmcc'} for i in range(100)]
        last=[{'Type':'A','Status':'ENABLE','RecordId':'other','Line':'telecom'},{'Type':'AAAA','Status':'ENABLE','RecordId':'v6'},{'Type':'A','Status':'DISABLE','RecordId':'disabled'}]
        with patch('rotation_dns.dns.alidns',side_effect=[{'DomainRecords':{'Record':rows},'TotalCount':103},{'DomainRecords':{'Record':last},'TotalCount':103}]) as provider:
            records,truncated=rotation_dns.records({'kind':'alidns'},'example.com')
        self.assertEqual(len(records),101);self.assertEqual(records[-1]['Line'],'telecom');self.assertFalse(truncated)
        self.assertEqual(provider.call_args_list[1].kwargs['PageNumber'],2)
    def test_cloudflare_does_not_allow_other_zone(self):
        with patch('rotation_dns.dns.cloudflare_records') as provider:
            with self.assertRaises(IntegrationError):rotation_dns.records({'kind':'cloudflare','config':{'zone_name':'example.com'}},'other.com')
            provider.assert_not_called()

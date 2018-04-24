import unittest

import dnsdb_query
from config import API_KEY, DNSDB_SERVER


class DnsdbClientTestCase(unittest.TestCase):

    def setUp(self):
        super(DnsdbClientTestCase, self).setUp()
        self.client = dnsdb_query.DnsdbClient(
            DNSDB_SERVER,
            API_KEY,
        )


class IpAddressTestCase(DnsdbClientTestCase):

    def test_domain_resolves_to_ip_address(self):
        result = list(self.client.query_rrset(
            'www.farsightsecurity.com',
            rrtype='A',
        ))[0]
        self.assertIn('www.farsightsecurity.com.', result['rrname'])
        self.assertRegexpMatches(result['rdata'][0], r'^\d+\.\d+\.\d+\.\d+')
        self.assertEqual('A', result['rrtype'])
        self.assertGreater(result['count'], 0)
        self.assertIsNotNone(result['time_last'])


class Ipv6AddressTestCase(DnsdbClientTestCase):

    def test_domain_resolves_to_ipv6_address(self):
        # l86
        result = list(self.client.query_rrset(
            'www.farsightsecurity.com',
            rrtype='AAAA',
        ))[0]
        self.assertIn('www.farsightsecurity.com.', result['rrname'])
        self.assertRegexpMatches(result['rdata'][0], r'[0-9a-f:]+')
        self.assertEqual('AAAA', result['rrtype'])
        self.assertGreater(result['count'], 0)
        self.assertIsNotNone(result['time_last'])


class RdataTestCase(DnsdbClientTestCase):

    def test_rtype_has_answers(self):
        result = list(self.client.query_rrset(
            'www.farsightsecurity.com',
            rrtype='AAAA',
        ))[0]
        self.assertIn('www.farsightsecurity.com', result['rrname'])

    def test_no_rrtype_behaves_like_any(self):
        result = list(self.client.query_rrset(
            'www.farsightsecurity.com',
            # NOTE: unset rrtype
        ))[0]
        self.assertIn('www.farsightsecurity.com', result['rrname'])

    def test_nonexistent_rrtype_raises(self):
        with self.assertRaises(dnsdb_query.QueryError):
            result = list(self.client.query_rrset(
                'www.farsightsecurity.com',
                rrtype='HINFO',
            ))


class SameIpTestCase(DnsdbClientTestCase):
    "What domain names pointed to same IP address? (A or AAAA)"

    def test_returns_matching_a_address(self):
        result = list(self.client.query_rdata_ip('8.8.8.8'))[0]
        self.assertEqual('8.8.8.8', result['rdata'])
        self.assertEqual('A', result['rrtype'])

    def test_ipv6_lookup_returns_name_with_same_aaaa_address(self):
        # l192 in dnsdb-api-testing.sh
        ipv6_key = '2001:470:a085:999::80'
        result = list(self.client.query_rdata_ip(ipv6_key))[0]
        self.assertEqual(ipv6_key, result['rdata'])
        self.assertEqual('AAAA', result['rrtype'])
        self.assertGreater(result['count'], 0)
        # TODO: times asserts, what do they assert?


@unittest.skip  # getting a 404
class NetBlockTestCase(DnsdbClientTestCase):

    def test_same_a_address_range(self):
        # l219 in dnsdb-api-testing.sh
        key = '1.179.250.0'
        result = list(self.client.query_rdata_ip(
            key,
            # FIXME: unexpected keyword argument (not supported)
            #rrtype=24,
        ))[0]
        self.assertEqual('A', result['rrtype'])
        # egrep "^.*[a-z0-9_.]+(gvt1|google)\.com\.[[:space:]]+A[[:space:]]+${key%%.0}\.[0-9]+$" $TMPFILE >/dev/null
        #self.assertRegexpMatches(result

    def test_same_aaaa_address_range(self):
        # 242
        pass

    def test_rdata_ipv6_lookup_returns_names_in_same_aaaa_address_range(self):
        # 262
        pass


class BailiwickInverseTestCase(DnsdbClientTestCase):

    def test_rdata_ipv6_net_block_does_not_return_bailiwick(self):
        # l282 in dnsdb-api-testing.sh
        pass

    def test_rdata_lookup_does_not_return_bailiwick(self):
        # l291 in dnsdb-api-testing.sh
        result = list(self.client.query_rrset(
            'www.farsightsecurity.com',
        ))

    def test_json_rdata_lookup_does_not_return_bailiwick(self):
        # l299 in dnsdb-api-testing.sh
        pass


class WildcardTestCase(DnsdbClientTestCase):

    def test_left_wildcard(self):
        """Left wildcard returns some answers."""
        # l318 in dns-api-testing.sh
        result = list(self.client.query_rdata_name(
            '*.farsightsecurity.com',
            rrtype='ANY',
        ))[0]
        # test only that we get records
        self.assertGreater(len(result['rdata']), 0)
        self.assertGreater(result['count'], 0)

    def test_right_wildcard(self):
        """Right wildcard returns some answers."""
        # l343 in dns-api-testing.sh
        # NOTE this passes when we query rrset (?)
        result = list(self.client.query_rdata_name(
            'farsightsecurity.*',
            rrtype='A',
        ))[0]
        self.assertGreater(len(result['rdata']), 0)
        self.assertGreater(result['count'], 0)

    def test_left_no_period_label_separator(self):
        """No results for no-period label separator after asterisk."""
        # l369 in dns-api-testing.sh
        with self.assertRaises(dnsdb_query.QueryError):
            result = list(self.client.query_rdata_name(
                '*farsightsecurity.com',
                rrtype='ANY',
            ))[0]

    def test_right_no_period_label_separator(self):
        # l395 in dns-api-testing.sh
        with self.assertRaises(dnsdb_query.QueryError):
            result = list(self.client.query_rdata_name(
                'farsightsecurity*',
                rrtype='ANY',
            ))[0]

    def test_midstring_no_results(self):
        """No results for middle wildcard."""
        # l425 in dns-api-testing.sh
        with self.assertRaises(dnsdb_query.QueryError):
            result = list(self.client.query_rdata_name(
                'farsig*curity.com',
                rrtype='ANY',
            ))[0]

    def test_partial_label_no_results(self):
        """No results for partial label."""
        # l450 in dns-api-testing.sh
        with self.assertRaises(dnsdb_query.QueryError):
            result = list(self.client.query_rdata_name(
                'farsightsecur*',
                rrtype='ANY',
            ))[0]

    def test_left_and_right_no_results(self):
        """No results for left and right wildcard."""
        # l480 in dns-api-testing.sh
        with self.assertRaises(dnsdb_query.QueryError):
            result = list(self.client.query_rdata_name(
                '*.farsightsecurity.*',
                rrtype='ANY',
            ))[0]


class SpecificRecordTypeTestCase(DnsdbClientTestCase):

    def test_ns_returns_domains_using_same_nameserver(self):
        """rdata lookup of $key rrtype $rrtype should return domains using same $key nameserver: """
        # l517 in dns-api-testing.sh
        result = list(self.client.query_rdata_name(
            'ns.netbsd.de',
            rrtype='NS',
        ))[0]
        self.assertRegexpMatches(result['rrname'], 'netbsd\.(com|net)\.')
        self.assertEqual('ns.netbsd.de.', result['rdata'])
        self.assertEqual('NS', result['rrtype'])
        self.assertGreater(result['count'], 0)
        self.assertIsNotNone(result['time_last'])

    def test_tlsa(self):
        # l547 in dns-api-testing.sh
        # FIXME failing
        result = list(self.client.query_rdata_name(
            '_443._tcp.*',
            rrtype='TLSA',
        ))[0]
        # TODO more assertions when passing

    def test_nsec3(self):
        # l581 in dns-api-testing.sh
        # FIXME: failing
        result = list(self.client.query_rdata_name(
            '*.house.gov',
            rrtype='NSEC3',
        ))[0]
        self.assertIn(result['rrname'], 'house.gov.')
        # TODO
        #self.assertEqual('foo', result['rdata'])
        self.assertEqual('NSEC3', result['rrtype'])
        self.assertGreater(result['count'], 0)
        self.assertIsNotNone(result['time_last'])
    
    def test_nsec3param(self):
        # l601 in dns-api-testing.sh
        # FIXME: failing
        result = list(self.client.query_rdata_name(
            '*.house.gov',
            rrtype='NSEC3PARAM',
        ))[0]
        self.assertIn(result['rrname'], 'house.gov.')
        # TODO
        #self.assertEqual('foo', result['rdata'])
        self.assertEqual('NSEC3PARAM', result['rrtype'])
        self.assertGreater(result['count'], 0)
        self.assertIsNotNone(result['time_last'])

    def test_dlv(self):
        # l621 in dns-api-testing.sh
        # FIXME: failing
        result = list(self.client.query_rdata_name(
            'isc.org.dlv.isc.org',
            rrtype='DLV',
        ))[0]
        self.assertIn(result['rrname'], 'isc.org.dlv.isc.org.')
        # TODO
        #self.assertEqual('foo', result['rdata'])
        self.assertEqual('DLV', result['rrtype'])
        self.assertGreater(result['count'], 0)
        self.assertIsNotNone(result['time_last'])
    
    def test_rrtype_any_dnssec_does_not_return_dnssec_record_types(self):
        # echo "query for special API RRTYPE of ANY should not return DNSSEC record types"
        # l676 in dns-api-testing.sh
        pass

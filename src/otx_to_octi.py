import argparse
import configparser
import datetime
import difflib
import html
import os
import requests
import requests_cache
import stix2
import sys
import tldextract
import yaml

from pycti import OpenCTIConnectorHelper
from pretty_printer import PrettyPrinter


CONF_FILE = '{}/config.cfg'.format(os.path.dirname(os.path.abspath(__file__)))

SECTOR_MAPPINGS = {}
REF_TLPS = {}


PATTERNTYPES = ['yara', 'sigma', 'pcre', 'snort', 'suricata']
OPENCTISTIX2 = {
    'autonomous-system': {'type': 'autonomous-system', 'path': ['number'],
                          'transform': {'operation': 'remove_string', 'value': 'AS'}},
    'mac-addr': {'type': 'mac-addr', 'path': ['value']},
    'domain': {'type': 'domain-name', 'path': ['value']},
    'ipv4-addr': {'type': 'ipv4-addr', 'path': ['value']},
    'ipv6-addr': {'type': 'ipv6-addr', 'path': ['value']},
    'url': {'type': 'url', 'path': ['value']},
    'email-address': {'type': 'email-addr', 'path': ['value']},
    'email-subject': {'type': 'email-message', 'path': ['subject']},
    'mutex': {'type': 'mutex', 'path': ['name']},
    'file-name': {'type': 'file', 'path': ['name']},
    'file-path': {'type': 'file', 'path': ['name']},
    'file-md5': {'type': 'file', 'path': ['hashes', 'MD5']},
    'file-sha1': {'type': 'file', 'path': ['hashes', 'SHA1']},
    'file-sha256': {'type': 'file', 'path': ['hashes', 'SHA256']},
    'directory': {'type': 'directory', 'path': ['path']},
    'registry-key': {'type': 'windows-registry-key', 'path': ['key']},
    'registry-key-value': {'type': 'windows-registry-value-type', 'path': ['data']},
    'pdb-path': {'type': 'file', 'path': ['name']},
    'windows-service-name': {'type': 'windows-service-ext', 'path': ['service_name']},
    'windows-service-display-name': {'type': 'windows-service-ext', 'path': ['display_name']},
    'x509-certificate-issuer': {'type': 'x509-certificate', 'path': ['issuer']},
    'x509-certificate-serial-number': {'type': 'x509-certificate', 'path': ['serial_number']}
}

class OTX:

    def __init__(self, config):
        self.config = config['OTX']
        self.headers = {'X-OTX-API-KEY': self.config['api_key']}
        self.base_pulse_url = "{}{}".format(self.config['api_host'], self.config['api_pulses'])

    def _update_last_check(self):
        self.config['last_check'] = datetime.datetime.utcnow().isoformat()

    def _get_pulses(self, url, params=None):
        res = requests.get(url, headers=self.headers, params=params)
        if res.status_code == 200:
            return True, res.json()

        return False, res.text

    def get_subscriptions(self):
        reports = []

        params = {'modified_since': self.config['last_check'], 'limit': self.config['otx_page_size']}
        url = f"{self.base_pulse_url}/subscribed"

        round = 1
        while True:

            status, body = self._get_pulses(url, params)
            if status:
                if round == 1:
                    printer.info("Got {} total results".format(body['count']))
                round = round + 1
                printer.info("Got {} results in this request".format(len(body['results'])))
                reports.extend(body['results'])

                if body['next']:
                    url = body['next']
                    params = None
                else:
                    break

            else:
                printer.error(body)

        self._update_last_check()
        return reports

    def get_subscription(self, id):
        status, body = self._get_pulses(f"{self.base_pulse_url}/{id}")
        if status:
            printer.debug("Got result")
            return [body]
        else:
            printer.error(body)


class OpenCTI:

    octi_sectors = {}

    def __init__(self, config, dryrun):
        self.config = config['OpenCTI']
        self.dryrun = dryrun
        self._get_octi_sectors()

        self.connector_config = {
                'name': self.config['connector_name'],
                'confidence_level': 3,
                'entities': 'report, intrusion-set, identity',
                'interval': 0,
                'log_level': 'info'
            }

        confyml_path = os.path.dirname(os.path.abspath(__file__)) + '/config.yml'
        confyml = yaml.load(open(confyml_path), Loader=yaml.FullLoader) if os.path.isfile(confyml_path) else {}

        self.opencti_connector_helper = OpenCTIConnectorHelper(confyml)

    def _get_octi_sectors(self):
        res = requests.get(self.config['sectors_url'])
        if res.status_code != 200:
            printer.error("Error getting sectors")
            sys.exit(1)

        for sector in res.json()['objects']:
            if 'name' in sector:
                self.octi_sectors[sector['name'].upper()] = sector['id']


    def resolve_type(self, type):
        types = {
            'filehash-md5': 'file-md5',
            'filehash-sha1': 'file-sha1',
            'filehash-sha256': 'file-sha256',
            'filepath': 'file-name',
            'ipv4': 'ipv4-addr',
            'ipv6': 'ipv6-addr',
            'hostname': 'domain',
            'domain': 'domain',
            'url': 'url'
        }
        if type in types:
            return types[type]

    def process_reports(self, reports):
        if reports is None:
            printer.error("No results")
            return

        for report in reports:
            name = report["name"]
            id = report["id"]
            stix2_objects = []
            stix2_object_refs = []

            # FFS AV, consistency!
            if 'tlp' in report:
                tlp_id = REF_TLPS[report['tlp'].upper()]
            elif 'TLP' in report:
                tlp_id = REF_TLPS[report['TLP'].upper()]
            else:
                tlp_id = REF_TLPS['WHITE']

            sectors = report['industries']
            if sectors:
                unmatched_sectors = []
                added_sector = False

                for sector in [html.unescape(x.upper()) for x in sectors]:
                    sector_name = None
                    sector_id = None

                    if sector in SECTOR_MAPPINGS:
                        # sector_ids.append(self.octi_sectors[SECTOR_MAPPINGS[sector]])
                        sector_name = SECTOR_MAPPINGS[sector]
                        try:
                            sector_id = self.octi_sectors[SECTOR_MAPPINGS[sector]]
                        except Exception as e:
                            printer.error(e)
                            continue
                    else:
                        printer.debug(f"Looking for sector {sector}")
                        match = difflib.get_close_matches(sector, self.octi_sectors.keys(), 1)
                        if not len(match):
                            printer.error(f"Unable to determine a matching sector for {sector}")
                            unmatched_sectors.append(sector)
                            continue
                        # sector_ids.append(self.octi_sectors[match[0]])
                        sector_name = match[0]
                        sector_id = self.octi_sectors[match[0]]

                    if sector_name is not None:
                        s = stix2.Identity(
                            id=sector_id,
                            name=sector_name,
                            identity_class='class',
                            custom_properties={
                                'x_opencti_identity_type': 'sector'
                            }
                        )
                        printer.debug(f"Adding sector {sector_name}")
                        stix2_objects.append(s)
                        stix2_object_refs.append(s)
                        added_sector = True

                if not added_sector:
                    printer.warn("Adding 'UNKNOWN' placeholder sector")
                    s = stix2.Identity(
                        id=self.octi_sectors["UNKNOWN"],
                        name="Unknown",
                        identity_class='class',
                        custom_properties={
                            'x_opencti_identity_type': 'sector'
                        }
                    )
                    stix2_objects.append(s)
                    stix2_object_refs.append(s)

                description = report['description']
                if len(unmatched_sectors):
                    description = description + "\n\n###\nUnable to find a match for the following sectors, " \
                                                "please review manually:\n - " + '\n - '.join(unmatched_sectors)

                printer.info(f"Generating STIX2 for {name} ({id})")


                author = stix2.Identity(
                    name = report['author_name'],
                    identity_class = 'organization'
                )
                stix2_objects.append(author)

                adversary = None
                if report['adversary']:
                    printer.debug("Adding adversary {}".format(report['adversary']))
                    adversary = stix2.IntrusionSet(
                        name=report['adversary']
                    )
                    stix2_object_refs.append(adversary)
                    stix2_objects.append(adversary)

                if report['targeted_countries']:
                    for country in report['targeted_countries']:
                        printer.debug(f"Adding country {country}")
                        c = stix2.Identity(
                            name=country,
                            identity_class='organization',
                            custom_properties={
                                'x_opencti_identity_type': 'country'
                            }
                        )
                        stix2_objects.append(c)
                        stix2_object_refs.append(c)

                external_refs = []
                for eref in report['references']:
                    external_refs.append(
                        stix2.ExternalReference(
                            source_name=tldextract.extract(eref).registered_domain,
                            url=eref
                        )
                    )

                indicators = report["indicators"]
                if indicators:
                    for indicator in indicators:
                        resolved_type = self.resolve_type(indicator["type"].lower())
                        if resolved_type != None and indicator["is_active"]:

                            observable_type = resolved_type
                            observable_value = indicator["indicator"]
                            pattern_type = 'stix'

                            try:
                                if observable_type in PATTERNTYPES:
                                    pattern_type = observable_type
                                elif observable_type not in OPENCTISTIX2:
                                    printer.info("Not in stix2 dict")
                                else:
                                    if 'transform' in OPENCTISTIX2[observable_type]:
                                        if OPENCTISTIX2[observable_type]['transform']['operation'] == 'remove_string':
                                            observable_value = observable_value.replace(OPENCTISTIX2[observable_type]['transform']['value'], '')
                                    lhs = stix2.ObjectPath(OPENCTISTIX2[observable_type]['type'], OPENCTISTIX2[observable_type]['path'])
                                    observable_value = stix2.ObservationExpression(stix2.EqualityComparisonExpression(lhs, observable_value))
                            except Exception as e:
                                printer.error(e)
                                printer.info("Could not determine suitable pattern")

                            try:

                                indicator_obj = stix2.Indicator(
                                    name=indicator["indicator"],
                                    description=indicator["description"],
                                    pattern=str(observable_value),
                                    valid_from=indicator["created"],
                                    labels=['malicious-activity'],
                                    created_by_ref=author,
                                    object_marking_refs=[tlp_id],
                                    custom_properties={
                                        'x_opencti_observable_type': resolved_type,
                                        'x_opencti_observable_value': indicator["indicator"],
                                        'x_opencti_pattern_type': pattern_type
                                    }

                                )
                                stix2_object_refs.append(indicator_obj)
                                stix2_objects.append(indicator_obj)
                            except Exception as e:
                                printer.error(e)
                                printer.info("Couldn't fetch indicator")

                else:
                    printer.error("No indicators")

                report = stix2.Report(
                    name=name,
                    description=description,
                    created_by_ref=author,
                    labels=['threat-report'],
                    published=report['created'],
                    created=report['created'],
                    modified=report['modified'],
                    object_refs=stix2_object_refs,
                    object_marking_refs=[tlp_id],
                    external_references=external_refs
                )
                stix2_objects.append(report)
                bundle = stix2.Bundle(stix2_objects).serialize()
                if not self.dryrun:
                    self.opencti_connector_helper.send_stix2_bundle(bundle, None, True, False)
                    printer.info("Sending to OpenCTI")
                #printer.debug(str(bundle))

            else:
                printer.debug(f"No sectors, disregarding '{name}'")


def _load_mappings(config):

    for x in config['Sector Mappings']:
        SECTOR_MAPPINGS[x.upper()] = config['Sector Mappings'][x].upper()

    for x in config['TLP']:
        REF_TLPS[x.upper()] = config['TLP'][x]


def main():

    global printer
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', dest='verbose', help="Verbose output", required=False, action='store_true')
    parser.add_argument('--dry-run', dest='dryrun', help="Do not upload to OpenCTI, just parse feeds",
                        required=False, action='store_true')
    args = parser.parse_args()

    printer = PrettyPrinter(debug=args.verbose, wrap=240)

    requests_cache.install_cache()

    config = configparser.ConfigParser()
    config.read(CONF_FILE)
    _load_mappings(config)

    otx = OTX(config)
    octi = OpenCTI(config, args.dryrun)

    try:
        reports = otx.get_subscriptions()
        octi.process_reports(reports)

    finally:
        if not args.dryrun:
            with open(CONF_FILE, 'w') as f:
                config.write(f)


main()

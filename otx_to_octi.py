#! /usr/bin/env python3

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

from pycti import OpenCTIConnectorHelper
from pretty_printer import PrettyPrinter


CONF_FILE = '{}/config.cfg'.format(os.path.dirname(os.path.abspath(__file__)))

SECTOR_MAPPINGS = {}
REF_TLPS = {}


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

        self.opencti_connector_helper = OpenCTIConnectorHelper(
            self.config['connector_name'].lower(),
            self.connector_config,
            {
                'hostname': self.config['rabbitmq_hostname'],
                'port': int(self.config['rabbitmq_port']),
                'username': self.config['rabbitmq_username'],
                'password': self.config['rabbitmq_password']
            },
            self.connector_config['log_level']
        )

    def _get_octi_sectors(self):
        res = requests.get(self.config['sectors_url'])
        if res.status_code != 200:
            printer.error("Error getting sectors")
            sys.exit(1)

        for sector in res.json()['objects']:
            if 'name' in sector:
                self.octi_sectors[sector['name'].upper()] = sector['id']

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
                        sector_id = self.octi_sectors[SECTOR_MAPPINGS[sector]]
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

                bundle = stix2.Bundle(stix2_objects)
                if not self.dryrun:
                    self.opencti_connector_helper.send_stix2_bundle(str(bundle), self.connector_config['entities'])
                    printer.info("Sending to OpenCTI")
                printer.debug(str(bundle))

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

"""
Builds a STIX Exploit Target from a CVE number.

The script will look at the first parameter as the CVE number and uses
the ares module (https://github.com/mrsmn/ares), to provide data from
https://cve.circl.lu/. This provides a quick and easy method of prototyping
the core information from publicly available CVE information into a
STIX package.
"""

import argparse
import json
import os
import sys

import requests
from ares import CVESearch
from stix.coa import CourseOfAction
from stix.common import Identity, InformationSource
from stix.core import STIXHeader, STIXPackage
from stix.data_marking import Marking, MarkingSpecification
from stix.exploit_target import ExploitTarget, Vulnerability, Weakness
from stix.exploit_target.vulnerability import CVSSVector
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.ttp import TTP, Behavior
from stix.ttp.behavior import AttackPattern

import common.ingest as ingest
import common.taxii as taxii

PATH = os.path.dirname(os.path.abspath(sys.argv[0]))

with open('config.json') as data_file:
    CONFIG = json.load(data_file)

NS_PREFIX = CONFIG['stix'][0]['ns_prefix']
NS = CONFIG['stix'][0]['ns']
NVD_URL = "https://web.nvd.nist.gov/view/vuln/detail?vulnId="
HNDL_ST = "This information may be distributed without restriction."
COAS = CONFIG['coas']
TTPON = CONFIG['ttp']


def _marking():
    """Define the TLP marking and the inheritance."""
    marking_specification = MarkingSpecification()
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    marking_specification.controlled_structure = "../../../../descendant"\
        "-or-self::node() | ../../../../descendant-or-self::node()/@*"
    simple = SimpleMarkingStructure()
    simple.statement = HNDL_ST
    marking_specification.marking_structures.append(simple)
    handling = Marking()
    handling.add_marking(marking_specification)
    return handling


def _weakbuild(data):
    """Define the weaknesses."""
    if data['cwe'] != 'Unknown':
        weak = Weakness()
        weak.cwe_id = data['cwe']
        return weak


def _buildttp(i, expt):
    """Do some TTP stuff."""
    ttp = TTP()
    ttp.title = str(i['name'])
    # The summary key is a list. In 1.2 this is represented
    # properly using description ordinality.
    ttp.description = i['summary']
    attack_pattern = AttackPattern()
    attack_pattern.capec_id = "CAPEC-" + str(i['id'])
    ttp.behavior = Behavior()
    ttp.behavior.add_attack_pattern(attack_pattern)
    ttp.exploit_targets.append(ExploitTarget(idref=expt.id_))
    return ttp


def _vulnbuild(data):
    """Do some vulnerability stuff."""
    vuln = Vulnerability()
    vuln.cve_id = data['id']
    vuln.source = NVD_URL + data['id']
    vuln.title = data['id']
    vuln.description = data['summary']
    # The below has issues with python-stix 1.2 and below
    # (https://github.com/STIXProject/python-stix/issues/276)
    # vuln.published_datetime = data['Published']
    vuln.references = data['references']
    vuln.is_known = 1
    # Create the CVSS object and then assign it to the vulnerability object
    cvssvec = CVSSVector()
    cvssvec.overall_score = data['cvss']
    vuln.cvss_score = cvssvec
    return vuln


def _postconstruct(xml, title):
    if CONFIG['ingest'][0]['active'] == True:
        try:
            ingest._inbox_package(CONFIG['ingest'][0]['endpoint'] +
                                  CONFIG['ingest'][0]['user'], xml)
            print("[+] Successfully ingested " + title)
        except ValueError:
            print("[+] Failed ingestion for " + title)
    elif CONFIG['taxii'][0]['active'] == True:
        try:
            taxii._taxii(xml, CONFIG['taxii'][0]['host'],
                         CONFIG['taxii'][0]['ssl'], CONFIG[
                             'taxii'][0]['discovery_path'],
                         CONFIG['taxii'][0]['binding'], CONFIG[
                             'taxii'][0]['username'],
                         CONFIG['taxii'][0]['password'],
                         CONFIG['taxii'][0]['inbox_path'])
            print("[+] Successfully inboxed " + title)
        except requests.exceptions.ConnectionError:
            print("[+] Failed inbox for " + title)
    else:
        with open(title + ".xml", "w") as text_file:
            text_file.write(xml)
        print("[+] Successfully generated " + title)


def lastcve():
    """Grab the last 30 CVEs."""
    cve = CVESearch()
    data = json.loads(cve.last())
    print("[+] Attempting to retrieve the latest 30 CVEs")
    if data:
        try:
            for vulns in data['results']:
                with open('history.txt', 'ab+') as history_file:
                    if vulns['id'] in history_file.read():
                        print("[+] Package already generated for " + vulns['id'])
                    else:
                        history_file.seek(0, 2)
                        cvebuild(vulns['id'])
                        history_file.write(vulns['id'] + "\n")
        except ImportError:
            pass


def cvebuild(var):
    """Search for a CVE ID and return a STIX formatted response."""
    cve = CVESearch()
    data = json.loads(cve.id(var))
    if data:
        try:
            from stix.utils import set_id_namespace
            namespace = {NS: NS_PREFIX}
            set_id_namespace(namespace)
        except ImportError:
            from stix.utils import idgen
            from mixbox.namespaces import Namespace
            namespace = Namespace(NS, NS_PREFIX, "")
            idgen.set_id_namespace(namespace)

        pkg = STIXPackage()
        pkg.stix_header = STIXHeader()
        pkg = STIXPackage()
        pkg.stix_header = STIXHeader()

        pkg.stix_header.handling = _marking()

        # Define the exploit target
        expt = ExploitTarget()
        expt.title = data['id']
        expt.description = data['summary']
        expt.information_source = InformationSource(
            identity=Identity(name="National Vulnerability Database"))

        # Add the vulnerability object to the package object
        expt.add_vulnerability(_vulnbuild(data))

        # Add the COA object to the ET object
        for coa in COAS:
            expt.potential_coas.append(
                CourseOfAction(
                    idref=coa['id'],
                    timestamp=expt.timestamp))

        # Do some TTP stuff with CAPEC objects
        if TTPON is True:
            try:
                for i in data['capec']:
                    pkg.add_ttp(_buildttp(i, expt))
            except KeyError:
                pass

        expt.add_weakness(_weakbuild(data))

        # Add the exploit target to the package object
        pkg.add_exploit_target(expt)

        xml = pkg.to_xml()
        title = pkg.id_.split(':', 1)[-1]
        # If the function is not imported then output the xml to a file.
        if __name__ == '__main__':
            _postconstruct(xml, title)
        return xml


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(
        description='Search for a CVE ID and return a STIX formatted response.')
    PARSER.add_argument('-i', '--id', type=cvebuild,
                        help='Enter the CVE ID that you want to grab')
    PARSER.add_argument('-l', '--last', action='store_true',
                        help='Pulls down and converts the latest 30 CVEs')
    ARGS = PARSER.parse_args()
    if ARGS.last == True:
        lastcve()

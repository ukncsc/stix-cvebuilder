"""
Builds a STIX Exploit Target from a CVE number.

The script will look at the first parameter as the CVE number and uses
the ares module (https://github.com/mrsmn/ares), to provide data from
https://cve.circl.lu/. This provides a quick and easy method of prototyping
the core information from publicly available CVE information into a
STIX package.
"""

from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.exploit_target import ExploitTarget, Vulnerability, Weakness, PotentialCOAs
from stix.exploit_target.vulnerability import CVSSVector
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.coa import CourseOfAction
from stix.ttp import TTP
from stix.common import InformationSource, Identity, RelatedCOA
from stix.common.related import GenericRelationshipList, RelatedCOA

from ares import CVESearch
import json
import sys
from ConfigParser import SafeConfigParser
import os

PATH = os.path.dirname(os.path.abspath(sys.argv[0]))
PARSER = SafeConfigParser()
PARSER.read(PATH + '/config.ini')

NS_PREFIX = PARSER.get('STIX', 'ns_prefix')
NS = PARSER.get('STIX', 'ns')
NVD_URL = "https://web.nvd.nist.gov/view/vuln/detail?vulnId="
HNDL_ST = "This information may be distributed without restriction."
COA = PARSER.get('COA', 'coa1')


def marking():
    """Define the TLP marking and the inheritence."""
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "../../../../descendant"\
        "-or-self::node() | ../../../../descendant-or-self::node()/@*"
    simple = SimpleMarkingStructure()
    simple.statement = HNDL_ST
    marking_specification.marking_structures.append(simple)
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    handling = Marking()
    handling.add_marking(marking_specification)
    return handling


def coabuild(coaid):

    return coa


def vulnbuild(data):
    """Do some vulnerability stuff."""
    vuln = Vulnerability()
    vuln.cve_id = data['id']
    vuln.source = NVD_URL + data['id']
    vuln.title = data['id']
    vuln.description = data['summary']
    # The below has issues with python-stix 1.2 (https://github.com/STIXProject
    # /python-stix/issues/276)
    # vuln.published_datetime = data['Published']
    vuln.references = data['references']
    vuln.is_known = 1
    # Create the CVSS object and then assign it to the vuln object
    cvssvec = CVSSVector()
    cvssvec.overall_score = data['cvss']
    vuln.cvss_score = cvssvec
    return vuln


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

        pkg.stix_header.handling = marking()

        # Define the exploit target
        expt = ExploitTarget()
        expt.title = data['id']
        expt.description = data['summary']
        expt.information_source = InformationSource(
            identity=Identity(name="National Vulnerability Database"))

        # Add the vulnerability object to the package object
        expt.add_vulnerability(vulnbuild(data))

        # Add the COA object to the ET object
        expt.potential_coas.append(CourseOfAction(idref=COA))

        # Do some TTP stuff with CAPEC objects
        try:
            for i in data['capec']:
                ttp = TTP()
                ttp.title = "CAPEC-" + str(i['id'])
                ttp.description = i['summary']
                ttp.exploit_targets.append(ExploitTarget(idref=expt.id_))
                pkg.add_ttp(ttp)
        except KeyError:
            pass

        # Do some weakness stuff
        if data['cwe'] != 'Unknown':
            weak = Weakness()
            weak.cwe_id = data['cwe']
            expt.add_weakness(weak)

        # Add the exploit target to the package object
        pkg.add_exploit_target(expt)

        xml = pkg.to_xml()

        # If the function is not imported then output the xml to a file.
        if __name__ == '__main__':
            title = pkg.id_.split(':', 1)[-1]
            with open(title + ".xml", "w") as text_file:
                text_file.write(xml)
        return xml

if __name__ == '__main__':
    # Does a quick check to ensure a variable has been given to the script
    if len(sys.argv) > 1:
        EXPLOITXML = cvebuild(sys.argv[1])
        print(EXPLOITXML)
    else:
        print("Please enter a CVE ID to enrich.")

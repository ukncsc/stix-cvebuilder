"""
The script will look at the first parameter as the CVE number and uses
the ares module (https://github.com/mrsmn/ares), to provide data from
https://cve.circl.lu/. This provides a quick and easy method of prototyping
the core information from publicly available CVE information into a
STIX package.
"""

from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.exploit_target import ExploitTarget, Vulnerability, Weakness
from stix.exploit_target.vulnerability import CVSSVector
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.ttp import TTP

from ares import CVESearch
import json
import sys
from ConfigParser import SafeConfigParser
import os

path = os.path.dirname(os.path.abspath(sys.argv[0]))
parser = SafeConfigParser()
parser.read(path + '/config.ini')

NS_PREFIX = parser.get('STIX', 'ns_prefix')
NS = parser.get('STIX', 'ns')
NVD_URL = "https://web.nvd.nist.gov/view/vuln/detail?vulnId="
HNDL_ST = "This information may be distributed without restriction."


def doMarking():
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


def doVuln(data):
    """Do some vulnerability stuff"""
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


def cveSearch(var):
    """Search for a CVE ID and return a STIX formatted response"""
    cve = CVESearch()
    data = json.loads(cve.id(var))

    try:
        from stix.utils import set_id_namespace
        namespace = {NS : NS_PREFIX}
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

    pkg.stix_header.handling = doMarking()

    # Define the exploit target
    et = ExploitTarget()
    et.title = data['id']
    et.description = data['summary']

    # Add the vulnerability object to the package object
    et.add_vulnerability(doVuln(data))

    # Do some TTP stuff with CAPEC objects
    for i in data['capec']:
        ttp = TTP()
        ttp.title = "CAPEC-" + str(i['id'])
        ttp.description = i['summary']
        ttp.exploit_targets.append(ExploitTarget(idref=et.id_))
        pkg.add_ttp(ttp)

    # Do some weakness stuff
    weak = Weakness()
    weak.cwe_id = data['cwe']
    et.add_weakness(weak)

    # Add the exploit target to the package object
    pkg.add_exploit_target(et)

    xml = pkg.to_xml()

    # If the function is not imported then output the xml to a file.
    if __name__ == '__main__':
        title = pkg.id_.split(':', 1)[-1]
        with open(title + ".xml", "w") as text_file:
            text_file.write(xml)
    return(xml)

if __name__ == '__main__':
    exploitxml = cveSearch(sys.argv[1])
    print(exploitxml)

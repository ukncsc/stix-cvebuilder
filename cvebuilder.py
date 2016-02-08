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
from stix.utils import set_id_namespace

from ares import CVESearch
import json
import sys

NAMESPACE = {"http://avengers.example.com": "avengers"}
NVD_URL = "https://web.nvd.nist.gov/view/vuln/detail?vulnId="


def doMarking():
    """Define the TLP marking and the inheritence."""
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "../../../../descendant-or-self::node() | ../../../../descendant-or-self::node()/@*"
    simple = SimpleMarkingStructure()
    simple.statement = "This information may be distributed without restriction."
    marking_specification.marking_structures.append(simple)
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    handling = Marking()
    handling.add_marking(marking_specification)
    return handling


def cveSearch(var):
    """Search for a CVE ID and return a STIX formatted response"""
    cve = CVESearch()
    data = json.loads(cve.id(var))

    set_id_namespace(NAMESPACE)

    pkg = STIXPackage()
    pkg.stix_header = STIXHeader()

    pkg.stix_header.handling = doMarking()

    # Define the exploit target
    et = ExploitTarget()
    et.title = data['id']
    et.description = data['summary']

    # Do some vulnerability stuff
    vuln = Vulnerability()
    vuln.cve_id = data['id']
    vuln.source = NVD_URL + data['id']
    vuln.title = data['id']
    vuln.description = data['summary']
    # vuln.published_datetime = data['Published']
    vuln.references = data['references']
    vuln.is_known = 1

    # Create the CVSS object and then assign it to the vuln object
    cvssvec = CVSSVector()
    cvssvec.overall_score = data['cvss']
    vuln.cvss_score = cvssvec

    # Add the vulnerability object to the package object
    et.add_vulnerability(vuln)

    # Do some COA stuff
    # coa = PotentialCOAs().PotentialCOA()
    # print(dir(coa))

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
    # weak.description = i['title']
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
    # Does a quick check to ensure a variable has been given to the script
    if len(sys.argv) > 1:
        exploitxml = cveSearch(sys.argv[1])
        print(exploitxml)
    else:
        print("Please enter a CVE ID to enrich.")

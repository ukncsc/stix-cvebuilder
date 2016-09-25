Copyright (c) 2016 Crown Copyright (CERT-UK)

Permission is hereby granted, free of charge, to use, copy, modify, merge, distribute and/or sub-licence the software together with any associated documentation provided that it is solely for your own internal use and subject to the following conditions:

(1) The above copyright notice and this permission notice shall be included in all copies or substantial portions of the software.

(2) THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT ANY WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN ANY ACTION FOR CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# CVE-Builder

[![Code Health](https://landscape.io/github/certuk/cve-builder/master/landscape.svg?style=flat)](https://landscape.io/github/certuk/cve-builder/master)

CVE Builder script that generates STIX Exploit Targets.

The script will look at the first parameter as the CVE number and uses the ares module (<https://github.com/mrsmn/ares>), to provide data from <https://cve.circl.lu/>. This provides a quick and easy method of prototyping the core information from publicly available CVE information into a STIX package.

Once generated the script has support for ingestion using the CERT-UK Edge mods or using native TAXII. If neither of these methods are required then the script will dump the XML into the current directory of the script.

## Status

The script is still under active development and as such shouldn't be considered a finished product.

## Setup

To install the script you can clone the repository using `git clone`.

Before using the script you will need setup the config file with your own settings:

1. Make a copy of the `config.json.template` file and rename it to `config.json`.
2. Enter your own settings inside your `config.json` file.

  - The `coas` key defines any COAs you would like to relate to your ET object.
  - The `ttp` key defines if you want TTP objects to be built as part of the package.
  - The `stix` key defines your namespace and prefix.
  - The `ingest` key defines settings related to API ingestion.
  - The `taxii` key defines settings related to TAXII inboxing.

Once setup your file should look like this:

```json
{
  "coas": [
    {
      "id": "avengers:coa-0c6e0337-18bc-4f58-a712-5fd743565180"
    }
  ],
  "ingest": [
    {
      "active": false,
      "endpoint": "http://kb.avengers.com/adapter/certuk_mod/import/",
      "user": "bot"
    }
  ],
  "stix":
    {
      "ns": "http://avengers.com",
      "ns_prefix": "avengers",
      "handling": "This information may be distributed without restriction."
    },
  "taxii": [
    {
      "active": false,
      "binding": "urn:stix.mitre.org:xml:1.1.1",
      "discovery_path": "/taxii-discovery-service",
      "host": "kb.avengers.com",
      "inbox_path": "/taxii-data",
      "password": "password",
      "ssl": false,
      "username": "username"
    }
  ],
  "ttp": false
}
```

## Usage

From a terminal/command prompt you can use the `-h` option to get an output of the available arguments.

```
$ python cvebuilder.py -h
usage: cvebuilder.py [-h] [-i ID] [-l]

Search for a CVE ID and return a STIX formatted response.

optional arguments:
  -h, --help      show this help message and exit
  -i ID, --id ID  Enter the CVE ID that you want to grab
  -l, --last      Pulls down and converts the latest 30 CVEs
```

To get a single CVE ID returned you would use the following command.

```
$ python cvebuilder.py -i CVE-2015-5119
```

Or if you wanted to get the last 30 CVE IDs.

```
$ python cvebuilder.py -l
```

Both of these commands will generate the STIX file for the CVE ID unless you have enabled either the TAXII or CERT-UK Ingest options in the `config.json` file.

Or you can use it as a module within your own script.

```python
from cve-builder import cveSearch

result = cveSearch("CVE-2015-5119")
print(cveSearch)
```

## Example Output

An example output can be found in the [Example](Example-Package-7cbc9064-8662-4fca-8b1e-4bdc3d32e0a7.xml) file. This example uses CVE-2015-5119.

## Dependencies

The following python libraries are required and can be installed with pip.

- ares (<https://github.com/mrsmn/ares>)
- stix (<https://github.com/STIXProject/python-stix>)
- cabby (<https://github.com/EclecticIQ/cabby>)

### Installation

```
$ sudo pip install -r requirements.txt
```

## Feedback

We would welcome feedback on this script and the functionality it provides. Please raise an issue on GitHub.

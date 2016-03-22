# CVE-Builder
[![Code Health](https://landscape.io/github/certuk/cve-builder/master/landscape.svg?style=flat)](https://landscape.io/github/certuk/cve-builder/master)

CVE Builder script that generates STIX formatted Exploit Targets.

The script will look at the first parameter as the CVE number and uses the ares module (https://github.com/mrsmn/ares), to provide data from https://cve.circl.lu/. This provides a quick and easy method of prototyping the core information from publicly available CVE information into a STIX package.

Full warning this script is still a work in progress and is by no means a one stop shop to build a fully featured exploit target in STIX. Your own mileage may vary.

## Setup
Before using the script you will need setup the config file with your own settings:

1. Make a copy of the `config.json.template` file and rename it to `config.json`.
2. Enter your own settings inside your `config.json` file.
  * The `coas` key defines any COAs you would like to relate to your ET object.

Once setup your file should look like this:
```JSON
{
  "stix": [{
    "ns": "http://avengers.com",
    "ns_prefix": "avengers"
  }],
  "coas": [{
    "id": "avengers:coa-0c6e0337-18bc-4f58-a712-5fd743565180"
  }]
}
```


## Usage
From a terminal/command prompt you can use the following to print the STIX and save it as a file.
```
$ python cve-builder.py --ttp 1 CVE-2015-5119
```

The optional `--ttp` flag designates if TTPs will be included in the package. By default this is set to 0 (off).

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
* ares (https://github.com/mrsmn/ares)
* stix (https://github.com/STIXProject/python-stix)


### Installation on Ubuntu 15.10 (and older)
```
$ sudo pip install -r requirements.txt
```

## License
See the [LICENSE](LICENSE) file for license rights and limitations (GPLv3).

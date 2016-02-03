# CVE-Builder
CVE Builder script that generates STIX formatted Exploit Targets.

The script will look at the first parameter as the CVE number and uses the ares module (https://github.com/mrsmn/ares), to provide data from https://cve.circl.lu/. This provides a quick and easy method of prototyping the core information from publicly available CVE information into a STIX package.

Full warning this script is still a work in progress and is by no means a one stop shop to build a fully featured exploit target in STIX. Your own mileage may vary.

## Usage
From a terminal/command prompt you can use the following to print the STIX and save it as a file.
```
$ python cve-builder CVE-2015-5119
```

Or you can use it as a module within your own script.
```python
from cve-builder import cveSearch

result = cveSearch("CVE-2015-5119")
print(cveSearch)

```

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

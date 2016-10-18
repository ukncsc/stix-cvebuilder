"""
Provides common functions for the CVE-Builder script.

The script provides functionality for both TAXII inboxing aswell as using
NCSC's custom adapter inbox.
"""

import json

import requests
from cabby import create_client


def _construct_headers():
    headers = {
        'Content-Type': 'application/xml',
        'Accept': 'application/json'
    }
    return headers


def _certuk_inbox(content, endpoint_url):
    """Inbox the package to the certuk adapter."""
    data = content
    headers = _construct_headers()
    response = requests.post(endpoint_url, data=data, headers=headers)
    print(json.dumps(response.json(), indent=4))
    return


def _taxii_inbox(content, config):
    client = create_client(config['host'], use_https=config[
                           'ssl'], discovery_path=config['discovery_path'])
    content = content
    binding = config['binding']
    client.set_auth(username=config['username'], password=config['password'])
    client.push(content, binding, uri=config['inbox_path'])

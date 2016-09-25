"""
Provides common functions for the CVE-Builder script.

The script provides functionality for both TAXII inboxing aswell as using
CERT-UK's custom adapter inbox.
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


def _certuk_inbox(endpoint_url, stix_package):
    """Inbox the package to the certuk adapter."""
    data = stix_package
    headers = _construct_headers()
    response = requests.post(endpoint_url, data=data, headers=headers)
    print(json.dumps(response.json(), indent=4))
    return


def _taxii_inbox(content, host, ssl, discovery, binding, user, password, inbox):
    client = create_client(host, use_https=ssl, discovery_path=discovery)
    content = content
    binding = binding
    client.set_auth(username=user, password=password)
    client.push(content, binding, uri=inbox)

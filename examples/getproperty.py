#!/usr/bin/env python3

"""
This example show how to connect to a SNS appliance, send a command
to get appliance properties and parse the result to extract the
appliance model and firmware version.
"""

import getpass

from stormshield.sns.sslclient import SNSError, SSLClient

# user input
host = input("Appliance ip address: ")
user = input("User:")
password = getpass.getpass("Password: ")

try:
    # the context manager disconnects even if a command raises
    with SSLClient(
        host=host, port=443,
        user=user, password=password,
        sslverifyhost=False,
    ) as client:

        # request appliance properties
        response = client.send_command("SYSTEM PROPERTY")

        if response:
            # get value using the get() shortcut, which accepts a default
            model = response.get(section='Result', token='Model')
            # get value with direct access to data
            version = response.data['Result']['Version']

            print("")
            print(f"Model: {model}")
            print(f"Firmware version: {version}")
        else:
            print(f"Command failed: {response.output}")

except SNSError as exception:
    raise SystemExit(f"Connection failed: {exception}") from exception

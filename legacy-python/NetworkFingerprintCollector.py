# Enhanced Computer and Network Fingerprint Collector
# This script gathers various system and network details from the machine
# it is executed on, creating a "fingerprint" of the system.
# The collected data is then displayed and saved to a CSV file.

import platform
import os
import socket
import datetime
import csv
import uuid


def getIPAddress():
    """Gets a primary local IP address.

    This function attempts to determine the machine's primary IP address
    by first trying to connect a UDP socket. If that fails, it falls
    back to resolving the machine's hostname.
    """
    socketHandle = None
    try:
        # This method finds the IP address used for an outbound connection.
        # A short timeout is used to prevent long waits if the network is unresponsive.
        socketHandle = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socketHandle.settimeout(0.1)
        # The IP address '10.255.255.255' does not need to be reachable;
        # this call helps the OS select an appropriate interface.
        socketHandle.connect(('10.255.255.255', 1))
        ipAddress = socketHandle.getsockname()[0]
    except Exception:
        try:
            # Fallback method: This may return a loopback address (e.g., '127.0.0.1').
            ipAddress = socket.gethostbyname(socket.gethostname())
        except Exception as e:
            return f'N/A: {e}'
    finally:
        if socketHandle:
            socketHandle.close()
    return ipAddress


def getMACAddress():
    """Gets a primary MAC address.

    This function uses the uuid.getnode() method to retrieve the MAC address
    and formats it as a standard colon-separated hexadecimal string.
    """
    try:
        macNum = uuid.getnode()
        mac = ':'.join(('%012X' % macNum)[i:i+2] for i in range(0, 12, 2))
        # The uuid.getnode() function may return an all-zero MAC if it fails to find one.
        if mac == '00:00:00:00:00:00':
            return 'N/A (uuid.getnode() returned null MAC)'
        return mac
    except Exception as e:
        return f'N/A: {e}'


def getProcessorModel():
    """Gets processor model information using the platform module."""
    model = platform.processor()
    return model if model else 'N/A'


def collectComputerFingerprint():
    """Collects basic system and network information about the local computer."""
    fingerprintData = {}
    fingerprintData['os'] = f'{platform.system()} {platform.release()} ({platform.version()})'
    fingerprintData['computer_name'] = platform.node()
    fingerprintData['processor_architecture'] = platform.machine()
    fingerprintData['processor_model'] = getProcessorModel()
    fingerprintData['ip_address'] = getIPAddress()
    fingerprintData['mac_address'] = getMACAddress()
    fingerprintData['system_time'] = datetime.datetime.now().isoformat()
    return fingerprintData


def saveToCSV(fingerprintData, filename='network_fingerprints.csv'):
    """Saves the fingerprint data to a CSV file.

    If the specified file exists, data is appended. Otherwise, a new file
    is created with a header row.
    """
    # Define the order of headers for the CSV file.
    # These keys must match those in the fingerprintData dictionary.
    fieldnames = [
        'computer_name', 'os', 'processor_architecture', 'processor_model',
        'ip_address', 'mac_address', 'system_time'
    ]

    # Determine the absolute path for the CSV file, placing it in the script's directory.
    scriptDir = os.path.dirname(os.path.abspath(__file__))
    absoluteFilename = os.path.join(scriptDir, filename)
    fileExists = os.path.isfile(absoluteFilename)

    try:
        with open(absoluteFilename, 'a', newline='', encoding='utf-8') as csvFile:
            writer = csv.DictWriter(csvFile, fieldnames=fieldnames)

            # If the file is new (did not exist before opening), write the header row.
            if not fileExists:
                writer.writeheader()

            # Write the collected fingerprint data as a new row.
            writer.writerow(fingerprintData)
        print(f'Fingerprint data appended to {absoluteFilename}')
    except IOError as e:
        print(f'Error: Could not write to CSV file {absoluteFilename}: {e}')


def displayFingerprint(fingerprint):
    """Displays the collected computer information in a formatted manner."""
    print(f"\n--- Computer Fingerprint: {fingerprint.get('computer_name', 'N/A')} ---")
    for key, value in fingerprint.items():
        # Format the key for display (e.g., 'computer_name' becomes 'Computer Name').
        displayKey = key.replace('_', ' ').title()
        if isinstance(value, list):
            # This handles list values, though not currently used by this script's main data.
            print(f'{displayKey}:')
            for item in value:
                print(f'  - {item}')
        else:
            print(f'{displayKey}: {value}')
    print('--------------------------')


if __name__ == '__main__':
    print('Collecting local machine fingerprint...')
    computerInfo = collectComputerFingerprint()
    displayFingerprint(computerInfo)
    saveToCSV(computerInfo)
    print('\nFingerprint collection and saving finished.')
import configparser

def read():
    """Reads the configuration."""

    # Get the config file
    config = configparser.ConfigParser()
    config.read('configuration.ini')

    if len(config) <= 1:
        print('Empty config file. Please fill configuration.ini')
        createEmptyConfig()
        raise ValueError('No configuration')

    return config

def createEmptyConfig():
    """Creates an empty config file"""

    config = configparser.ConfigParser()
    config['IPAM SERVER'] = {
        'ServerIpAddress': 'orion.mydomain.com',
        'username': 'svc_api',
        'password': ''
        }
    config['ACI APIC'] = {
        'url': 'https://apic01.mydomain.com',
        'username': 'admin',
        'password': ''
        }
    config['DEFAULT VALUES'] = {
        'YOUR_NAME': '',
        }
    with open('configuration.ini', 'w') as configfile:
        config.write(configfile)
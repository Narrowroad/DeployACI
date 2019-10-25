"""Provides programatic access to Solarwinds IPAM."""

# Requests allows for REST API queries, and JSON lets us open the password file
import requests

# Allows for checking IP addresses
import ipaddress as ip  
import read_config
import json
import logging
import urllib3
from orionsdk import SwisClient

# Constants used 
VERIFY = False
IPTYPE = (ip.IPv4Address, ip.IPv6Address)
NETTYPE = (ip.IPv4Network, ip.IPv6Network)


# Open the password file and import the settings
config = read_config.read()
npm_server = config['IPAM SERVER']['serveripaddress']
username = config['IPAM SERVER']['username']
password = config['IPAM SERVER']['password']
  
# Decide whether to ignore insecure connection warnings
if not VERIFY:
    # from requests.packages.urllib3.exceptions import InsecureRequestWarning
    # requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
swis = SwisClient(npm_server, username, password)
      
    
def verifyFreeAddresses(subnet: ip.ip_network, num: int) -> int:
    """Verify that the requested number of addresses are available in a given subnet in IPAM.
    
    Args:
        subnet (ipaddress.ip_network): The subnet to reserve IPs in
        num (int): The number of IPs to reserve
    
    Returns:
        int: The index of the subnet in the IPAM database
        bool: False if the subnet does not exist

    """
    # Check for free addresses in the subnet
    try: avail = getAvailableIP(subnet)
    except LookupError: return False
        
    # Check if there are enough IP's available
    if avail['AvailableCount'] < num:
        print('Subnet {x1} only has {x2} available IPs, less than the {x3} needed.'.format(
            x1 = subnet.exploded,
            x2 = avail['AvailableCount'],
            x3 = num
        ))
    else: print('  + Sufficient IPs are available: {} of {}'.format(
        avail['AvailableCount'],
        subnet.num_addresses
    ))
    return avail['SubnetID']


def getReservableIPs(subnet: ip.ip_network, num: int, blank_only=True):
    """Return a list containing the next 'num' number of free addresses.
    
    Args:
        subnet (ipaddress.ip_network): The subnet to reserve IPs in
        num (int): The number of IPs to reserve
    
    Optional Args:
        +
    
    Returns:
        list (of dicts): A list containing the next 'num' number of free addresses.
    
    Raises:
        ValueError: If the addresses could not be retrieved.

    """    
    # Error checking and get subnet ID
    sub_id = verifyFreeAddresses(subnet, num)
    if not sub_id:
        print('Error verifying free addresses')
        return False
    
    # Query the database for IP addresses                                      
    nodes = swis.query("SELECT TOP {x_num} URI, IPAddress, IPNodeID " \
                       "FROM IPAM.IPNode " \
                       "WHERE " \
                       "Description is Null AND " \
                       "SysName is Null AND " \
                       "Comments is Null AND " \
                       "Status = 2 AND " \
                       "SubnetId = {x_sub_id}".format(
                           x_num= num, 
                           x_sub_id= sub_id))
    
    # Check to see if any results were returned
    if len(nodes['results']) == 0:
        print('No valid IP addresses found when querying database.')
        return False
    
    return nodes['results']

    
def getAvailableIP(net: ip.ip_network) -> dict:
    """Get the number of available IP addresses in a subnet in IPAM.
    
    Args:
        net (ipaddress.ip_network): The subnet to look in
    
    Returns: 
        dict: A dict object containing:
            AvailableCount: The amount of available addresses
            SubnetID:
            Address: The network address
            CIDR: The CIDR of the subnet
    
    """
    #nodes = swis.query("SELECT Distinct IpNodeId, URI, IPAddress, Description, SysName, Status from IPAM.IPNode WHERE NOT Status = 1 AND IPAddress like '10.4%'")
    available = swis.query("SELECT Distinct AvailableCount, SubnetID, Address, CIDR FROM IPAM.Subnet WHERE Address = '{addr}' AND CIDR = {cidr}".format(
        addr = net.network_address,
        cidr = net.prefixlen
    ))['results']
    
    # Check whether IPAM had a match
    if len(available) == 0:
        raise LookupError('Subnet does not exist in IPAM')

    return available[0]



def getIPAttributes(id: int= None, ip: str= None) -> dict:
    """Retrieve attributes of an IP address from IPAM.
    
    Optional Args:
        id (int): The database ID of an IP address
        ip (string): An IP address

    Raises:
        ValueError: If entry does not exist

    Returns:
        bool: False if not successfully reserved
        dict: A dict containing the attributes of the IP entry
        
    """
    # Error Check
    if not (isinstance(id, int) or isinstance(ip, str)):
        raise ValueError('No valid IP or IPNodeID was supplied.')
    
    # Format None values to be more SQL-like
    if not id: id = 'Null'
    else: id = "'{}'".format(id)
        
    if not ip: ip = 'Null'
    else: ip = "'{}'".format(ip)        
    
    # Get the IP address
    q = swis.query("SELECT TOP 1 " \
               "IPNodeId, SubnetId, IPAddress, Comments, Status, SysName, SkipScan, Description, URI " \
               "FROM IPAM.IPNode "\
               "WHERE NOT IPNodeId is Null AND NOT IPAddress is Null AND (IPNodeID = {} OR IPAddress = {})".format(
                   id, ip))
    
    if len(q['results']) == 0: 
        raise ValueError("The given IP entry doesn't exist: {} | {}".format(id, ip))
    
    # Break out the dict from the response and return it
    return q['results'][0]


def getSubnetAttributes(id: int= None, net: ip.ip_network= None) -> dict:
    """Retrieve attributes of an IP address from IPAM.
    
    Args:
        id (int): The SubnetID of a subnet
        net (ip.ip_network): A subnet

    Raises:
        LookupError: If entry does not exist
        ValueError: If no entry was supplied

    Returns:
        bool: False if not successfully reserved
        dict: A dict containing the attributes of the IP entry
        
    """
    # Error Check
    if not (isinstance(id, int) or isinstance(net, NETTYPE)):
        raise ValueError('No valid Subnet or SubnetId was supplied.')
    
    query = None
    
    # Format the search queries
    if not id: 
        query = "(Address = '{}' AND CIDR = {})".format(
            net.network_address,
            net.prefixlen
        )
    else: query = "SubnetId = {}".format(id)
    
    # Get the subnet attributes
    q = swis.query("SELECT TOP 1 " \
               "SubnetId, Address, CIDR, Comments, VLAN, Location, Description, URI " \
               "FROM IPAM.Subnet "\
               "WHERE NOT Address is Null AND {}".format(query)
               )
    
    # Check if the subnet exists
    if len(q['results']) == 0: 
        raise LookupError("The given subnet doesn't exist: {} | {}".format(id, net))
    
    # Break out the dict from the response and return it
    return q['results'][0]

def isRealCIDR(cidr: int):
    """Checks to see if the given int is a valid CIDR value"""
    if  0<= cidr <=32:
        return True
    else:
        return False

def getIPNodeURI(entry):
    """Return the URI associated with the supplied IP entry.

    Args:
        entry (int): The database ID of an IP address
        entry (string): The uri of the node (this is NOT validated, just returned)
        entry (ip.IPv4Address): An IP address
    
    Raises:
        LookupError: If entry does not exist
        ValueError: If incorrect values were passed
    
    Returns:
        string: The URI associated with the supplied IP entry
    
    Example:
        uri = getIPNodeURI(ip.ip_address('10.46.1.1'))
    
    """
    # If the entry is already an URI (assumed from being a string), return itself.
    # No validation is done here.
    if isinstance(entry, str): return entry 
    
    # Get the URI of the IP address
    try:
        if isinstance(entry, int): i = getIPAttributes(id= entry)
        elif isinstance(entry, IPTYPE): i = getIPAttributes(ip= entry.exploded)
        else: raise ValueError('Entry not of valid type ({}).'.format(type(entry)))
                               
        if not i: raise LookupError('The request URI could not be found')
        return i['URI']
    except Exception as err:
        print('Error in getIPNodeURI:' , err)
        raise

def getSubnetURI(entry) -> str:
    """Return the URI associated with a supplied subnet.
    
    Args:
        entry (int): The database ID of a subnet
        entry (string): The uri of the subnet (this is NOT validated, just returned)
        entry (ip.ip_network): The subnet 
    
    Raises:
        LookupError: If entry does not exist
        ValueError: If incorrect values were passed
    
    Returns:
        string: The URI associated with the supplied subnet
    
    """
    # If the entry is already an URI (assumed from being a string), return itself.
    # No validation is done here.
    if isinstance(entry, str): return entry    
    
    # Get the URI of the subnet
    try:
        if isinstance(entry, int): i = getSubnetAttributes(id= entry)
        elif isinstance(entry, NETTYPE): i = getSubnetAttributes(net= entry)
        else: raise ValueError('Entry not of valid type ({}).'.format(type(entry)))
        
        if not i: raise LookupError('The request URI could not be found')

        return i['URI']
    except Exception as err:
        print('Error in getSubnetURI:' , err)
        raise

def reserveSubnet(subnet: ip.IPv4Network,
                  parentID: int = 0,
                  vlan: int = None,
                  comment: str = None,
                  location: str = None,
                  ):
    """Create a subnet in IPAM and place it underneath the appropriate parent subnet.

    TODO: This function only places subnets under 10.46, .47, and .48. Replace this
        functionality with proper automatic parent-finding.
    """
    # set up property bag for the new node
    props = {
        'VLAN': vlan,
        'Comments': comment,
        'Location': location,
    }   
    
    args = (str(subnet.network_address), str(subnet.prefixlen),)
    
    try: swis.invoke('IPAM.SubnetManagement', 'CreateSubnet', *args)
    except: return False

    a = swis.query("SELECT TOP 1 SubnetID FROM IPAM.Subnet WHERE "\
                   "Address = '{}' AND "\
                   "CIDR = {}".format(str(subnet.network_address),
                                      subnet.prefixlen)
                   )['results']
    if len(a) == 0: return False
    a = a[0]['SubnetID']
    
    # Super clunky to-be-replaced code for putting them in the correct subnet
    # These are the subnetIDs of the supernets
    supers = {
        46: 1548,
        47: 1621,
        48: 1620,
    }
    # Get the parent and uri of this subnet
    ParentId = supers.get(int(str(subnet.network_address).split('.')[1]), 0)
    uri = getSubnetURI(subnet)
    
    # Update the subnet info
    for d in props.items(): 
        try:
            # If the value of an attribute isn't None:
            if d[1]:
                swis.update(uri, **dict([d]))
                print('Updated "{}" to "{}"'.format(d[0], d[1]))
        except Exception as err:
            print('Error updating "{}" to "{}": {}'.format(d[0], d[1], err))

    # Put the subnet into it's appropriate supernet
    swis.update(uri, ParentId= ParentId)

    return True  

def updateSubnet(
                subnet: ip.IPv4Network,
                vlan: int = None,
                comment: str = None,
                location: str = None
                ):
    
    # set up property bag for the new node
    props = {
        'VLAN': vlan,
        'Comments': comment,
        'Location': location,
    }   

    """Update the attributes of a subnet in IPAM."""
    # Get the URI of the IP address
    try: uri = getSubnetURI(subnet)
    except Exception as err: 
        raise
   
    # Update the subnet info
    for d in props.items(): 
        try:
            # If the value of an attribute isn't None:
            if d[1]:
                swis.update(uri, **dict([d]))
                print('Updated "{}" to "{}"'.format(d[0], d[1]))
        except Exception as err:
            print('Error updating "{}" to "{}": {}'.format(d[0], d[1], err))

    return True

def updateIP(entry, **kwargs):
    """Update the attributes of an IP address in IPAM.
    
    Args:
        entry (int): The database ID of an IP address
        entry (string): The uri of the node
        entry (ip.IPv4Address): An IP address
    
    Keyword Args:
    Any key/value pair that is present in the IPAM schema. These are 
    used to update the IP entry. i.e.:
        status (int): New status for the entry
        sysname (string): Hostname
        skipscan (bool): Skip scanning of entry
        comments [string]
        description [string]

    Returns:
        bool: True if successfully reserved
        
    Example:
    updateIP(ip.ip_address('10.46.69.2'), 
         skipscan=True,
         alias='NLAE403PRIMA01', 
         sysname='Gateway', 
         comments='Gateway',
         ))
    
    """
    # Get the URI of the IP address
    try: uri = getIPNodeURI(entry)
    except Exception as err: 
        raise
   
    # Update the IP
    for d in kwargs.items(): 
        try:
            swis.update(uri, **dict([d]))
            print('Updated "{}" to "{}"'.format(d[0], d[1]))
        except Exception as err:
            print('Error updating "{}" to "{}": {}'.format(d[0], d[1], err))
           
    return True

def getNextAvailableSubnet(supernet: ip.IPv4Network, size: int, numSubnets: int = 1):
    """Retrieves the next available subnet of a particular size within a given supernet.
    
    Keyword Args:
        supernet (ip.IPv4Network): The address of the supernet
        size (int): The CIDR size of the new network
        numSubnets (int): The number of subnets to find

    Raises:
        LookupError: If the supernet doesn't exist
        LookupError: If no valid subnet exists
        ValueError: If an incorrect size or numSubnets was supplied

    Returns:
        List: A list of IPv4Network objects representing the next free subnets
    """
    
    if numSubnets <= 0:
        raise ValueError('An unusable number of networks was supplied ({})'.format(numSubnets))

    if size <= supernet.prefixlen:
        raise ValueError('A new network CIDR was supplied that is larger than the parent CIDR')

    # Make sure the supernet exists and get its internal ID number
    try:
        supernetID = getSubnetAttributes(net=supernet)
    except LookupError as err:
        # The supernet doesn't exist
        print(err)
        raise

    def getNextNetwork(addrs):
        newNet = None
        # Iterate over the list of possible subnets and check if each one has been used yet.
        for net in supernet.subnets(new_prefix=size):
            if not net.network_address in supernetAddresses: 
                # We found a potential candidate, now check if it really is fully available
                validatedAddr = True
                for addr in net:
                    addr = addr.compressed
                    # print('{} in supernetAddresses: {}'.format(addr, addr in supernetAddresses))
                    if addr in supernetAddresses: # Check all addresses to see if they are used
                        validatedAddr = False
                        break
                if validatedAddr: # A valid address was found
                    # print('A valid address was found')
                    newNet = net
                    break
        
        # Error out if nothing was found
        if not newNet: raise LookupError('No valid subnet was found')
        
        # print('Subnet Found: ' + newNet.exploded)
        
        return newNet
    
    # This query gets a list of all IP addresses within the supernet
    # For performance reasons, please don't try this on something bigger
    # than a /16 :)
    supernetAddresses = swis.query(
        "SELECT IPAddress "\
        "FROM IPAM.IPNode "\
        "WHERE "\
        "   IPAddressN >= '{}' AND "\
        "   IPAddressN <= '{}' ".format(
            IPtoGUID(supernet.network_address),
            IPtoGUID(supernet.broadcast_address),
            )
        )['results']
    supernetAddresses = [i['IPAddress'] for i in supernetAddresses]

    results = []

    # Find the next available networks
    for x in range(numSubnets):
        nextNet = getNextNetwork(supernetAddresses)
        # Mark the found network as used in our result set
        supernetAddresses.append(nextNet.network_address.compressed) 
        print('Got ' + nextNet.exploded)
        results.append(nextNet)
        
    return results

def subnetAvailable(net: ip.ip_network) -> bool:
    """Check whether a given subnet is empty and available.
    
    It works by searching for all the IP addresses in the given subnet and 
    finding if any are allocated.
    
    Args:
        net (ip.ip_network): A subnet  

    Returns:
        bool: False if the subnet is NOT empty and available
            for allocation.
    
    """
    # Check all IP addresses within the new subnet to see if any of the IPs
    # already have a SubnetID assigned to them
    a = swis.query("SELECT TOP 1 SubnetID, IPAddress FROM IPAM.IPNode WHERE "\
                   "(NOT SubnetID is Null) AND "\
                   "IPAddressN >= '{}' AND "\
                   "IPAddressN <= '{}'".format(
                       IPtoGUID(net.network_address),
                       IPtoGUID(net.broadcast_address)
                   )
                   )['results']
    
    # If any IP addresses were returned, that means some part of the subnet
    # is unavailable for allocation. If no IP's in the given range have a 
    # SubnetID, then the entire subnet is available.
    if len(a) == 0: return True
    else: return False

def IPtoGUID(ip: ip.IPv4Address) -> str:
    """Convert an IPv4 address to a Solarwinds-style GUID as used in IPAddressN."""
    ip = ip.exploded.split('.')
    return '{:02X}{:02X}{:02X}{:02X}-0000-0000-0000-000000000000'.format(*map(
        int, list(reversed(ip)))).lower()

#getNextAvailableSubnet(ip.IPv4Network('10.46.0.0/16'), 20, 20)
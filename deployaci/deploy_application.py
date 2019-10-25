"""
A tool to rapidly deploy new applications in the NL Equinix ACI environment.

1. Validate that the deployment will be successful (no pre-existing EPGs, 
    subnets, reservations, etc)
2. Create subnets and reserve IP's in IPAM
3. Create the EPGs in ACI and add the appropriate settings and contracts
4. Label everything with change numbers and requestor names

TODO: Create command-line interface so users can run this without having to
    create code at the end of the script.
"""

from pyaci import Node, options, filters
from pyaci.errors import MetaError
from Scripts import rmetagen

import swipam as ipam
import json
import ipaddress as ip
import logging
import time
import os
import datetime
import time
import read_config

IPTYPE = (ip.IPv4Address, ip.IPv6Address)
NETTYPE = (ip.IPv4Network, ip.IPv6Network)
CONSOLE_LOGGING = logging.DEBUG


def requestIPNum():
    """Ask the user how many IPs to reserve."""
    # Get the number of IP's to reserve and cast it as an int
    while True:
        try:
            return int(input("Number of IP's to reserve: "))
        except:
            print('Invalid input')
                  
def requestIPSubnet(num):
    """Ask the user which subnet to add IP's to.
    
    Arguments:
    -num [int]: The number of IP's requested
    
    Returns an ipaddress.ip_network object
    """
    while True:
        try:
            new_subnet = ip.ip_network(input("Subnet: "))                   
            
        except Exception as inst:
            print('Invalid input. Subnet should be given as X.X.X.X/YY')
            print('Error: ' + str(inst))
            
        else:
                       
            # Check if the subnet is big enough
            if (new_subnet.num_addresses-2) < num: 
                print('Invalid input. {} ({} usable IPs) does not contain {} IPs to reserve.'.format(
                    new_subnet.exploded, new_subnet.num_addresses, num))
                continue
            
            return new_subnet    

def backupCurrentConfig(name: str = None):
    """Backs up the current configuration of the APIC to roll-back if needed"""

    # Log in to the APIC and reference the fabric
    apic = aciLogIn()
    fb = apic.mit.polUni().fabricInst().configExportP('defaultOneTime')
    fb.GET()

    # Break out of the program if there is already a backup job underway, since we
    # would want to wait for it to finish
    if not fb.adminSt == 'untriggered':
        log.critical('An ACI backup job is already running.')
        raise RuntimeError ('An ACI backup job is already running.')
    
    # Set the backup description
    st = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
    if not name: 
        backupName= 'deploy_application automated backup at {}'.format(st)
    else:
        backupName= 'Automated backup for app {} at {}'.format(name, st)

    bk = apic.mit.polUni().fabricInst().configExportP('defaultOneTime')
    bk.descr = backupName
    
    # Start the backup
    bk.adminSt = 'triggered'
    bk.POST()
    log.info('Backed up current config to backup named "{}"'.format(backupName))

def requestUserInput():
    """Provide an interactive menu to let users reserve IP addresses."""
    #print('Request an IP from {}'.format(npm_server))
    
    # Ask the user for the number of IPs to reserve
    num = requestIPNum()
    
    # Ask the user for the subnet to reserve IPs in
    subnet = requestIPSubnet(num)
           
    # Get the next free IP addresses
    results = ipam.getReservableIPs(subnet, num)
    if not results: return False
    
    print('Results Found:')
    
    # Print the first 5 results
    i = 0
    for n in results:
        print(n['IPAddress'])
        i+= 1
        if i == 5:
            cnt = input('Additional Results not shown. Show all? [y / N]: ')
            if cnt.lower() == 'y': continue
            break

def aciLogIn(apic = None):
    """Log in to ACI."""
    
    # Get the credentials
    config = read_config.read()

    # If an existing session wasn't supplied, make a new session
    if not isinstance(apic, Node):
        try: 
            apic = Node(config['ACI APIC']['url'])
        except MetaError as err:
            # This implies that the meta hasn't been downloaded yet
            raise Exception("The ACI Meta information hasn't been "\
                "downloaded from the controller. To fix this, run:"\
                "\nrmetagen.py -u admin 10.43.40.11") from err
        
    log.info('APIC Login: {}'.format(apic.methods.Login(config['ACI APIC']['username'], 
                                                        config['ACI APIC']['password']
                                                        ).POST()))
    return apic
    
def createNewSBMApplication(name: str, 
                            prod_client_subnet: ip.ip_network,
                            **kwargs) -> bool:
    """Deploy a new application into the NL Equinix ACI environment.
    
    This function will do the following:
        - Select appropriate subnet ranges from IPAM if none were specified
        - Generate a list of subnets to create
        - Validate that they are available in IPAM
        - Validate that they are available in ACI
        - Reserve them in IPAM
        - Make a backup of ACI
        - Create an Application Profile
        - Create EPGs
        - Assign subnets to each EPG
        - Create a provided contract which every EPG provides
        - Consume the Shared Services and l3Out contracts
        - Assign VMM domain to each EPG
        
        Future Considerations:
        10. Create firewall rules explicitly permitting traffic to EPGs
        
    Args:
        name (str): The name of the application
        autoIP (bool): If true, automatically generate IPs from IPAm
        prod_client_subnet (ip.ip_network): The subnet that will be 
            assigned to the production client EPG (or other first EPG 
            if client is not used). The other subnets will be 
            extrapolated from this one. Ignored if using autoIP.
        reserve_in_ipam (bool, optional): If True, reserves the address in IPAM
        create_in_aci (bool, optional): If True, create the EPGs in ACI
        create_uat (bool, optional): If True, creates a staging environment
        create_dev (bool, optional): If True, creates a development environment
        change_num (str, optional): A change number which will be added to descriptors
        requestor (str, optional): The name of the person who requested the change
        author (str, optional): The name of the person who requested the change
        subnet_size (int, optional): The CIDR of the subnets to be created
        tenant (str, optional): The tenant to create the EPG in
        
        # Set false to omit the creation of an EPG
        prod_client (bool, optional): 
        prod_web (bool, optional): 
        prod_app (bool, optional): 
        prod_db (bool, optional): 
        uat_client (bool, optional): 
        uat_web (bool, optional): 
        uat_app (bool, optional): 
        uat_db (bool, optional): 
        dev_client (bool, optional): 
        dev_web (bool, optional): 
        dev_app (bool, optional): 
        dev_db (bool, optional): 
        
    Returns:
        bool: True if the application was deployed

    """
    reserve_in_ipam = kwargs.get('reserve_in_ipam', True)
    create_in_aci = kwargs.get('create_in_aci', True)
    tenant = kwargs.get('tenant', 'lab')
    
    # Generate the comment string for this change
    kwargs['comment'] = makeComment(**kwargs)
    print(kwargs['comment'])
    
    # Generate a list of subnets to create and validate them
    if kwargs.get('autoIP', True):
        subnets= generateNextAvailableSubnets(name, **kwargs)
    else:
        subnets= generateSubnetsFromSeed(name, prod_client_subnet, **kwargs)
       
    # Check ACI for the existance of the Subnets or EPGs
    if not checkACI(name= name, subnets= subnets, tenant= tenant, append=kwargs.get('append', True)): return False
    
    # Create a backup of ACI before making changes
    backupCurrentConfig(name)
    
    # Reserve the subnet in IPAM
    if reserve_in_ipam: reserveSubnetInIPAM(name, subnets, **kwargs)

    # Create ACI infrastructure
    if create_in_aci: createApp(name= name, subnets= subnets, **kwargs)
    
    # Report Results
    print('\n\nResults:')
    for net in subnets:
        print(net['name'])
        print(' - Subnet:', net['subnet'])
        print(' - Mask:', net['subnet'].netmask)
        print(' - Gateway:', net['subnet'][1])
        print(' - Usable addresses range:', net['subnet'].network_address+2, 'to', net['subnet'].broadcast_address-1)
        print(' - Usable addresses:', net['subnet'].num_addresses-3)
        print('')
    
def makeComment(**kwargs):
    """Make a comment string for this change."""
    author = kwargs.get('author')
    change_num = kwargs.get('change_num')
    requestor = kwargs.get ('requestor')
    
    comment = ' -  '
    if change_num: comment += 'Chg: #{} '.format(change_num)
    if author: comment += 'By: {} '.format(author)
    if requestor: comment += 'For: {}'.format(requestor)  
    return comment

def findBD(name) -> str:
    """Generate the name for a BD from the supplied EPG name."""
    x = name.lower().split('_')
    return '-'.join(x[-2:])

def createApp(name: str, subnets: list, **kwargs):
    """Deploy the application into ACI."""
    tenant = kwargs.get('tenant', 'lab')
    comment = kwargs.get('comment', '')
    append = kwargs.get('appendToAp', False)
    
    apic = aciLogIn()

    # Create the tenant if needed
    tn = apic.mit.polUni().fvTenant(tenant)
    tn.POST()

    # Create the Application Profile 
    app = tn.fvAp(name)
    app.descr = comment
    app.POST()

    # Create the master "permit-all" contract
    cnt = (tn.vzBrCP('cnt_' + name + '_permit_all_communication'))
    cnt.vzSubj('ip_any').vzRsSubjFiltAtt('allow_all')
    cnt.scope="tenant"
    cnt.POST()    
    
    # Create the AP Contract Master epg and associate the 
    master = app.fvAEPg(name.lower() + '_contract_master')
    master.descr = comment
    master.fvRsProv(cnt.name) # Provide the all-epg permit contract

    ###############################################################
    # Standard consumed contracts for all EPGs
    # Consumed contracts added here will apply to all EPGs in this
    # Application Profile, thereby giving all EPGs access to those
    # resources. 
    ###############################################################
    master.fvRsCons('cnt_l3_transit_rbsh_ftd') # Transit out of ACI
    master.fvRsCons('cnt_shared_services') # Shared Services
    ###############################################################
    
    master.POST()
    
    def _assignCnt(tn, c_name):
        """Create (or reference) inter-epg contracts."""
        cnt = tn.vzBrCP('cnt_' + c_name)
        cnt.scope="application-profile"
        cnt.vzSubj('ip_any').vzRsSubjFiltAtt('allow_all')
        return cnt

    prevRole=None
    prevSeg=None
    prevEPG=None
    for net in subnets:
        # Create the EPGs
        epg = app.fvAEPg(net['name'])
        fvnet = epg.fvSubnet('{}/{}'.format(str(net['subnet'][1]), net['subnet'].prefixlen))
        fvnet.scope="public"
        epg.fvRsDomAtt('uni/phys-phys')
        epg.fvRsDomAtt('uni/vmmp-VMware/dom-NLAEDVS01')
        epg.descr = comment
        epg.fvRsSecInherited(master.Dn)
        epg.fvRsBd().tnFvBDName= findBD(net['name'])
        
        # Check to see if we are starting a new role; if so,
        # reset the 'prev' variables so we dont create extra
        # contracts between environments
        if prevRole != net['role']: 
            prevRole= None
            prevEPG= None
            prevSeg= None

        # Create contracts between EPGs in the same role (prod, dev, uat) by 
        # creating (or selecting a pre-existing) contract with the name of the 
        # last segment and the current one. This makes it so that we always 
        # have contracts from client > web > app > db, but also so that if
        # an app skips a segment, the contracts will still work (i.e:
        # it will make client > app if those are the only EPGs)
        #
        # The contract is always the same type (eg, cnt_uatclient_to_uatweb) rather
        # than a unique contract for each EPG so that ACI doesn't get flooded by
        # contracts. They are scoped to the application profile so that it doesn't get
        # too permissive.
        if prevRole: 
            cnt = _assignCnt(tn, '{}_to_{}'.format(prevRole+prevSeg, net['role']+net['seg']))
            prevEPG.fvRsProv(cnt.name)
            epg.fvRsCons(cnt.name) 
            log.debug('Assigned cnt_{}_to_{} to {} (prov) and {} (cons)'.format(
                prevRole+prevSeg, net['role']+net['seg'], prevEPG.Dn, epg.Dn))
        prevRole = net['role']
        prevSeg = net['seg']
        prevEPG = epg

        # Create contracts for Database servers
        if (net['seg'] == 'db' or 
            net['seg'] == 'app'): 
            epg.fvRsConsIf('cnt_storage_cifs-export')

        # Create contracts for Client servers
        if net['seg'] == 'client': epg.fvRsCons('cnt_citrix_infra_srv')

    tn.POST()
        
def reserveSubnetInIPAM(name: str,
                        subnets: dict,
                        **kwargs,
                        ) -> bool:
    """Check ACI to ensure that the subnets and EPGs do not yet exist.
    
    Args:
        name (str): The name of the application
        subnets (dict): Each dict entry (i.e. prod or dev) contains a list of IPv4 Networks
        
    Returns:
        bool: False if there is an error preventing the creation of the subnets or EPGs

    """
    for net in subnets:
        # Make the subnet
        ipam.reserveSubnet(subnet= net['subnet'], 
                           comment= '{} {}'.format(net['name'], kwargs.get('comment', '')))
        
        # Reserve the gateway address
        ipam.updateIP(net['subnet'][1], status= 1, comments= 'Gateway', sysname= 'ACI Network')
    
def checkACI(name: str,
             subnets: list,
             tenant: str,
             apic: Node = None,
             append: bool = False,
             ) -> bool:
    """Check ACI to ensure that the subnets and EPGs do not yet exist.
    
    Args:
        name (str): The name of the application
        subnets (list): Each list entry contains a dict 
        tenant (str): The tenant to perform the operation in
        
    Returns:
        bool: False if there is an error preventing the creation of the subnets or EPGs

    """
    # Log in to ACI
    apic = aciLogIn(apic)
    # sbm = apic.mit.polUni().fvTenant(tenant)

    # Get all the subnets in the tenant to make sure the new ones don't exist
    for subnet in apic.mit.polUni().fvTenant(tenant).GET(**options.subtreeClass('fvSubnet')):
        
        # Subnets is a list of dicts of IPv4 networks. Iterate through all of them and check if they
        # already exist or overlap/are contained within existing networks.
        for net in (n['subnet'] for n in subnets):
            if net.overlaps(ip.ip_network(subnet.ip, False)): 
                log.error('Subnet {} overlaps with existing subnet {} found in tenant {}'.format(net, subnet.ip, tenant))
                return False
        log.debug('Existing subnet {} does not overlap subnets to be created.'.format(subnet.ip))
    
    if not append:
        # Check if the EPG already exists        
        for epg in apic.mit.polUni().fvTenant(tenant).GET(**options.subtreeClass('fvAEPg')):
            if (name.lower() == epg.name.lower() or 
                name.lower() in epg.name.lower().split('_')
            ):
                log.error('EPG {} contains the name "{}"'.format(epg.Dn, name))
                return False
            else: log.debug('EPG {} does not contain the name "{}"'.format(epg.Dn, name))
        log.info('Confirmed: No duplicate EPGs will be created.')
    
    return True

def startLogging() -> logging.Logger:
    """Set up the logger."""
    # Set up logging
    logging.raiseExceptions = True
    logging.lastResort = None
    
    timestr = time.strftime("%Y%m%d-%H%M%S")
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)

    # Set up handlers for console and file logging
    ch = logging.StreamHandler()
    ch.setLevel(CONSOLE_LOGGING)
    
    # Make the directories for the file handler
    log_dir = os.path.join(os.path.normpath(os.getcwd()), 'logs')
    log_fname = os.path.join(log_dir, 'app_create_{}.log'.format(timestr))   
    
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)    
    
    fh = logging.FileHandler(filename=log_fname)
    fh.setLevel(logging.DEBUG)
    
    # add formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    
    # add handlers to logger
    log.addHandler(ch)
    log.addHandler(fh)
    
    log.debug('Logger started')
    return log

def make_ip_network(ip: str) -> ip.ipv4network:
    '''Returns an IP network object from the supplied string'''
    # If the supplied ip is already a network, just return it
    if isinstance(ip, NETTYPE): 
        return ip

    return ip.ip_network(ip)


def generateNextAvailableSubnets(name, **kwargs) -> list:
    """
    Generates a list of dicts of subnets by iterating through the next
    available subnets in IPAM.

    """
    subnet_size  = kwargs.get('subnet_size', 28)
    prod_client  = kwargs.get('prod_client', True)
    prod_web  = kwargs.get('prod_web', True)
    prod_app  = kwargs.get('prod_app', True)
    prod_db  = kwargs.get('prod_db', True)
    uat_client  = kwargs.get('uat_client', True)
    uat_web  = kwargs.get('uat_web', True)
    uat_app  = kwargs.get('uat_app', True)
    uat_db  = kwargs.get('uat_db', True)
    dev_client  = kwargs.get('dev_client', True)
    dev_web  = kwargs.get('dev_web', True)
    dev_app  = kwargs.get('dev_app', True)
    dev_db  = kwargs.get('dev_db', True)

    # Get the supernets
    prod_supernet = make_ip_network(kwargs.get('prod_supernet', '10.46.0.0/16'))
    uat_supernet = make_ip_network(kwargs.get('uat_supernet', '10.47.0.0/16'))
    dev_supernet = make_ip_network(kwargs.get('dev_supernet', '10.48.0.0/16'))  
    
    results = []
       
    def appendNet(name, net, role, seg):
        # Turn the supplied subnet info into a dict of attributes we will
        # later iterate over and create in ACI and IPAM 
        return {'subnet': net,
                'name': '{}_{}_{}'.format(name.lower(), role, seg),
                'role': role,
                'seg': seg,
                }       
    
    # Get the prod subnets
    sum_prod = 0
    if prod_client: sum_prod +=1
    if prod_web: sum_prod +=1
    if prod_app: sum_prod +=1
    if prod_db: sum_prod +=1        
    
    if sum_prod > 0:
        nets = ipam.getNextAvailableSubnet(ip.IPv4Network('10.46.0.0/16'),  
                                            subnet_size,
                                            sum_prod
                                            )
        log.debug('Found {} prod subnets: {}'.format(sum_prod, nets))
        if prod_client: results.append(appendNet(name, nets.pop(0), 'prod', 'client'))
        if prod_web: results.append(appendNet(name, nets.pop(0), 'prod', 'web'))
        if prod_app: results.append(appendNet(name, nets.pop(0), 'prod', 'app'))
        if prod_db: results.append(appendNet(name, nets.pop(0), 'prod', 'db'))  

    # Get the uat subnets
    sum_uat = 0
    if uat_client: sum_uat +=1
    if uat_web: sum_uat +=1
    if uat_app: sum_uat +=1
    if uat_db: sum_uat +=1        

    if sum_uat > 0:
        nets = ipam.getNextAvailableSubnet(ip.IPv4Network('10.47.0.0/16'),  
                                            subnet_size,
                                            sum_uat
                                            )
        log.debug('Found {} uat subnets: {}'.format(sum_uat, nets))
        if uat_client: results.append(appendNet(name, nets.pop(0), 'uat', 'client'))
        if uat_web: results.append(appendNet(name, nets.pop(0), 'uat', 'web'))
        if uat_app: results.append(appendNet(name, nets.pop(0), 'uat', 'app'))
        if uat_db: results.append(appendNet(name, nets.pop(0), 'uat', 'db'))  

    # Get the dev subnets
    sum_dev = 0
    if dev_client: sum_dev +=1
    if dev_web: sum_dev +=1
    if dev_app: sum_dev +=1
    if dev_db: sum_dev +=1        

    if sum_dev > 0:
        nets = ipam.getNextAvailableSubnet(ip.IPv4Network('10.48.0.0/16'),  
                                            subnet_size,
                                            sum_dev
                                            )         
        log.debug('Found {} dev subnets: {}'.format(sum_dev, nets))
        if dev_client: results.append(appendNet(name, nets.pop(0), 'dev', 'client'))
        if dev_web: results.append(appendNet(name, nets.pop(0), 'dev', 'web'))
        if dev_app: results.append(appendNet(name, nets.pop(0), 'dev', 'app'))
        if dev_db: results.append(appendNet(name, nets.pop(0), 'dev', 'db'))      
        
           
    # Check if any of the subnets are in use in IPAM. Iterate through each subnet in results
    for net in (x['subnet'] for x in results):
        if not ipam.subnetAvailable(net): 
            log.critical('Subnet {} already exists. Exiting.'.format(net))
            raise ValueError('Subnet {} already exists.'.format(net))
        
        else: log.debug('Subnet {} does not exist.'.format(net))
    
    log.info('Found subnets: ' + str([str(r['subnet']) for r in results]))
    return results    
    
def generateSubnetsFromSeed(name, prod_client_subnet, **kwargs) -> list:
    """Generate a list of dicts of subnets from a seed subnet."""
    # Get the variables from args
    subnet_size  = kwargs.get('subnet_size', 28)
    prod_client  = kwargs.get('prod_client', True)
    prod_web  = kwargs.get('prod_web', True)
    prod_app  = kwargs.get('prod_app', True)
    prod_db  = kwargs.get('prod_db', True)
    uat_client  = kwargs.get('uat_client', True)
    uat_web  = kwargs.get('uat_web', True)
    uat_app  = kwargs.get('uat_app', True)
    uat_db  = kwargs.get('uat_db', True)
    dev_client  = kwargs.get('dev_client', True)
    dev_web  = kwargs.get('dev_web', True)
    dev_app  = kwargs.get('dev_app', True)
    dev_db  = kwargs.get('dev_db', True)     
    
    results = []
    
    # Split the seed IP into four parts
    i = str(prod_client_subnet.network_address).split('.')    
    
    
    def appendNet(name, net, role, seg):
        return {'subnet': net,
                'name': '{}_{}_{}'.format(name.lower(), role, seg),
                'role': role,
                'seg': seg,
                }       
    
    # Get the prod subnets
    sum_prod = 0
    if prod_client: sum_prod +=1
    if prod_web: sum_prod +=1
    if prod_app: sum_prod +=1
    if prod_db: sum_prod +=1        

    if sum_prod > 0:
        # Find the supernet of the given seed network
        t_net = ip.ip_network('10.46.{}.{}/{}'.format(i[2], i[3], subnet_size))
        s = list(t_net.supernet(new_prefix=24).subnets(new_prefix=subnet_size))
        
        # Start at the seed subnet, then get the next three after it
        nets = s[s.index(t_net):][:sum_prod]  
        log.debug('Found {} prod subnets: {}'.format(sum_prod, nets))
        
        if prod_client: results.append(appendNet(name, nets.pop(0), 'prod', 'client'))
        if prod_web: results.append(appendNet(name, nets.pop(0), 'prod', 'web'))
        if prod_app: results.append(appendNet(name, nets.pop(0), 'prod', 'app'))
        if prod_db: results.append(appendNet(name, nets.pop(0), 'prod', 'db'))      

    # Get the uat subnets
    sum_uat = 0
    if uat_client: sum_uat +=1
    if uat_web: sum_uat +=1
    if uat_app: sum_uat +=1
    if uat_db: sum_uat +=1        

    if sum_uat > 0:
        # Find the supernet of the given seed network
        t_net = ip.ip_network('10.47.{}.{}/{}'.format(i[2], i[3], subnet_size))
        s = list(t_net.supernet(new_prefix=24).subnets(new_prefix=subnet_size))
        
        # Start at the seed subnet, then get the next three after it
        nets = s[s.index(t_net):][:sum_uat]  
        log.debug('Found {} uat subnets: {}'.format(sum_uat, nets))
        
        if uat_client: results.append(appendNet(name, nets.pop(0), 'uat', 'client'))
        if uat_web: results.append(appendNet(name, nets.pop(0), 'uat', 'web'))
        if uat_app: results.append(appendNet(name, nets.pop(0), 'uat', 'app'))
        if uat_db: results.append(appendNet(name, nets.pop(0), 'uat', 'db'))      
        
    # Get the dev subnets
    sum_dev = 0
    if dev_client: sum_dev +=1
    if dev_web: sum_dev +=1
    if dev_app: sum_dev +=1
    if dev_db: sum_dev +=1        

    if sum_dev > 0:
        # Find the supernet of the given seed network
        t_net = ip.ip_network('10.48.{}.{}/{}'.format(i[2], i[3], subnet_size))
        s = list(t_net.supernet(new_prefix=24).subnets(new_prefix=subnet_size))
        
        # Start at the seed subnet, then get the next three after it
        nets = s[s.index(t_net):][:sum_dev]  
        log.debug('Found {} dev subnets: {}'.format(sum_dev, nets))
        
        if dev_client: results.append(appendNet(name, nets.pop(0), 'dev', 'client'))
        if dev_web: results.append(appendNet(name, nets.pop(0), 'dev', 'web'))
        if dev_app: results.append(appendNet(name, nets.pop(0), 'dev', 'app'))
        if dev_db: results.append(appendNet(name, nets.pop(0), 'dev', 'db'))      
        
           
    # Check if any of the subnets are in use in IPAM. Iterate through each subnet in results
    for net in (x['subnet'] for x in results):
        if not ipam.subnetAvailable(net): 
            log.critical('Subnet {} already exists. Exiting.'.format(net))
            raise ValueError('Subnet {} already exists.'.format(net))
        
        else: log.debug('Subnet {} does not exist.'.format(net))
    
    log.info('Found subnets: ' + str([str(r['subnet']) for r in results]))
    return results


# Execute the program    
log = startLogging()

# createNewSBMApplication(name= 'Mastersaf', 
#                         prod_client_subnet= ip.ip_network('10.46.15.0/28'),
#                         subnet_size  = 28,
#                         prod_db  = False,
#                         uat_db  = False,
#                         dev_db  = False,
#                         tenant = 'sbm',
#                         comment = 'Change CHG0031868 for Igor',
#                         reserve_in_ipam = True,
#                         autoIP = False,
#                         create_in_aci= True,
#                         )
                        
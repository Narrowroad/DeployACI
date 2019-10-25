from pyforms.basewidget import BaseWidget
from pyforms.controls   import ControlText
from pyforms.controls   import ControlButton
from pyforms.controls   import ControlCheckBox
from pyforms.controls   import ControlCombo

from deploy_application import createNewSBMApplication

from ipaddress import ip_network, AddressValueError
import traceback
import read_config

class ApplicationDeployer(BaseWidget):

    def __init__(self, *args, **kwargs):
        print('Loading GUI')
        super().__init__('SBM Application Deployment')

        config = read_config.read()

        #Definition of the forms fields
        self._txt_name    = ControlText('Application Name (No Spaces)')
        self._auto_ip = ControlCheckBox('Automatically select IPs', default=True)
        self._txt_ip    = ControlText('First Prod Subnet (for Seeded IP generation) (X.X.X.X/Y)')
        self._txt_ip.enabled = False
        self._subnet_size = ControlText('Subnet Size (CIDR)', default='28')
        self._author    = ControlText('Change Implementer', default=config['DEFAULT VALUES']['Your_name'])
        self._requestor    = ControlText('Change Requestor')
        self._change    = ControlText('Change Number')
        self._reserve_in_ipam = ControlCheckBox('Reserve in IPAM', default=True)
        self._append = ControlCheckBox('Append to Existing Service (Overwrite Possible)', default=False)
        self._cc_env = ControlCombo('Environment')
        self._cc_env.add_item('DeployACI Lab (Dev)', 'deployaci_lab')
        # TODO: Populate this from ACUAL tenants
        self._cc_env.add_item('SBM (Production)', 'sbm')

        self._ck_prod_client = ControlCheckBox('prod_client', default=True)
        self._ck_prod_web = ControlCheckBox('prod_web', default=True)
        self._ck_prod_app = ControlCheckBox('prod_app', default=True)
        self._ck_prod_db = ControlCheckBox('prod_db', default=True)
        self._ck_uat_client = ControlCheckBox('uat_client', default=True)
        self._ck_uat_web = ControlCheckBox('uat_web', default=True)
        self._ck_uat_app = ControlCheckBox('uat_app', default=True)
        self._ck_uat_db = ControlCheckBox('uat_db', default=True)
        self._ck_dev_client = ControlCheckBox('dev_client', default=True)
        self._ck_dev_web = ControlCheckBox('dev_web', default=True)
        self._ck_dev_app = ControlCheckBox('dev_app', default=True)
        self._ck_dev_db = ControlCheckBox('dev_db', default=True)
        self._runbutton     = ControlButton('Deploy')

        self._txt_ip.key_pressed_event = self._runReady
        self._txt_name.key_pressed_event = self._runReady
        self._subnet_size.key_pressed_event = self._runReady
        self._auto_ip.changed_event = self._auto_ip_press


        #Define the event that will be called when the run button is processed
        self._runbutton.value       = self.__runEvent
        self._runbutton.enabled     = False
        #self._cc_env.value          = self.__envEvent

        #Define the organization of the Form Controls
        # self._formset = [
        #     ('_text'),
        #     ('_ck_prod_client'),
        #     ('_ck_prod_web'),
        #     ('_ck_prod_app'),
        #     ('_ck_prod_db'),
        #     ('_ck_uat_client'),
        #     ('_ck_uat_web'),
        #     ('_ck_uat_app'),
        #     ('_ck_uat_db'),
        #     ('_ck_dev_client'),
        #     ('_ck_dev_web'),
        #     ('_ck_dev_app'),
        #     ('_ck_dev_db'),
        #     ('_runbutton'),
        # ]

        self._formset = [
            ('_txt_name'),
            ('_auto_ip'),
            ('_txt_ip'),
            ('_subnet_size'),
            ('_author'),
            ('_requestor'),
            ('_change'),
            ('_reserve_in_ipam', '_append'),
            ('_cc_env'),
            ('_ck_prod_client', '_ck_uat_client', '_ck_dev_client'),
            ('_ck_prod_web', '_ck_uat_web', '_ck_dev_web'),
            ('_ck_prod_app', '_ck_uat_app', '_ck_dev_app'),
            ('_ck_prod_db', '_ck_uat_db', '_ck_dev_db'),
            ('_runbutton'),
        ]

    def _auto_ip_press(self):
        # print('Pressed auto_ip')
        if self._auto_ip.value == False:
            self._txt_ip.enabled = True
        else:
            self._txt_ip.enabled = False

        self._runReady
            

    def _runReady(self, event):

        # pass
        if ((not self._txt_name.value) or 
            len(self._txt_name.value) <= 2): 
            self._runbutton.enabled     = False
            print('Application name is too short')
            return

        if not self._auto_ip.value == True:
            try:
                if not (0 < int(self._subnet_size.value) < 30):
                    print('Subnet Size must be between 0 and 30, not inclusive')
                    self._runbutton.enabled     = False
                    return 
            except Exception:
                print('Subnet Size is invalid')
                self._runbutton.enabled     = False
                return

            # Check if a real IP address was supplied
            try:
                ip_network(self._txt_ip.value)
            except Exception:
                self._runbutton.enabled     = False
                print('IP address is invalid', self._txt_ip.value)
                return
        
        self._runbutton.enabled     = True
        print('Nofail')



    def __runEvent(self):
        """
        After setting the best parameters run the full algorithm
        """
        
        # Put a value in for the seed subnet
        if not self._auto_ip.value:
            pcs = ip_network(self._txt_ip.value)
        else: pcs = None

        # Fix any names
        name = self._txt_name.value
        name.replace(' ', '_')

        try:
            createNewSBMApplication(name= self._txt_name.value,
                                prod_client_subnet= pcs,
                                autoIP = self._auto_ip.value,
                                author = self._author.value,
                                requestor = self._requestor.value,
                                change_num = self._change.value,
                                subnet_size = int(self._subnet_size.value),
                                tenant = self._cc_env.value,
                                reserve_in_ipam = self._reserve_in_ipam.value,
                                prod_client = self._ck_prod_client.value,
                                prod_web = self._ck_prod_web.value,
                                prod_app = self._ck_prod_app.value,
                                prod_db = self._ck_prod_db.value,
                                uat_client = self._ck_uat_client.value,
                                uat_web = self._ck_uat_web.value,
                                uat_app = self._ck_uat_app.value,
                                uat_db = self._ck_uat_db.value,
                                dev_client = self._ck_dev_client.value,
                                dev_web = self._ck_dev_web.value,
                                dev_app = self._ck_dev_app.value,
                                dev_db = self._ck_dev_db.value,
                                append = self._append.value,
        )
        except Exception:
            print("Critical error creating application")
            traceback.print_exc()    

def start():
    from pyforms import start_app
    start_app(ApplicationDeployer, geometry=(200, 200, 400, 400))

if __name__ == '__main__':
    start()

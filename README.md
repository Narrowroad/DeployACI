


# DeployACI

DeployACI is a Python library for deploying applications within the SBM Amsterdam datacenters.

## Installation

1. Clone this repository to your computer in a subdirectory of your choosing
2. Install [Python 3.7](https://www.python.org/downloads/) (this is not compatible with Python 2 and has some dependancy import errors with 3.8 and above as of October 2019). Make sure to check "Add Python to PATH" during installation, as it makes running commands from the command line easier.
3. *Optional*: You can isolate this application's dependancies using a virtual environment. This is advisable if you ever plan to run any other Python application which may share dependancies. Open a command prompt and type:
```
cd [package directory; the folder that has requirements.txt in it]
pip install virtualenv
virtualenv venv
venv\Scripts\activate.bat
```
> **Note:** If you do this and use a `virtualenv`, then any time you wish to run anything in this application, including the following installation steps, you will first run `activate.bat` (see above) to enter the virtual environment. To exit from the virtual environment, either close the terminal (command prompt) or type `deactivate`.


4. Install dependancies:
```sh
cd [package directory]
pip install -r requirements.txt
```
5. Download the ACI metadata to your computer. You will need to get the ACI `admin` account password from [PmP](https://nlpmp001.sbmoffshore.com:7272/PassTrixMain.cc#/PasswordFullView/PasswordMainView).
```sh
rmetagen.py -u admin 10.43.40.11
```
6. Run the application once without doing anything to generate the blank config file. You can close it as soon as it opens.
```sh
python deployaci
```

7. Open the newly generated `configuration.ini` and fill out the passwords and optional `Default Values` section. *Yes, the passwords are currently hardcoded. Yes, it's awful.*

This is the layout of the file:

```ini
[IPAM SERVER]
serveripaddress = orion.sbmoffshore.com
username = svc_api
password = 

[ACI APIC]
url = https://10.43.40.11
username = admin
password = 

[DEFAULT VALUES]
your_name = Wyko ter Haar
```

## Usage

Running the application will bring up a simple GUI you can fill out to generate the new EPG. 
```
python deployaci
```

![Loading the Application](/media/deployaci_start.gif)

![The GUI](/media/deployaci_gui.png)


### Application Name
This is the name of the application. It must be at least three characters long. The name will be used to generate the EPG names  *(i.e. **application**_prod_db)*

### Automatically Select IPs
This application will automatically search IPAM for the first available subnets of the given size. Currently, the following subnets are used:

 - `10.46.0.0/16`: Production
 - `10.47.0.0/16`: UAT
 - `10.48.0.0/16`: Development

If you want to manually/only semi-automatically specify the IP range, uncheck `Automatically select IPs` and fill in the network address for the first **prod** subnet you will make. The application will then choose the next consecutive subnets for the EPGs you selected.

**Example:**

You specify `10.46.40.0\24` as the seed subnet, and you select `Prod-Client`, `Prod-Db`, `UAT-Db`, and `Dev-Db` to be provisioned. The application will then choose (*and validate in ACI and IPAM*) the following:

 - **Prod-Client**: 10.46.40.0/24
 - **Prod-Db**: 10.46.41.0/24
 - **UAT-Db**: 10.47.40.0/24
 - **Dev-Db**: 10.48.40.0/24

### Environment
This is the selector for which tenant to deploy this application into.

For safety, the GUI defaults to using the `lab` tenant for deployments. Deploying new EPGs to that tenant is *generally* safe to do without the risk of impacting production environments, and is a useful way to test whether this script works. I highly recommend to uncheck `Reserve in IPAM` when testing, because otherwise you have to go through the annoying process of going though Solarwinds' GUI to delete the newly reserved addresses when you are done testing. 

When deploying to the production environment, switch to tenant `SBM` and check `Reserve in IPAM`.

### Reserve in IPAM
When checked, this automatically creates the appropriate subnets in IPAM, labels them appropriately, and reserves the gateway IP address. 

> **Note**: Even if `Reserve in IPAM` isn't checked, the script does verify that the IP addresses it generates are not in use in IPAM (and ACI, too).


### Append to Existing Service
Checking this removes the protections normally in place to prevent you from accidentally overwriting an existing application. Use this if you want to add new EPGs to an existing application profile.

### EPGs
At the bottom of the GUI is a list of possible EPGs to make. By default all are selected. Uncheck the EPGs you do not need to make. Contracts will automatically be created between the remaining EPGs. 


## After Running
After the application runs, check the terminal that you ran the it from to find a report on the EPGs that you created. You can share this output with the server engineers.

> **Note**: This is a **dangerous** application. With minimal effort, you will affect widespread changes across the **production environment**. If you have any questions on how to use this, please reach out to Wyko ter Haar.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.



## License
This application is proprietary to SBM Offshore and is not to be used by any unauthorized persons. As such, no license applies.


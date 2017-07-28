CERTitude - The seeker of IOC
=============
![CERTitude logo](https://s3.postimg.org/a9wtwdftv/test-logo-certitude-white-bg-75p.png)
# Description

CERTitude is a Python-based tool which aims at assessing the compromised perimeter during incident response assignments.
It allows analysts to perform large scale scans of Windows-based information systems by searching for behavioural patterns described in IOC (Indicator Of Compromise) files.

Notable features:
* Ability to scan hosts in a way that prevents the target workstation from knowing what the investigator is searching for
* Ability to retrieve some pieces of data from the hosts
* Multiple scanner instances (for IOCs and/or hash scans) can be run at the same time for parallel scanning
* Built with security considerations in mind (protected database, secure communications with hosts using IPSec)

# Install guide

## Submodules notice

CERTitude now relies on submodules. If updating an already cloned repo, do `git submodule init` and then `git submodule update`.

## Requirements

- Python (>= 2.7.9)
- OpenSSL (if you want to use SSL)


## Setup
### Clone properly
```
git clone --recurse-submodules https://github.com/CERT-W/certitude.git
cd certitude
```

### Virtualenv (optional)
CERTitude is best used with the *virtualenv* development scheme:
- Install virtualenv with `pip install virtualenv`
- In the root directory, type `virtualenv .`
- Activate the virtualenv
  - On Windows: `.\Scripts\activate`
  - On Linux: `. ./bin/activate`

### Install dependencies
* Install *plyara*
```
cd dist/plyara
python setup.py build && python setup.py install
cd ..
```
* Upgrade *pip*
```
pip install --upgrade pip
```
* **Windows only**: manually install *lxml* & *pycrypto*
```
pip install lxml-3.6.0-cp27-none-win32.whl
easy_install pycrypto-2.6.1.win32-py2.7.exe
```
* Install the other requirements
```
pip install -r requirements.txt
```
* Initialize the database
```
python main.py init
```

## Configuration
### Generate SSL certificate & private key (optional)

**Note:** this steps requires OpenSSL to be installed and in your `$PATH`. 
You may also have to run *gen-cert-for-me.bat* in an administrator prompt.

```batch
cd ssl
gen-cert-for-me.bat
```


### Tweak your config file

Edit `config.py` in the root directory:
- Enable HTTPS:
    - `USE_SSL=True`
    - `SSL_KEY_FILE = 'path/to/key'`
    - `SSL_CERT_FILE = 'path/to/cer'`
- Update the database location: `BASE_DE_DONNEES_QUEUE = 'path/to/db'`
- Set the server SALT for password hashing (based on sha256)


# Run guide

To use CERTitude and search for IOC efficiently, you need to use these different modules:

## Interface
This module creates a web-interface on <http://127.0.0.1:5000/> that allows you to visualize results and configure:
- IOCs
- Scan profiles (host-confidential scans, IOC list)
- Add Windows credentials
- Add scan batches and specify their targets

It can be launched using: `python main.py run -c interface`. Shortcuts are available for Windows (`.\interface.bat`) and Linux (`./interface.sh`).

**Note**: This module **only** configures CERTitude, but doesn't launch the scans itself.

## Scanners
After configuring scan batches through the interface, you will need to launch scanners to actually scan the target machines.

If your IOCs do not contain any hash elements, running the *IOC scanner* will be enough.

Otherwise, you will also need to run the *Hash scanner*.

**Why?** IOC scans perform much faster than hash scans, so running these in different processes allows you to perform faster scans overall. 

These scanners can be launched using:
- IOC scanner: `python main.py run -c iocscan` (shortcuts: `.\iocscan.bat` & `./iocscan.sh`)
- Hash scanner:`python main.py run -c hashscan` (shortcuts: `.\hashscan.bat` & `./hashscan.sh`)

**Tip**: If you want to scan different targets at the same time, you can run multiple scanner instances.

# Misc
## Common errors
#### \[dropFile] File components\scanner/resources/RemComSvc.exe was not found
That error tends to happen when your antivirus software flags RemComSvc.exe as dangerous and deletes it.
The binary has since been recompiled and should not trigger any errors anymore, but if so please contact us!

#### \[__setup]  (No writable share found among \[ADMIN$, C$])
The account you added through the interface does not seem to have administrator rights on the target machine.
Please make sure these rights have been setup properly.

## Contact

cert@wavestone.com
&copy; Wavestone 2017


## Available scan modules

```
*** IOCSCAN ***
ProcessItem     pid, parentpid, UserSID, Username, name, path, moduleList
MemoryItem      pid, parentpid, name, page_addr, page_size, access_read, access_write, access_execute, access_copy_on_write
RegistryItem    KeyPath, ValueName
ArpEntryItem    Interface, IPv4Address, PhysicalAddress, CacheType
PrefetchItem    PrefetchHash, ApplicationFileName, ReportedSizeInBytes, SizeInBytes, TimesExecuted, FullPath
ServiceItem     descriptiveName, mode, path, pathmd5sum, status, name
DnsEntryItem    RecordName, RecordType, TimeToLive, DataLength, RecordData/Host, RecordData/IPv4Address
PortItem        protocol, localIP, localPort, remoteIP, remotePort, state, pid
FileItem        FilePath, FullPath, FileExtension, FileName


*** HashSCAN ***
FileItem        FilePath, Md5Sum, Sha1Sum, Sha256Sum
```

## Contributors

### Developers 

- Aurélien BAUD
- Adrien DEGRANGE
- Thomas LABADIE
- Jean MARSAULT
- Vincent NGUYEN
- Fabien SCHWEBEL
- Antoine VALLEE


### External dependencies

- Plyara : https://github.com/8u1a/plyara/

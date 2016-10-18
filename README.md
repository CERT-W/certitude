CERTitude - The seeker of IOC
=============

# Install guide

## Software Requirements

- Python >= 2.7.9
- OpenSSL if you want to use SSL


## Installing Python requirements

```batch
cd dist
pip install --upgrade pip
pip install lxml-3.6.0-cp27-none-win32.whl
.\pycrypto-2.6.1.win32-py2.7.exe
pip install -r requirements.txt
```


## Generating SSL certificate & private key

```batch
cd ssl
gen-cert-for-me.bat
```


## Tweaking your config file

Edit `config.py`

- Enable HTTPS:
    - `USE_SSL=True`
    - `SSL_KEY_FILE = 'path/to/key'`
    - `SSL_CERT_FILE = 'path/to/cer'`
    
- Database location: `BASE_DE_DONNEES_QUEUE = 'path/to/db'`
- Set the server SALT for password hashing (based on sha256)


# Run guide

## Initializing the database

`python main.py init`


## Runnning things

- Interface : `python main.py run -c interface`
- Scanner : `python main.py run -c iocscan [-b batch]`


# Misc

## Contact

cert@wavestone.com

&copy; Wavestone 2016


## Contributors

- Aurélien BAUD
- Adrien DEGRANGE
- Jean MARSAULT
- Vincent NGUYEN
- Fabien SCHWEBEL
- Antoine VALLEE

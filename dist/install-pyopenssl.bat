@echo off

easy_install pycparser
easy_install ipaddress
easy_install enum34
easy_install idna

pip install -v cffi-1.2.1-cp27-none-win32.whl
pip install -v cryptography-1.0-cp27-none-win32.whl

easy_install pyopenssl
python -c "import OpenSSL"
pause
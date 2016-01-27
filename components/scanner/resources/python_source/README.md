Adding your module
==================

## Coding

- Look at the way other modules are built
- Write your module
- Add your import code to collector.py


## Compiling

#### Requirements

- pyinstaller
- pywin32

#### The right way

- `pyinstaller --onefile collector.py`
- Grab `dist\collector.exe` and TarGZ it along with `launch.bat` and other EXE in this directory + file `hash.cfg`
- Place it in parent directory under the name `collecte.tar.gz`
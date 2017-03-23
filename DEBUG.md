CERTitude - Debugging the tool
=============

## SMBError - ErrNoMem

**Description:**
This error can be encountered on Windows 7 (and maybe other) wintations. 
It is due to a lack of resources that can be allowed to the named pipes by the "LanMan Server" service.

**Fix:**
Add or modify the DWORD registry key `HKLM\SYSTEM\CurrentControlSet\services\LanManServer\Parameters => size` to `0x3`.

**Admin command:**
```
reg add HKLM\SYSTEM\CurrentControlSet\services\LanManServer\Parameters /t REG_DWORD /v Size /d 0x3 /f
``` 
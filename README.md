# A tool to read the ntfs acls of directories and files

I wrote this tool as I could not find one that reads ntfs permissions for files and directories and allows to exclude inherited access rules and returns csv/json/... output.
I am not a programmer, so the code is pretty ugly and likely not very efficient  ¯\\_(ツ)_/¯

The tool recursively checks acls for the provided directory. As I'm using .Net core, we can make use of [enumerationoptions](https://learn.microsoft.com/en-us/dotnet/api/system.io.enumerationoptions?view=net-7.0) which allows to continue enumerating files and directories on access denied errors.
Inherited access rules, and access rules for the following SIDs are skipped:
- S-1-5-18 (SYSTEM)
- S-1-5-32-544 (Administrators)

An output file in CSV-format is being generated.

### Usage

```
NtfsAuditV3.exe -p <path-to-scan> -o <output-file>
```
```
NtfsAuditV3.exe -p C:\Temp\ -o C:\Temp\NtfsAuditV3.txt
[*] Scanning 'C:\Temp\' and writing output to 'C:\Temp\NtfsAuditV3.txt'
```
### Example output file content:

```
Result;objectType;SID;Path;Account;FilesystemRights
Read;directory;S-1-5-32-545;C:\Temp\;BUILTIN\Users;ReadAndExecute, Synchronize
Write;directory;S-1-5-11;C:\Temp\;NT AUTHORITY\Authenticated Users;Modify, Synchronize
Write;file;S-1-5-11;C:\Temp\test\Bla.txt;NT AUTHORITY\Authenticated Users;Modify, Synchronize
Read;file;S-1-5-32-545;C:\Temp\test\Bla.txt;BUILTIN\Users;ReadAndExecute, Synchronize
```

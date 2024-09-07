# Generic Injection Detection

## Detect DLL or SO injection
- Windows
 > Verifying signatures of DLLs of the current process.
- Linux
> Verify the checksums of loaded shared objects by calculating the checksums of loaded objects and re-checking if the checksums have changes (have been tampered with), excluding system libraries.

## Detect IAT (Import Address Table) or similar injection
- Windows
 > Checking DOS signature, NT signature, checking if import address is different than DLL/library address based on the name of the import.
- Linux
 > In Linux, "IAT-like" injections could be checked by verifying dlsym or library hooking (verifying the integrity of GOT (Global Offset Table) entries using dlsym).
 > This would involve checking the function resolution system (similar to IAT) for integrity.
 > Typically, Linux does not have a direct IAT, but you can monitor for manipulation via dlsym or by LD_PRELOAD.

## Detect FAT or function pointer injections
- Windows
 > Detects potential FAT (vtable) injection by checking the vtable of an object.
 > FAT injection detection can be specific to the application structure (like virtual table).
- Linux
 > Checking for function pointer injections (virtual table or function hook monitoring).
 > FAT-like injection in Linux could involve monitoring virtual function tables.
 > FAT injection detection can be specific to vtable manipulation or function pointer overwrites.

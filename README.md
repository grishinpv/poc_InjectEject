# poc_InjectEject
Testing tool with Injection\Ejection technics built for learning purposes

# Available functions
```
Usage:
      -i <process name> <path/to/dll>   Inject Dll into the process
      -h <process name> <path/to/dll>   Inject Dll via SetWindowsHookEx (exported func = poc)
      -u <process name> <dll name>      Unload Dll from the process
      -c <process name> <dll name>      Check Dll loaded by the process
      -e <process name to duplicate Token> <path/to/exeToRun>   Run Elevated process via DuplicateTokenEx
```

# Available actions after injection
  * killProcessByName (might not work when multiple process with the same name)
  * StopService
  * SetServiceType_DISABLE
  * InjectLib (for reflected dll injection)
  * RenameFile
  * MessageBox
  * StartHollowed
  * NTkillProcessByName
  * RemoveAllPrivileges
  

## From OALabs first DLL tutorial analysis!!!!!!
- The DLL has a single export function named Work, we can tell it's a DLL from the DllEntryPoint export as well in IDA.
- Lots of imports, we can see Sleep, file creation, some thread and process operations, a lot of kernel32 and one from shell32 called shellexecuteW.

Dll main shouldn't have much malicious stuff since its mainly for setup and not bad stuff yet.

We can see that DllMain's decompilation has some setup code before calling the DllMainCRTStartup function, which is just the dllmain startup; the actual setup for the dll file.
- MSDN documentation for DllMain (entry point) says that the DllMain function takes a handle to a Dll, a reason for calling a function, and a reserved argument.
  - The fdwReason variable states why the DLL was called; most oftenly for attaching to a process (DllProcessAttach), ThreadAttach, ProcessDetach, etc.
  - Since fdwReason is being checked for '1', which is representative of 'DLL_PROCESS_ATTACH', we can rename the '1' in the if statement by hitting 'm' and search 'DLL_' and seeing that DLL_PROCESS_ATTACH is the only available option!
    - Since this is true, this means the check is looking for if this is the first time the DLL has been loaded.
      - __security_init_cookie is a cookie that prevents buffer overflows; it's a security feature for PEs/Dlls and is usually one of the first few things done in program setup.

After all of this, the crtstartup function runs!
- Notice that when we check the function, it shows it takes 3 args, but the entry point showed 1 arg being passed! IDA is dumb and doesn't know this, but we can go back and check to see that 3 args ARE being passed to DllMainCRTStartup, which are:
  - IDA doesn't instantly show this, so we need to edit this ourselves
  - Press 'y' when hovering on the function prototype and we can then copy it like so:
    - BOOL __fastcall __DllMainCRTStartup(void *a1, DWORD a2, HINSTANCE hinstDLL);
    - We know that the second arg is fdwReason (type DWORD) and the first one is lpReserved (type LPVOID)
    - The fixed prototype is 'BOOL __fastcall __DllMainCRTStartup(LPVOID lpReserved, DWORD fdwReason, HINSTANCE hinstDLL);'
    - Now when we go back to CRTStartup, the var names are all good and are propogated in the function.
      - We can see that in this function, the same fdwReason checking stuff is occurring, so we can rename all the constant numbers to the appropriate constants/macros per the MSDN docs.
      - We can also see that DllMain is being called, which is a nice entry point to the malicious nature of the program.
      - We can see that CRT_INIT is called and checked if it succeeds in running.
        - If it fails to run successfully, then DllMain is never called and we early return.
        - CRT_INIT does some setup things for getting command line input.
          - dword_10033CD8 = (int)GetCommandLineA();
            - GetCommandLineA MSDN docs say that it retrieves the current command line string for the current process (not the dll, but the process the dll runs under), returns LPSTR.
            - We can hit 'y' to edit the type of the dword to LPSTR, then 'n' to edit it's name to 'g_commandLineString'.

DllMain MSDN docs shows it returns a BOOL value for its exit status.
- We can edit the 'v5' value as it is the ret value of DllMain, which we'll call 'initStatus'. We can change this by hitting 'n' on it and renaming it.
            
Notice that on line 12, if the dll is attached to a process and the first DllMain call fails, we call Dllmain against bt this time with fdwReason 0, which is 'DLL_PROCESS_DETACH', which is the cleanup call to DllMain.
- Basically, if it fails, we should just clean up and give up.

If we check DllMain, DllMain legit returns 1, and THAT'S IT. Nothing to hide here, so the only other thing left to check is the other export, which is Work.

When we do open this export function, we can see that there is now some actual code to reverse!

> [!NOTE]
> That's all that's left in the tutorial, so we'll just stop here!

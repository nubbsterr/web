## From OALabs 2nd tutorial exe analysis!!!!!!
- Imports show some kernel32 and ntll stuff.
  - We can see some network and crypt32 imports, which may suggest some outbound c2 comms.
- Only one export which is just 'start', suggesting this is just an EXE, with no other function to run, like a DLL w/ the entry point and some other.

- When decompiled, we can see that the entry point initializes the security cookie and runs the CRTStartup function, which is 'C Runtime Startup'.
  - When we enter this function, we can see some red memory addresses, which are made by the compiler.
  - When IDA views this, the address doesn't exist in the binary.
  - On disk, a PE file is in its unmapped form; the file offsets in it will align to the bytes on disk.
    - When the PE is ran, everything gets mapped into memory (virtual addresses now in use), which is controlled by the PE header. What we see in IDA is the mapped addresses, which are mapped to the 'preferred base address' of the PE file.
      - The preferred base address in specified in the Optional Header in the PE.
      - When loaded in IDA, IDA sets the base address as the Image Base specified in the PE file.
      - When we check the Section View in IDA, we can actually see that these bad addresses occur before the .text section; these addresses are referencing stuff IN THE PE HEADER, which gets loaded when the EXE is ran.
        - In IDA, this whole issue can be fixed by exiting from IDA, then opening the file to disas, except we'll click "manual load" --> "ok" --> "yes to all secctions" --> "load file header!!!!!!" --> "continue hitting ok through the prompts"
        - When we load back into CRTStartup, we can see the addresses are fixed and we can see the ImageBase is loaded and we can see it in the linear disas view!
        - Note IDA also doesn't load resources by default, but this can be solved similarly as we did just now.

  We can see that there is some startupinfo that gets loaded, and some if condition that runs HeapSetInformation.
  - HeapSetInformation under MSDN (how it's running here) basically is just adding some error protection to the heap setup.
    - We can also see the function run with some constant expressions, which we can evaluate through the MSDN docs. The correct new function call is:
    HeapSetInformation(
      (HANDLE)HeapCompatibilityInformation,
      HeapEnableTerminationOnCorruption,
      (PVOID)HeapCompatibilityInformation,
      HeapCompatibilityInformation);
  - We can rename the DWORD controlling the if condition that runs this to 'g_HeapEnableTerminationOnCorruption'.
    - Even if we don't know the exact name, this allows us to note that we've seen this variable before.

Next up are a ton of conditions:

v7 = LOWORD(_ImageBase.unused) == 23117
    && *(int *)((char *)&_ImageBase.unused + (_DWORD)off_40003C) == 17744
    && *(__int16 *)((char *)&word_400018 + (_DWORD)off_40003C) == 267
    && *(_DWORD *)&byte_400040[(_DWORD)off_40003C + 52] > 0xEu
    && *(_DWORD *)&byte_400040[(_DWORD)off_40003C + 168] != HeapCompatibilityInformation;

We can note a few things:
- They check ImageBase structure info
- The ImageBase HISTANCE struct is documented but isn't correct for the code that's running. The code is actually parsing the PE file.
  - The 23117 being checked is actually the 'MZ' header that is being checked!!!

We'll fix up the struct type as follows:
- Hit 'y' and remove the type info from the ImageBase struct in the linear view.
- Hit 'u' to undo our changes, which will now show no type on the ImageBase, but undoes the changes we did such that nothing bad happens to the struct itself.
- Go to 'Local Types' --> Right-click to add a type --> C syntax --> Paste the following:

union PE_BASE {
  PVOID baseAddress;
  IMAGE_DOS_HEADER *mz;
  IMAGE_NT_HEADERS *pe;
};

Note that we actually already have a handle to the PE file already, so we can remove the pointer to instead referencing the values at the headers and not the addresses.

Now hit 'y' on the linear view and apply our new type to the ImageBase struct.
- Then hit 'F5' in the decompiled view to decompile again.

Now our struct is applied nicely, the code is a bit more readable.
- Firstly, we will "edit" the v7 condition checking the MZ header.
  - Right-click and select 'Select Union Field' then hit 'baseAddress'.
  - This shows that we're checking the baseAddress to MZ.
- We will also rename the 17744 constant by hitting 'r' which now shows 'EP', or 'PE'.
  - This shows that we're checking the offset from the ImageBase to the PE header, which you get by adding the base + elfanew address.
  - Note that the very first byte in the MZ header is the base address!
  - If the 'Select Union Field' and set the pe.Signature field to now e_magic, we can really see that they're just ensuring that the PE header is properly structured and offset from the base address correctly.
- The next check can be modified as we change the union to pe.OptionalHeader.
  - This 2nd condition is checking that the 'MZ' header + the optional header offset is equal to '0x10B', which per the docs is 'IMAGE_NT_OPTIONAL_HDR32_MAGIC'; the file is executable.
  - They are ensuring this is a valid exe/PE.
- The 3rd condition if the number of directory entries is large enough to index into the 14th one, which is checked in the 4th condition.
- The 4th condition checks if the 14th directory != 0
  - Recall that e_lfanew is the logical file address of the NEW executable file; in other words, the offset relative to the start of the exe file.
  - This basically ensures we are checking the right address in the PE file!

Our next step is to check the data directory now.
- The 14th one is the IMAGE_DIRECTORY_ENTER_COM_DESCRIPTOR table.
  - The COM_DESCRIPTOR table is populated if this is a manged PE file; a .NET file.

We now have sufficient information to label the v7 variable to something meaningful.
- We'll name it 'isManagedPE'
- We can see that this var was actually just used to call a different exit function lol.
  - If not managed, then a separate exit function is called.

We can see a bit more startup stuff:
- _heap_init which is for heap initialization
- _mtinit which is for thread initialization
- _ioinit which is for stderr/stdout initialization
- _setargv which sets up command line args
- _setenvp which sets up environment vars
- _cinit which is for C runtime setup
  - Notice that if this fails, we exit
  - the _amsgexit function prints an error message through _NMSG_WRITE
    - _NMSG_WRITE itself runs "_GET_RTERRMSG, which will actually pass the given error code (named a1) from _asmgexit and find an appropriate error message to display.
    - We can see the various defined error messages at '.rdata:0040AE98' in the PE file!
    - We'll rename 'a1' to be 'errorCode' in this case.
    - We'll also rename the two offsets being indexed to 'g_data1' and 'g_data2' respectively.
    - We can also note that the total number of error codes available is 22, given the conditional check in the while loop determining if v1 (index of array error code) is >= 22.
      - With this, we'll make a simple data struct to represent this error code array (0 - 21).
        - Each element has an error code + a pointer to an error message
        - We can also notice that the _GET_RTERRMSG function returns wchar_t, which is just going to the be long string (UTF-16LE, as shown if you hover over the offsets/pointers in the data section).
        - Now we have enough info to actually make the new data type:
        - Goto local types --> new type --> create the type like so:

        struct error_msg{
          DWORD error;
          wchar_t* msg;
        }

        - Now back to the data section, we can hit 'y' on int g_data1 to apply the type, then apply it to g_data1 itself.
          - Apply 'error_msg' to g_data1 then right-click g_data1 --> array --> size 22 --> OK --> directly convert to array
          - Now we can see our strings/error codes nicely like so:

          error_msg <8, offset aR6008NotEnough> ; "R6008\r\n- not enough space for argumen"...

          - Hit F5 again in the decompiled view and we can see our array being indexed nicely.
          - We can change g_data1's type in the RTERRMSG function to show an array-like syntax by changing its type to error_msg g_data1[22].
          - Now this is extremely clean and makes a lot more sense, though it was already pretty clean to begin with.
          - We can also rename g_data1 to g_ErrorCodes instead now since it makes more sense.
          - **Part of the vid shows turning the array into an enum, which is cool but also rather unnecessary given the already-good array definition.**
          

After all this setup, we can see 'v1' stores some command line input, so we'll label this instead as 'var_commandLine'

Afterwards, we finally see a call to WinMain

## End of tutorial 2

Continuing on our own, we can see sub_4011C1 doing a LOT of process handling and things.
- Accidentally messed up the conditional statement and removed the '== 1' bit from the while loop in WinMain, added a comment about this.

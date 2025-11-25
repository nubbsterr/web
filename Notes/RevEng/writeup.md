## Shrimple analysis of [r0b's SanSuu crackme](https://crackmes.one/crackme/606b1faf33c5d418e8c4009e)

This is a C/C++ Windows binary, as we can instantly tell by the WinMain call in the disassembly.

The program itself is rather short and shows some conditional control flow through the `sub_401209` subroutine.

We can decompile the program to get the following:

```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  HWND v4; // edi
  struct tagMSG Msg; // [esp+4h] [ebp-1Ch] BYREF

  if ( !sub_401209(hInstance) )
    return 0;
  v4 = (HWND)sub_401298(hInstance, nShowCmd);
  if ( !v4 )
    return 0;
  while ( GetMessageA(&Msg, 0, 0, 0) )
  {
    if ( !IsDialogMessageA(v4, &Msg) )
    {
      TranslateMessage(&Msg);
      DispatchMessageA(&Msg);
    }
  }
  return Msg.wParam;
}
```

The `tagMSG` struct is rather interesting. The first few lines appear to be initialization/setup stuff. We actually only get some stuff going once we enter the `GetMessageA` loop.

Per MSDN docs, this function "retrieves a message from the calling thread's message queue. The function dispatches incoming sent messages until a posted message is available for retrieval."
- The `MSG` struct is documented [here](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg).
- The final return statement returns `Msg.wParam`, which is additional information about the message sent. 

The function returns either 0/1/negative for return code; whether it retrieves a message other than quit (ret nonzero), quit (ret 0), or some error (-1); e.g. the function fails if hWnd is an invalid window handle or lpMsg is an invalid pointer.

So basically, we continue ingesting messages until we want to quit. The next IF statement uses `IsDialogMessageA`. This confirms that the incoming message is for the app dialogue box.
- We can also note that v4 is the first param, and its also set to be a handle to the dialogue box, so we can rename it as such.

Once we're out of this check, we run `TranslateMessage` and `DispatchMessageA`:
- Not much happens here, so we're kinda stuck?

---

We can check for strings in the Views --> Subviews menu and see two very interesting finds; two strings, one saying "Invalid Serial! :(" and one saying "Thank you for registering! :D".
- We can see that the two `unk_*` strings are referenced in `sub_401026`, which looks like this:

```c
int __cdecl sub_401026(
        int (__stdcall *a1)(int),
        void (__stdcall *a2)(int),
        void (__stdcall *a3)(int, _BYTE *, _DWORD, _DWORD),
        int (__stdcall *a4)(int, int),
        int (__stdcall *a5)(int, int, int, int),
        int a6)
{
  int v6; // eax
  _BYTE *v7; // eax
  _BYTE v9[28]; // [esp+8h] [ebp-40h] BYREF
  char v10[4]; // [esp+24h] [ebp-24h] BYREF
  _BYTE v11[20]; // [esp+28h] [ebp-20h] BYREF
  int v12; // [esp+3Ch] [ebp-Ch]
  int v13; // [esp+40h] [ebp-8h]
  int v14; // [esp+44h] [ebp-4h]

  v12 = 1;
  v13 = a1(64);
  v6 = a4(a6, 101);
  v14 = a5(v6, 13, 64, v13);
  if ( v14 >= 5 && v14 <= 11 && (v14 & 1) != 0 )
    v12 = sub_401000(v13);
  qmemcpy(v11, &unk_402150, sizeof(v11));
  qmemcpy(v9, &unk_402164, sizeof(v9));
  strcpy(v10, ":D");
  v7 = v11;
  if ( !v12 )
    v7 = v9;
  a3(a6, v7 + 1, 0, 0);
  a2(v13);
  return 0;
}
```

Notice the `:D` is very clearly going to be the `thank you` string, so this is our foothold for now.

We first need to figure out what each of these functions are.
**I did a lil cheating and looked up a writeup (by https://crackmes.one/user/rDFDyYI) at this point because the functions here are damn near unreadable/impossible to understand. Like wtf is a1/a5, and why do they not resolve to any sort of functions but instead some random dword**

What we can definitely see and do is that v11/v9 are both the destination of the mem copy operations. We can also assume that `sizeof(v11)` is the size of our string. So what we're doing here, is just getting our strings ready to print.

The big thing to get here is `v12`. From the writeup, we know that `v14` just refers to the size of our given key, among other things, purely from just intuition and guessing:

```c
int __cdecl sub_401026(
        int (__stdcall *a1)(int),
        void (__stdcall *a2)(int),
        void (__stdcall *a3)(int, _BYTE *, _DWORD, _DWORD),
        int (__stdcall *a4)(int, int),
        int (__stdcall *a5)(int, int, int, int),
        int a6)
{
  int v6; // eax
  _BYTE *output; // eax
  _BYTE goodStr[28]; // [esp+8h] [ebp-40h] BYREF
  char v10[4]; // [esp+24h] [ebp-24h] BYREF
  _BYTE invalidStr[20]; // [esp+28h] [ebp-20h] BYREF
  int isBadKey; // [esp+3Ch] [ebp-Ch]
  int inputKey; // [esp+40h] [ebp-8h]
  int keySize; // [esp+44h] [ebp-4h]

  isBadKey = 1;
  inputKey = a1(64);
  v6 = a4(a6, 101);
  keySize = a5(v6, 13, 64, inputKey);
  if ( keySize >= 5 && keySize <= 11 && (keySize & 1) != 0 )
    isBadKey = sub_401000(inputKey);
  qmemcpy(invalidStr, &unk_402150, sizeof(invalidStr));
  qmemcpy(goodStr, &unk_402164, sizeof(goodStr));
  strcpy(v10, ":D");
  output = invalidStr;
  if ( !isBadKey )
    output = goodStr;
  a3(a6, output + 1, 0, 0);
  a2(inputKey);
  return 0;
}
```

This makes far more sense now. All that's left is to reverse `sub_4010000`, since we want isBadKey to be 0 to get the good string.

```c
int __thiscall sub_401000(char *this)
{
  char v1; // al
  int v2; // esi
  char *v3; // ecx

  v1 = *(this + 1);
  v2 = *this;
  if ( v1 )
  {
    v3 = this + 2;
    if ( (v1 & 1) != 0 )
      return v2 + sub_401000(v3);
    v2 -= sub_401000(v3);
  }
  return v2;
}
```

Let's fix this up a bit with what we know:

```c
int __thiscall sub_401000(char *inputStr)
{
  char char1_of_inputStr; // al
  int char2_of_inputStr; // esi
  char *ptr_to_char3_of_inputStr; // ecx

  char1_of_inputStr = *(inputStr + 1);
  char2_of_inputStr = *inputStr;
  if ( char1_of_inputStr )
  {
    ptr_to_char3_of_inputStr = inputStr + 2;
    if ( (char1_of_inputStr & 1) != 0 )
      return char2_of_inputStr + sub_401000(ptr_to_char3_of_inputStr);
    char2_of_inputStr -= sub_401000(ptr_to_char3_of_inputStr);
  }
  return char2_of_inputStr;
}
```

With the unmatched power of C knowledge of pointers we can make this INCREDIBLY EASY TO UNDERSTAND!

This really just devolves into ASCII table arithmetic jargon, which I can't be asked to solve, especially since I hate bitwise operations.

Overall, this is a very cool challenge, but IDA just screws us over w/ obscure/obfuscated/impossible-to-decipher function names, which are legit Windows API functions according to the writeup.

# Pinjectra
Pinjectra is a C/C++ library that implements Process Injection techniques (with focus on Windows 10 64-bit) in a "mix and match" style. Here's an example:

```
// CreateRemoteThread Demo + DLL Load (i.e., LoadLibraryA as Entry Point)
executor = new CodeViaCreateRemoteThread(
    new OpenProcess_VirtualAllocEx_WriteProcessMemory(
        (void *)"MsgBoxOnProcessAttach.dll",
        25,
        PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE),
    LoadLibraryA
);

executor->inject(pid, tid);
```

It's also currently the only implementation of the "Stack Bomber" technique. A new process injection technique that is working on Windows 10 64-bit with both CFG and CIG enabled.

Pinjectra, and "Stack Bomber" technique released as part of the [Process Injection Techniques - Gotta Catch Them All](https://www.blackhat.com/us-19/briefings/schedule/#process-injection-techniques---gotta-catch-them-all-16010) talk given at BlackHat USA 2019 conference and DEF CON 27 by Itzik Kotler and Amit Klein from [SafeBreach Labs](http://www.safebreach.com).

### Version
0.1.0

License
----

BSD 3-Clause

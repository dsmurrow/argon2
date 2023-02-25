
Created for compatibility with a larger project I'm working on.


Will work on GCC and MSVC.


GCC recommended flags(Right out of the specs):
```
-m64 -mavx -pthread -O3 -std=c99
```

To compile with MSVC into a static library I recommend:
```
cl argon2.c threading.c blake2b.c /c /GL /O2 /arch:AVX
lib argon2.obj threading.obj blake2b.obj /LTCG
```
and when you link the .lib file you need to add the /LTCG flag again. If you want to avoid that you can choose not to use /GL and /LTCG.

To compile into a DLL, add the \_\_declspec items into argon2.h and run:
```
cl argon2.c threading.c blake2b.c /O2 /arch:AVX /LD
```


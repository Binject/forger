# Forger

Forger is a tool that implements various code signing attacks against multiple binary types. Currently only certificate copying attacks on PE files are implemented. 

## Usage:

```
  -C    File to check if signature is present; validity is not checked
  -T    Remove signature from input file
  -a    Add signature from input cert to target file
  -c    Copy signature from input file to target file
  -i string
        File to copy the signature from
  -o string
        Output file
  -r    Copy signature to from the input file to disk
  -s string
        Path to binary signature on disk
  -t string
        File to be signed
```


## Read more about the project here:
https://www.symbolcrash.com/2019/02/23/introducing-symbol-crash/

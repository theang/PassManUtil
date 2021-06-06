# Utility to manage passman password of WebMethods Integration Server installation 6.5

```
Parameters: [-v] <empw.dat> <txnPassStore.data> <passman.cnf> <-l | -s key value | -d key>"
             -v                  - verbose mode to log passman messages
             <empw.dat>          - path to empw.dat, master password file
             <txnPassStore.data> - path to txnPassStore password database
             <passman.cnf>       - path to passman configuration file
             -l                  - list all passwords
             -s <key> <value>    - modify key with value
             -d <key>            - delete key
```

# Building
./gradlew build

./gradlew distZip

will create zipped file in ./build/distributions

# Example
example provided to demonstrate, which can be run like this:
./gradlew build
./runPassmanUtil.sh ./example/empw.dat ./example/txnPassStore.dat ./example/passman.cnf -l


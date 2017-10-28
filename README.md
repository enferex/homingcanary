HomingCanary: Proof-of-concept for locating return addresses based on entropy.
==============================================================================

What
----
HomingCanary (HC) is a proof-of-concept code that scans a process' memory space
looking for return addresses.  Once a return address is located it is
compromised/tainted by writing the value 0xdeadbeef in place of the address.

How
---
HC works by scanning a process' memory space via `/proc/<pid>/maps` filesystem
mapping.  HC looks within that space for what it thinks is a stack canary.  HC
guesses what word is a canary based on the assumption that a canary consists of
a pseudo-randomly generated value. The HC algorithm is based on Shannon's
Entropy.  In the case of HC, it looks at word sized items within the process'
memory-mapped space, and guesses that a canary is any word where each byte in
the word is unique.

An additional check is also performed looking at the value 16 bytes from the
guessed canary.  If that word has a value that falls within the address range of
the mapped memory range, then we say that word contains a return address.  This
is not 100% exact, and this POC can be extended to be more accurate.  However,
this utility illustrates the potential return-address attack.

The other assumption HC makes is that all threads (and their stacks, return
addresses and canaries) live in the memory mapped area of the process.
Since thread's have their own stack's, then return addresses must live in that
space.

Usage
-----
* The sample program can be built via ```make test```
* HC can be built via ```make```
* Run the test program `test` from one terminal.  This
test will output its PID.
* In another terminal, as root, run ```homingcanary -p <pid>``` where `<pid>` is
the PID output from the test program.
* The test program should crash if it has been compromised, running `test` via a
debugger should show that it's return address was corrupted to be 0xdeadbeef.

Caveat
------
* To guess a return address, HC looks 16 bytes past what it thinks is a canary.
* HC requires root permissions to scan and manipulate a process' memory space.

Reference
---------
* https://en.wikipedia.org/wiki/Diversity_index#Shannon_index 
* Associated article: POC||GTFO 0x16, page 49, https://www.alchemistowl.org/pocorgtfo/

Contact
-------
Matt Davis (enferex)

https://github.com/enferex

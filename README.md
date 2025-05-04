This is a thin wrapper around the ed25519 library by Orson Peters (and contributors), which you may find on the linked git submodule. 

To use, first compile the library with the appropriate script, and then simply include the odin package. 

Seeding is meant to be done by Odin's true randomness source, instead of using the integrated seed algorithm, and thus that part of the ed25519 library has been disabled.
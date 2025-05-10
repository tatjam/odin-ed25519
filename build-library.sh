mkdir build
cd build
gcc -DED25519_NO_SEED -c \
../ed25519-c/src/add_scalar.c \
../ed25519-c/src/fe.c \
../ed25519-c/src/ge.c \
../ed25519-c/src/key_exchange.c \
../ed25519-c/src/keypair.c \
../ed25519-c/src/sc.c \
../ed25519-c/src/seed.c \
../ed25519-c/src/sha512.c \
../ed25519-c/src/sign.c \
../ed25519-c/src/verify.c

ar rcs libed25519.a add_scalar.o fe.o ge.o key_exchange.o keypair.o sc.o seed.o sha512.o sign.o verify.o

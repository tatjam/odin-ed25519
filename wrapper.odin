package ed25519_wrapper
import "core:c"

when ODIN_OS == .Windows do foreign import ed25519 "build/libed25519.lib"
when ODIN_OS == .Linux   do foreign import ed25519 "build/libed25519.a"

@(default_calling_convention="c")
foreign ed25519 {
    @(link_name="ed25519_create_keypair")
    __ed25519_create_keypair :: proc(pubkey, privkey, seed: [^]c.uchar) ---
    @(link_name="ed25519_sign")
    __ed25519_sign :: proc(sig, msg: [^]c.uchar, msg_len: c.size_t, pubkey, privkey: [^]c.uchar) ---
    @(link_name="ed25519_verify")
    __ed25519_verify :: proc(sig, msg: [^]c.uchar, msg_len: c.size_t, pubkey: [^]c.uchar) -> c.int ---
    @(link_name="ed25519_add_scalar")
    __ed25519_add_scalar :: proc(pubkey, privkey, scalar: [^]c.uchar) ---
    @(link_name="ed25519_key_exchange")
    __ed25519_key_exchange :: proc(shared_secret, pubkey, privkey: [^]c.uchar) ---
}


// Creates a public-private key pair from the given 32 byte long seed
// which ideally should be created with high quality randomness
// pubkey and privkey must also be 32 bytes long
create_keypair :: proc(seed, pubkey, privkey: []byte) {
    assert(len(seed) == 32)
    assert(len(pubkey) == 32)
    assert(len(privkey) == 32)

    __ed25519_create_keypair(raw_data(pubkey), raw_data(privkey), raw_data(seed))
    return
}

// Writes signature of msg to sig. sig must be 64 bytes long, msg is arbitrarily long.
sign :: proc(sig, msg, pubkey, privkey: []byte) {
    assert(len(sig) == 64)
    assert(len(pubkey) == 32)
    assert(len(privkey) == 32)

    __ed25519_sign(raw_data(sig), raw_data(msg), len(msg), raw_data(pubkey), raw_data(privkey))
}

// Verifies if sig was generated from msg with pubkey's associated private key
// sig must be 64 bytes long, and pubkey 32 bytes long
verify :: proc(sig, msg, pubkey: []byte) -> bool {
    assert(len(sig) == 64)
    assert(len(pubkey) == 32)

    ret := __ed25519_verify(raw_data(sig), raw_data(msg), len(msg), raw_data(pubkey))

    if ret == 0 do return false

    return true
}

// Adds scalar (32 bytes) to the given keys (32 bytes or nil each)
add_scalar :: proc(pubkey, privkey, scalar: []byte) {
    if pubkey != nil do assert(len(pubkey) == 32)
    if privkey != nil do assert(len(privkey) == 32)
    assert(len(scalar) == 32)

    __ed25519_add_scalar(raw_data(pubkey), raw_data(privkey), raw_data(scalar))
}

// Performs key exchange on given public and private keys (32 bytes each), writing the shared
// secret to `secret`, which must also be 32 bytes long
key_exchange :: proc(secret, pubkey, privkey: []byte) {
    assert(len(pubkey) == 32)
    assert(len(privkey) == 32)
    assert(len(secret) == 32)

    __ed25519_key_exchange(raw_data(secret), raw_data(pubkey), raw_data(privkey))
}

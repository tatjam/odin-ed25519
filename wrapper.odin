package ed25519
import "core:c"

when ODIN_OS == .Windows do foreign import ed25519 "build/libed25519.lib"
when ODIN_OS == .Linux   do foreign import ed25519 "build/libed25519.a"

foreign ed25519 {
}

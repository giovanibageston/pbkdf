package pbkdf

import "crypto"

// PBKDF is the general signature for a password-based key derivation function.
// hash: the hash function to be used(can be any crypto.Hash)
// P: the password(as a byte slice)
// S: the salt(as a byte slice)
// c: the iteration count
// dkLen: the byte length of the derived key
// returns: DK, the derived key or an error if any
// the functions PBKDF1 and PBKDF2 of this package implement this function
type PBKDF func(hash crypto.Hash, P []byte, S []byte, c int64, dkLen int64) ([]byte, error)

package pbkdf

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha512"
	"errors"
	"fmt"
)

// PBKDF1 is a function that implements the PBKDF1 algorithm
// It is based on the RFC8018(https://datatracker.ietf.org/doc/html/rfc8018)
// it implements the PBKDF function type
func PBKDF1(hash crypto.Hash, P []byte, S []byte, c int64, dkLen int64) ([]byte, error) {
	// check the derived key length
	if int64(hash.Size()) < dkLen {
		return nil, errors.New("error in PBKDF1 function: derived key too long")
	}

	// check if derived key length is negative
	if dkLen < 0 {
		return nil, errors.New("error in PBKDF1 function: derived key length must not be negative")
	}

	// check if iteration count is negative
	if c <= 0 {
		return nil, errors.New("error in PBKDF1 function: iteration count must not be negative")
	}

	// create a slice to hold the initial T
	T := append(make([]byte, len(P)+len(S)))

	// copy the password and salt to the slice
	copy(T, P)
	copy(T[len(P):], S)

	// create the PRF(pseudo-random function)
	PRF := hash.New()

	// iterate c(iteration count) times
	for i := int64(0); i < c; i++ {
		// write T to the PRF
		n, err := PRF.Write(T)

		// check for errors/incomplete writes
		if err != nil {
			return nil, fmt.Errorf("error in PBKDF1 function while writing to PRF: %s", err.Error())
		} else if n != len(T) {
			// problem writing(incomplete write)
			return nil, fmt.Errorf("error in PBKDF1 function while writing to PRF: incomplete write to PRF")
		}

		// save the hash to T
		T = PRF.Sum(nil)

		// reset the PRF
		PRF.Reset()
	}

	// return the derived key(DK)
	return T[:dkLen], nil
}

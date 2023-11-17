package pbkdf

import (
	"crypto"
	"errors"
	"fmt"
)

// PBKDF2 is a function that implements the PBKDF2 algorithm
// It is based on the RFC8018(https://datatracker.ietf.org/doc/html/rfc8018)
// it implements the PBKDF function type
func PBKDF2(hash crypto.Hash, P []byte, S []byte, c int64, dkLen int64) ([]byte, error) {
	// hash length
	hLen := int64(hash.Size())

	// max key length
	maxKeyLen := (int64(1<<32) - int64(1)) * hLen

	// check if dkLen is less than maxKeyLen
	if dkLen > maxKeyLen {
		return nil, errors.New("error in PBKDF2 function: derived key too long")
	}

	// check if derived key length is negative
	if dkLen < 0 {
		return nil, errors.New("error in PBKDF2 function: derived key length must not be negative")
	}

	// check if iteration count is negative
	if c <= 0 {
		return nil, errors.New("error in PBKDF2 function: iteration count must not be negative")
	}

	// calculate parameters l and r
	l := dkLen / hLen
	r := dkLen % hLen

	// if r is not zero increase l
	if r != 0 {
		l++
	}

	// make slice to hold the derived key(DK)
	DK := make([]byte, dkLen)

	// create PRF(pseudo-random function)
	PRF := hash.New()

	// F function => F(P, S, c, i), P, S, c are passed through closures
	F := func(i int64) ([]byte, error) {
		// start last iterations U as S + int32(i)[little endian]
		lastU := make([]byte, len(S)+4)

		// copy salt
		copy(lastU, S)

		// set int32(i) bytes
		copy(lastU[len(S):], ConvertUnsignedIntegerToByteSlice(uint64(i), 4, false))

		// create slice to hold result
		result := make([]byte, hLen)

		// iterate c(iteration count) times
		for j := int64(0); j < c; j++ {
			// write password
			n, err := PRF.Write(P)

			// handle errors/incomplete writes
			if err != nil {
				return nil, fmt.Errorf("error in PBKDF2 function while writing to PRF: %s", err.Error())
			} else if n != len(P) {
				return nil, fmt.Errorf("error in PBKDF2 function while writing to PRF: incomplete write to PRF")
			}

			// write last U
			n, err = PRF.Write(lastU)

			// handle errors/incomplete writes
			if err != nil {
				return nil, fmt.Errorf("error in PBKDF2 function while writing to PRF: %s", err.Error())
			} else if n != len(lastU) {
				return nil, fmt.Errorf("error in PBKDF2 function while writing to PRF: incomplete write to PRF")
			}

			// set lastU as the hash of P || lastU
			lastU = PRF.Sum(nil)

			// bitwise XOR the result with last U
			for k := 0; k < len(result); k++ {
				result[k] ^= lastU[k]
			}

			// reset PRF
			PRF.Reset()
		}

		// return the result
		return result, nil
	}

	// current index of the DK slice
	currIndex := int64(0)
	// iterate calling F l times
	// if 1 <= i < l, append the result of F(P, S, c, i)
	for i := int64(1); i < l; i++ {
		f, err := F(i)

		if err != nil {
			return nil, err
		}

		// append F to DK
		copy(DK[currIndex:], f)
		// current index += hLne
		currIndex += hLen
	}

	f, err := F(l)

	if err != nil {
		return nil, err
	}

	if r == 0 {
		// if r is zero append last block
		copy(DK[currIndex:], f)
	} else {
		// if r is diferent than zero, append first r bytes of F(P, S, c, l)
		copy(DK[currIndex:], f[:r])
	}

	// return the derived key(DK)
	return DK, nil
}

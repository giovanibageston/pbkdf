package pbkdf

import (
	"crypto"
	"fmt"
)

// VerifyPasswordPBKDF1 checks if a password matches an encoded password
// The encoded password must be in the format: salt:iterationCount:hashedPassword(salt and hashedPassword are base64 encoded)
// The hash parameter is the hash function to be used(can be any crypto.Hash)
// The password parameter is the password to be checked
// The encodedPassword parameter is the encoded password
func VerifyPasswordPBKDF1(hash crypto.Hash, password, encodedPassword string) (bool, error) {
	return VerifyPassword(hash, password, encodedPassword, PBKDF1)
}

// VerifyPasswordPBKDF2 checks if a password matches an encoded password
// The encoded password must be in the format: salt:iterationCount:hashedPassword(salt and hashedPassword are base64 encoded)
// The hash parameter is the hash function to be used(can be any crypto.Hash)
// The password parameter is the password to be checked
// The encodedPassword parameter is the encoded password
func VerifyPasswordPBKDF2(hash crypto.Hash, password, encodedPassword string) (bool, error) {
	return VerifyPassword(hash, password, encodedPassword, PBKDF2)
}

// VerifyPassword checks if a password matches an encoded password
// The encoded password must be in the format: salt:iterationCount:hashedPassword(salt and hashedPassword are base64 encoded)
// The hash parameter is the hash function to be used(can be any crypto.Hash)
// The password parameter is the password to be checked
// The encodedPassword parameter is the encoded password
// The function parameter is the function that has been used to generate the encoded password
// it must have the PBKDF signature
func VerifyPassword(hash crypto.Hash, password, encodedPassword string, kdf PBKDF) (bool, error) {
	// get the password parameters
	saltAsBytes, iterationCount, passwordHash, err := GetPasswordParametersFromString(encodedPassword)

	// check if an error occurred
	if err != nil {
		return false, fmt.Errorf("error in VerifyPassword kdf while getting password parameters: %s", err.Error())
	}

	// transform the password into a byte slice
	passwordAsBytes := []byte(password)

	// encode the password
	passwordHash2, err := kdf(hash, passwordAsBytes, saltAsBytes, iterationCount, int64(len(passwordHash)))

	// check if an error occurred
	if err != nil {
		return false, fmt.Errorf("error in VerifyPassword kdf while encoding password: %s", err.Error())
	}

	// check if the hashes have same length
	if len(passwordHash) != len(passwordHash2) {
		return false, nil
	}

	// check if the hashes are equal
	for i, v := range passwordHash {
		if v != passwordHash2[i] {
			// bytes are not equal, return false
			return false, nil
		}
	}

	// return true
	return true, nil
}

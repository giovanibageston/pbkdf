package pbkdf

import (
	"crypto"
	"fmt"
)

// EncodePasswordPBKDF1 encodes a password using PBKDF1 algorithm
// The encoded password is returned in the format: salt:iterationCount:hashedPassword(salt and hashedPassword are base64 encoded)
// the hash parameter is the hash function to be used(can be any crypto.Hash)
// The saltLength parameter is the length of the salt in bytes
// The iterationCount parameter is the number of iterations
// The keyLength parameter is the length of the derived key in bytes
func EncodePasswordPBKDF1(hash crypto.Hash, password string, saltLength, iterationCount, keyLength int64) (string, error) {
	return EncodePassword(hash, password, saltLength, iterationCount, keyLength, PBKDF1)
}

// EncodePasswordPBKDF2 encodes a password using PBKDF2 algorithm
// The encoded password is returned as a string in the format: salt:iterationCount:hashedPassword(salt and hashedPassword are base64 encoded)
// The hash parameter is the hash function to be used(can be any crypto.Hash)
// The saltLength parameter is the length of the salt in bytes
// The iterationCount parameter is the number of iterations
// The keyLength parameter is the length of the derived key in bytes
func EncodePasswordPBKDF2(hash crypto.Hash, password string, saltLength, iterationCount, keyLength int64) (string, error) {
	return EncodePassword(hash, password, saltLength, iterationCount, keyLength, PBKDF2)
}

// EncodePassword encodes a password using the given algorithm
// The encoded password is returned as a string in the format: salt:iterationCount:hashedPassword(salt and hashedPassword are base64 encoded)
// The hash parameter is the hash function to be used(can be any crypto.Hash)
// The saltLength parameter is the length of the salt in bytes
// The iterationCount parameter is the number of iterations
// The keyLength parameter is the length of the derived key in bytes
// The kdf parameter is the function used to generate the password key
// it must have the PBKDF signature
func EncodePassword(hash crypto.Hash, password string, saltLength, iterationCount, keyLength int64, kdf PBKDF) (string, error) {
	// transform the password into a byte slice
	passwordAsBytes := []byte(password)

	// generate a salt
	saltAsBytes, err := GenerateRandomSequence(int(saltLength))

	// check if an error occurred
	if err != nil {
		return "", fmt.Errorf("error in EncodePassword kdf while generating salt: %s", err.Error())
	}

	// encode the password
	encodedPassword, err := kdf(hash, passwordAsBytes, saltAsBytes, iterationCount, keyLength)

	// check if an error occurred
	if err != nil {
		return "", fmt.Errorf("error in EncodePassword kdf while encoding password: %s", err.Error())
	}

	// return the encoded password
	return GeneratePasswordString(saltAsBytes, iterationCount, encodedPassword), nil
}

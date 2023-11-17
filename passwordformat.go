package pbkdf

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// GeneratePasswordString generates a password string from the given parameters
// The salt parameter is the salt as a byte slice
// The iterationCount parameter is the iteration count
// The encodedPassword parameter is the encoded password as a byte slice
// The password string is returned in the format: salt:iterationCount:encodedPassword(salt and encodedPassword are base64 encoded)
func GeneratePasswordString(salt []byte, iterationCount int64, encodedPassword []byte) string {
	return fmt.Sprintf("%s:%d:%s", base64.StdEncoding.EncodeToString(salt), iterationCount, base64.StdEncoding.EncodeToString(encodedPassword))
}

// GetPasswordParametersFromString gets the password parameters from a password string
// the encodedPassword parameter is the password string
// the string must be in the format: salt:iterationCount:encodedPassword(salt and encodedPassword are base64 encoded)
// the salt, iterationCount and encodedPassword parameters are returned in this order
// the salt and encodedPassword parameters are byte slices
func GetPasswordParametersFromString(encodedPassword string) ([]byte, int64, []byte, error) {
	// split the encodedPassword string
	passwordSplit := strings.Split(encodedPassword, ":")

	// check if the encodedPassword string is valid
	if len(passwordSplit) != 3 {
		err := fmt.Errorf("error in GetPasswordParametersFromString function: encodedPassword must contain the salt, iteration count and encoded encodedPassword separated by colons")
		return nil, 0, nil, err
	}

	// decode the salt
	saltAsbytes, err := base64.StdEncoding.DecodeString(passwordSplit[0])

	// check if an error occurred
	if err != nil {
		return nil, 0, nil, fmt.Errorf("error in GetPasswordParametersFromString function while decoding salt: %s", err.Error())
	}

	// decode the iteration count
	iterationCount, err := strconv.ParseInt(passwordSplit[1], 10, 64)

	// check if an error occurred
	if err != nil {
		return nil, 0, nil, fmt.Errorf("error in GetPasswordParametersFromString function while decoding iteration count: %s", err.Error())
	}

	// decode the encoded encodedPassword
	passwordHash, err := base64.StdEncoding.DecodeString(passwordSplit[2])

	// check if an error occurred
	if err != nil {
		return nil, 0, nil, fmt.Errorf("error in GetPasswordParametersFromString function while decoding encoded encodedPassword: %s", err.Error())
	}

	// return the encodedPassword parameters
	return saltAsbytes, iterationCount, passwordHash, nil
}

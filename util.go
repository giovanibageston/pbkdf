package pbkdf

import (
	"crypto/rand"
	"fmt"
)

// GenerateRandomSequence generates a random sequence of bytes with the given length.
// The length parameter is the length of the random sequence in bytes
// this function uses the crypto/rand package
func GenerateRandomSequence(length int) ([]byte, error) {
	// create a slice of bytes with the given length to hold the random sequence
	seq := make([]byte, length)

	// fill the slice with random bytes
	if n, err := rand.Read(seq); err != nil {
		return nil, fmt.Errorf("error in GenerateRandomSequence function while generating random sequence: %s", err.Error())
	} else if n != length {
		return nil, fmt.Errorf("error in GenerateRandomSequence function: number of bytes read is not equal to the length of the random sequence")
	}

	// return the random sequence
	return seq, nil
}

// GenerateRandomByte generates a random byte with value between min and max
// The min parameter is the minimum value of the random byte
// The max parameter is the maximum value of the random byte
// The random byte is returned
func GenerateRandomByte(min, max byte) (byte, error) {
	// get a random seed
	randomSeed, err := GenerateRandomSequence(1)

	// check if an error occurred
	if err != nil {
		return 0, fmt.Errorf("error in GenerateRandomByte function while generating random seed: %s", err.Error())
	}

	// return the random byte between min and max
	return randomSeed[0]%(max-min+1) + min, nil
}

// GenerateRandomInt64 generates a random int64 with value between min and max
// The min parameter is the minimum value of the random int64
// The max parameter is the maximum value of the random int64
// The random int64 is returned
func GenerateRandomInt64(min, max int64) (int64, error) {
	// get a random seed
	randomSeed, err := GenerateRandomSequence(8)

	// check if an error occurred
	if err != nil {
		return 0, fmt.Errorf("error in GenerateRandomInt64 function while generating random seed: %s", err.Error())
	}

	// convert the random seed to an int64
	randomSeedAsInt64 := ConvertSliceToUnsignedInteger(randomSeed, false)

	// return the random int64 between min and max
	return int64(randomSeedAsInt64%uint64(max-min+1)) + min, nil
}

// valid runes for password generation
var passwordRunes = []rune("!@#$%&*()-_+=[]{}^~?/:;<>.,abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

// GenerateRandomPassword generates a random password
// The minLength parameter is the minimum length of the password
// The maxLength parameter is the maximum length of the password
// The password is returned as a string
// this function uses a built-in slice of runes for password generation
// to generate a password with a custom set of runes, use the GenerateRandomPasswordFromRunes function
func GenerateRandomPassword(minLength, maxLength int) (string, error) {
	return GenerateRandomPasswordFromRunes(minLength, maxLength, passwordRunes)
}

// GenerateRandomPassword generates a random password
// The minLength parameter is the minimum length of the password
// The maxLength parameter is the maximum length of the password
// The password is returned as a string
func GenerateRandomPasswordFromRunes(minLength, maxLength int, passwordRunes []rune) (string, error) {
	if maxLength < minLength {
		return "", fmt.Errorf("error in GenerateRandomPasswordFromRunes function: maxLength must be greater than minLength")
	}

	if minLength < 0 {
		return "", fmt.Errorf("error in GenerateRandomPasswordFromRunes function: minLength must not be negative")
	}

	// get random password length
	passwordLength, err := GenerateRandomInt64(int64(minLength), int64(maxLength))

	if err != nil {
		return "", fmt.Errorf("error in GenerateRandomPasswordFromRunes function while generating password length: %s", err.Error())
	}

	// create a slice of runes to hold the password
	passwordAsRunes := make([]rune, passwordLength)

	// fill the slice with random runes
	for i := range passwordAsRunes {
		// generate random rune
		r, err := GetRandomRune(passwordRunes)

		// check if an error occurred
		if err != nil {
			return "", fmt.Errorf("error in GenerateRandomPasswordFromRunes function while generating random rune: %s", err.Error())
		}

		// set the rune
		passwordAsRunes[i] = r
	}

	// return the password as a string
	return string(passwordAsRunes), nil
}

// GetRandomRune gets a random rune from a slice of runes
// The validRunes parameter is the slice of runes to get the random rune from
// The random rune is returned
func GetRandomRune(validRunes []rune) (rune, error) {
	// check if validRunes is not nil or empty
	if validRunes == nil || len(validRunes) == 0 {
		return 0, fmt.Errorf("error in GetRandomRune function: validRunes must not be nil or empty")
	}

	// get a random index
	randomIndex, err := GenerateRandomInt64(0, int64(len(validRunes)-1))

	// check if an error occurred
	if err != nil {
		return 0, fmt.Errorf("error in GetRandomRune function while generating random index: %s", err.Error())
	}

	// return the random rune
	return validRunes[randomIndex], nil
}

// ConvertUnsignedIntegerToByteSlice converts an unsigned integer to a byte slice
// The integer parameter is the integer to be converted
// The byteLength parameter is the length of the byte slice
// The bigEndian parameter indicates if the byte slice should be big endian
// The byte slice is returned
func ConvertUnsignedIntegerToByteSlice(integer uint64, byteLength int, bigEndian bool) []byte {
	// create a byte slice to hold the integer
	b := make([]byte, byteLength)

	// check if big endian
	if !bigEndian {
		// number of bits to shift
		shiftCount := byteLength * 8

		// loop through the bytes
		for i := 0; i < byteLength; i++ {
			// reduce the shift count
			shiftCount -= 8
			// shift the integer and store it in the byte slice
			b[i] = byte(integer >> shiftCount)
		}
	} else {
		// number of bits to shift
		shiftCount := 0

		// loop through the bytes
		for i := 0; i < byteLength; i-- {
			// shift the integer and store it in the byte slice
			b[i] = byte(integer >> shiftCount)
			// reduce the shift count
			shiftCount += 8
		}
	}

	// return the byte slice
	return b
}

// ConvertByteSliceToUnsignedInteger converts a byte slice to an unsigned integer
// The slice parameter is the byte slice to be converted
// The bigEndian parameter indicates if the byte slice is big endian
// The integer is returned
func ConvertSliceToUnsignedInteger(slice []byte, bigEndian bool) uint64 {
	// get the byteLength of the integer
	byteLength := len(slice)
	// create a uint64 to hold the integer
	integer := uint64(0)

	// check if big endian
	if !bigEndian {
		// shift count
		shiftCount := 8 * byteLength

		// loop through the bytes
		for i := 0; i < byteLength; i++ {
			// reduce the shift count
			shiftCount -= 8
			// shift the value of the current byte and add it to the integer
			integer += uint64(slice[i]) << shiftCount
		}
	} else {
		// shift count
		shiftCount := 0

		// loop through the bytes
		for i := 0; i < byteLength; i++ {
			// shift the value of the current byte and add it to the integer
			integer += uint64(slice[i]) << shiftCount
			// increase the shift count
			shiftCount += 8
		}
	}

	// return value as uint64
	return integer
}

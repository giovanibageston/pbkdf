package pbkdf

import (
	"crypto"
	"testing"
)

// tests the EncodePasswordPBKDF1, EncodePasswordPBKDF2, VerifyPasswordPBKDF1 and VerifyPasswordPBKDF2 functions
func TestEncodeDecodePassword(t *testing.T) {
	// 32 rounds of tests
	for i := 0; i < 32; i++ {
		// generate a random password with length between 8 and 32
		password, err := GenerateRandomPassword(8, 32)

		// check for error on password generation
		if err != nil {
			t.Errorf("error in TestEncodePassword function while generating password: %s", err.Error())
		}

		// generate random key length between 8 and 20 bytes
		keyLen, err := GenerateRandomByte(8, 20)

		// check for error on key length generation
		if err != nil {
			t.Errorf("error in TestEncodePassword function while generating key length: %s", err.Error())
		}

		// generate random iteration count between 1024 and 1048576
		iterationCount, err := GenerateRandomInt64(1024, 1048576)

		// check for error on iteration count generation
		if err != nil {
			t.Errorf("error in TestEncodePassword function while generating iteration count: %s", err.Error())
		}

		// generate random salt length between 8 and 32 bytes
		saltLen, err := GenerateRandomByte(8, 32)

		// check for error on salt length generation
		if err != nil {
			t.Errorf("error in TestEncodePassword function while generating salt length: %s", err.Error())
		}

		// encode the password(PBKDF1)
		encodedPBKDF1, err := EncodePasswordPBKDF1(crypto.SHA1, password, int64(saltLen), iterationCount, int64(keyLen))

		// check for error on password encoding
		if err != nil {
			t.Errorf("error in TestEncodePassword function while encoding password: %s", err.Error())
		}

		// check the encoded password
		valid, err := VerifyPasswordPBKDF1(crypto.SHA1, password, encodedPBKDF1)

		// check for error on password checking
		if err != nil || !valid {
			t.Errorf("error in TestEncodePassword function: encoded password is not valid")
		}

		// generate random key length between 16 and 128 bytes
		keyLen, err = GenerateRandomByte(32, 128)

		// check for error on key length generation
		if err != nil {
			t.Errorf("error in TestEncodePassword function while generating key length: %s", err.Error())
		}

		// generate random iteration count between 1024 and 1048576
		iterationCount, err = GenerateRandomInt64(1024, 1048576)

		// check for error on iteration count generation
		if err != nil {
			t.Errorf("error in TestEncodePassword function while generating iteration count: %s", err.Error())
		}

		// generate random salt length between 8 and 32 bytes
		saltLen, err = GenerateRandomByte(16, 32)

		// check for error on salt length generation
		if err != nil {
			t.Errorf("error in TestEncodePassword function while generating salt length: %s", err.Error())
		}

		// encode the password(PBKDF2)
		encodedPBKDF2, err := EncodePasswordPBKDF2(crypto.SHA512, password, int64(saltLen), iterationCount, int64(keyLen))

		// check for error on password encoding
		if err != nil {
			t.Errorf("error in TestEncodePassword function while encoding password: %s", err.Error())
		}

		// check the encoded password
		valid, err = VerifyPasswordPBKDF2(crypto.SHA512, password, encodedPBKDF2)

		// check for error on password checking
		if err != nil || !valid {
			t.Errorf("error in TestEncodePassword function: encoded password is not valid")
		}
	}
}

// BenchmarkEncodePasswordPBKDF1 benchmarks the EncodePasswordPBKDF1 function
func BenchmarkEncodePasswordPBKDF1(b *testing.B) {
	// generate a slice of passwords
	passwords := make([]string, b.N)

	// generate random passwords
	for i := range passwords {
		passwords[i], _ = GenerateRandomPassword(8, 32)
	}

	// reset the timer
	b.ResetTimer()

	// encode the passwords
	for i := range passwords {
		// generate randon paraneters
		saltLen, _ := GenerateRandomByte(8, 32)
		iterationCount, _ := GenerateRandomInt64(1024, 1048576)
		keyLen, _ := GenerateRandomByte(8, 20)

		EncodePasswordPBKDF1(crypto.SHA1, passwords[i], int64(saltLen), iterationCount, int64(keyLen))
	}
}

// BenchmarkEncodePasswordPBKDF2 benchmarks the EncodePasswordPBKDF2 function
func BenchmarkEncodePasswordPBKDF2(b *testing.B) {
	// generate a slice of passwords
	passwords := make([]string, b.N)

	// generate random passwords
	for i := range passwords {
		passwords[i], _ = GenerateRandomPassword(8, 32)
	}

	// reset the timer
	b.ResetTimer()

	// encode the passwords
	for i := range passwords {
		// generate randon paraneters
		saltLen, _ := GenerateRandomByte(16, 32)
		iterationCount, _ := GenerateRandomInt64(1024, 1048576)
		keyLen, _ := GenerateRandomByte(32, 128)

		EncodePasswordPBKDF2(crypto.SHA512, passwords[i], int64(saltLen), iterationCount, int64(keyLen))
	}
}

// BenchmarkCheckPasswordPBKDF1 benchmarks the VerifyPasswordPBKDF1 function
func BenchmarkCheckPasswordPBKDF1(b *testing.B) {
	// generate a slice of passwords
	passwords := make([]string, b.N)

	// generate random passwords
	for i := range passwords {
		passwords[i], _ = GenerateRandomPassword(8, 32)
	}

	// generate a slice of encoded passwords
	encodedPasswords := make([]string, b.N)

	// encode the passwords
	for i := range encodedPasswords {
		// generate randon paraneters
		saltLen, _ := GenerateRandomByte(8, 32)
		iterationCount, _ := GenerateRandomInt64(1024, 1048576)
		keyLen, _ := GenerateRandomByte(8, 20)

		// generate the encoded password
		encodedPasswords[i], _ = EncodePasswordPBKDF1(crypto.SHA1, passwords[i], int64(saltLen), iterationCount, int64(keyLen))
	}

	// reset the timer
	b.ResetTimer()

	// check the passwords
	for i := range passwords {
		VerifyPasswordPBKDF1(crypto.SHA1, passwords[i], encodedPasswords[i])
	}
}

func BenchmarkCheckPasswordPBKDF2(b *testing.B) {
	// generate a slice of passwords
	passwords := make([]string, b.N)

	// generate random passwords
	for i := range passwords {
		passwords[i], _ = GenerateRandomPassword(8, 32)
	}

	// generate a slice of encoded passwords
	encodedPasswords := make([]string, b.N)

	// encode the passwords
	for i := range encodedPasswords {
		// generate randon paraneters
		saltLen, _ := GenerateRandomByte(16, 32)
		iterationCount, _ := GenerateRandomInt64(1024, 1048576)
		keyLen, _ := GenerateRandomByte(32, 128)

		// generate the encoded password
		encodedPasswords[i], _ = EncodePasswordPBKDF2(crypto.SHA512, passwords[i], int64(saltLen), iterationCount, int64(keyLen))
	}

	// reset the timer
	b.ResetTimer()

	// check the passwords
	for i := range passwords {
		VerifyPasswordPBKDF2(crypto.SHA512, passwords[i], encodedPasswords[i])
	}
}

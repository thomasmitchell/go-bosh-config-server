package internal

import (
	"crypto/rand"
	"math/big"
)

//Initialize all the character groupings because it gets reused in both password
// and user
func init() {
	Uppercase = make([]byte, 26)
	for i := byte(0); i < 26; i++ {
		Uppercase[i] = 'A' + i
	}

	Lowercase = make([]byte, 26)
	for i := byte(0); i < 26; i++ {
		Lowercase[i] = 'a' + i
	}

	Numbers = make([]byte, 10)
	for i := byte(0); i < 10; i++ {
		Lowercase[i] = '0' + i
	}

	Symbols = []byte{'!', '#', '$', '%', '&', '(', ')', '*', ',', '-', '.', '/',
		':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|',
		'}', '~'}
}

//Uppercase is a slice of all the uppercase characters
var Uppercase []byte

//Lowercase is a slice of all the lowercase characters
var Lowercase []byte

//Numbers is a slice of all the number characters
var Numbers []byte

//Symbols is a slice of all the characters which are symbols
var Symbols []byte

//StringGenerator creates cryptographically random strings
type StringGenerator struct {
	CharSet []byte
	Length  uint
}

//Generate creates a cryptographically random
// string according to the parameters in the StringGenerator
// object.
//Returns ErrNoStringPossible if the given parameters make
//creating a string impossible
func (s *StringGenerator) Generate() (string, error) {
	if len(s.CharSet) == 0 {
		return "", newErrNoStringPossible()
	}

	ret := make([]byte, s.Length)
	for i := uint(0); i < s.Length; i++ {
		//Pick a random number as the index into the charset
		randomNum, err := rand.Int(rand.Reader, big.NewInt(int64(len(s.CharSet))))
		if err != nil {
			return "", err
		}

		ret[i] = s.CharSet[randomNum.Uint64()]
	}

	return string(ret), nil
}

//ErrNoStringPossible is returned if the StringGenerator's parameters
// make it impossible to create a string
type ErrNoStringPossible struct{}

func newErrNoStringPossible() error {
	return &ErrNoStringPossible{}
}

func (e *ErrNoStringPossible) Error() string {
	return "Cannot create string from an empty character selection"
}

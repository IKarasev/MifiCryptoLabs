package permutation

import (
	"fmt"
	"strings"
)

type Cypher struct {
	positions []int
	size      int
}

type CypherError struct {
	m string
}

func (c CypherError) Error() string {
	return "Cypher Error: " + c.m
}

func CheckPositions(pos []int) error {
	l := len(pos) - 1
	hash := map[int]bool{}
	for i, v := range pos {
		if v < 0 || v > l {
			return CypherError{fmt.Sprintf("Wrong position value [%d] at index %d", v, i)}
		}
		if hash[v] {
			return CypherError{fmt.Sprintf("Position duplicate [%d] at index %d", v, i)}
		}
		hash[v] = true
	}
	return nil
}

// Creates permutation encriptor object
// input:
//
//	pos []int - list of position permutations,
//	            where index is original position
//	            and value is new position
func NewEncriptor(pos []int) (*Cypher, error) {
	if err := CheckPositions(pos); err != nil {
		return nil, err
	}
	return &Cypher{pos, len(pos)}, nil
}

// Pads text with spaces to c.size length
// if istring's legth < c.size
func (c *Cypher) padText(s string) string {
	ls := len(s)
	if ls < c.size {
		s = s + strings.Repeat(" ", c.size-ls)
	}
	return s
}

func (c *Cypher) Encrypt(s string) string {
	s = c.padText(s)
	ls := len(s)
	encripted := make([]byte, ls)
	for n := 0; n < ls; n += c.size {
		for i := 0; i < c.size; i++ {
			encripted[n+i] = s[n+c.positions[i]]
		}
	}
	return strings.TrimRight(string(encripted), " ")
}

func (c *Cypher) Decrypt(s string) string {
	s = c.padText(s)
	ls := len(s)
	decripted := make([]byte, ls)
	for n := 0; n < ls; n += c.size {
		for i, p := range c.positions {
			decripted[n+p] = s[n+i]
		}
	}
	return strings.Trim(string(decripted), " ")
}

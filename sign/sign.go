package sign

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/IKarasev/MifiCryptoLabs/helpers"
)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
)

type SignGOST struct {
	p, q, a, x, y *big.Int
}

type Sign struct {
	r, s string
}

type SignGOSTError struct {
	block, msg string
}

func (e SignGOSTError) Error() string {
	return "Sign GOST : " + e.block + " : " + e.msg
}

func (s *Sign) String() string {
	return fmt.Sprintf("(%s, %s)", s.r, s.s)
}

func NewSignGOST(p, q, a *big.Int) (*SignGOST, error) {
	// Check p
	if !p.ProbablyPrime(20) {
		return nil, SignGOSTError{"New Sign Gost", "p is not prime"}
	}

	// Check q
	if !q.ProbablyPrime(20) {
		return nil, SignGOSTError{"New Sign Gost", "q is not prime"}
	}

	pSubOne := new(big.Int).Sub(p, big.NewInt(1))
	if new(big.Int).Mod(pSubOne, q).Cmp(bigZero) != 0 {
		return nil, SignGOSTError{"New Sign Gost", "q is not prime divisor of p-1"}
	}

	// Check a
	if a.Cmp(bigOne) != 1 || a.Cmp(pSubOne) != -1 {
		return nil, SignGOSTError{"New Sign Gost", "a is not in range (1;p-1)"}
	}

	if new(big.Int).Exp(a, q, p).Cmp(bigOne) != 0 {
		return nil, SignGOSTError{"New Sign Gost", "a doesn't comply condition a^q mod p == 1"}
	}

	return &SignGOST{p, q, a, nil, nil}, nil
}

func NewSignGOSTInt64(p, q, a int64) (*SignGOST, error) {
	return NewSignGOST(big.NewInt(p), big.NewInt(q), big.NewInt(a))
}

// Generates sign keys
// if secret == nil, generates new random secret
func (s *SignGOST) GenKeys(secret *big.Int) error {
	if s.a == nil || s.p == nil || s.q == nil {
		return SignGOSTError{"Gen keys", "SignGOST is not complete"}
	}

	if secret == nil {
		sec, err := helpers.RandomBigInt(big.NewInt(2), s.q)
		if err != nil {
			return err
		}
		secret = sec
	} else {
		if secret.Cmp(bigOne) < 1 || secret.Cmp(s.q) > -1 {
			return SignGOSTError{"GenKeys", "secret session key not in range (1,q)"}
		}
	}
	s.x = new(big.Int).Set(secret)
	s.y = new(big.Int).Exp(s.a, secret, s.p)

	return nil
}

func (s *SignGOST) GenKeysInt64(secret int64) error {
	return s.GenKeys(big.NewInt(secret))
}

// Generates 1 bit count hash for given string
func (s *SignGOST) getOneBitHash(message string) int64 {
	ones := 0
	for _, c := range message {
		for _, b := range fmt.Sprintf("%b", c) {
			ones += bits.OnesCount32(uint32(b))
		}
	}
	h := int64(ones)
	if new(big.Int).Mod(big.NewInt(h), s.q).Cmp(bigZero) == 0 {
		h = 1
	}
	return h
}

// Generates sign for given message
func (s *SignGOST) CreateSign(message string) (*Sign, error) {
	if s.a == nil || s.p == nil || s.q == nil || s.x == nil {
		return nil, SignGOSTError{"Create sign", "SignGOST is not complete"}
	}
	h := big.NewInt(s.getOneBitHash(message))
	r1 := big.NewInt(0)
	s1 := big.NewInt(0)
	qPlusOne := new(big.Int).Add(s.q, bigOne)
	for r1.Cmp(bigZero) == 0 || s1.Cmp(bigZero) == 0 {
		k, err := helpers.RandomBigInt(bigOne, qPlusOne)
		if err != nil {
			return nil, err
		}
		r1.Exp(s.a, k, s.p).Mod(r1, s.q)
		s1.
			Mul(s.x, r1).
			Add(s1, new(big.Int).Mul(k, h)).
			Mod(s1, s.q)
	}
	return &Sign{r1.Text(16), s1.Text(16)}, nil
}

// Checks if sign is valid for given message
func (s *SignGOST) CheckSign(message string, sign *Sign) (bool, error) {
	if s.a == nil || s.p == nil || s.q == nil || s.y == nil {
		return false, SignGOSTError{"Sceck sign", "SignGOST is not complete"}
	}

	// check sign params
	r1, ok := new(big.Int).SetString(sign.r, 16)
	if !ok {
		return false, nil
	}

	s1, ok := new(big.Int).SetString(sign.s, 16)
	if !ok {
		return false, nil
	}

	if r1.Cmp(bigZero) <= 0 || r1.Cmp(s.q) >= 0 ||
		s1.Cmp(bigZero) <= 0 || s1.Cmp(s.q) >= 0 {
		return false, nil
	}

	// check sign itself
	h := big.NewInt(s.getOneBitHash(message))
	v := new(big.Int).Exp(
		h,
		new(big.Int).Sub(s.q, big.NewInt(2)),
		s.q,
	)
	z1 := new(big.Int).Mul(s1, v)
	z1.Mod(z1, s.q)
	z2 := new(big.Int).Sub(s.q, r1)
	z2.Mul(z2, v).Mod(z2, s.q)
	u := new(big.Int)
	u.
		Mul(
			new(big.Int).Exp(s.a, z1, nil),
			new(big.Int).Exp(s.y, z2, nil),
		).
		Mod(u, s.p).
		Mod(u, s.q)

	if u.Cmp(r1) == 0 {
		return true, nil
	}
	return false, nil
}

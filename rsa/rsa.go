package rsa

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/IKarasev/MifiCryptoLabs/helpers"
)

var (
	bigZero = big.NewInt(0)
	bigOne  = big.NewInt(1)
	bigTwo  = big.NewInt(2)
)

type Cypher struct {
	p, q, e, n, d *big.Int
}

type CypherError struct {
	b, msg string
}

func (e CypherError) Error() string {
	return fmt.Sprintf("Cypher error [%s]: %s", e.b, e.msg)
}

// Creates new cypher from p,q in big.Int type
func NewCypher(p, q *big.Int) (*Cypher, error) {
	if !p.ProbablyPrime(20) {
		return nil, CypherError{"NewCypher", "p isn't prime"}
	}

	if !q.ProbablyPrime(20) {
		return nil, CypherError{"NewCypher", "q isn't prime"}
	}

	c := Cypher{}
	c.p, c.q = p, q
	c.GenKeys()

	return &c, nil
}

// Creates RSA cypher from string params.
// p and q params are numbers in string formats.
// pBase and qBase identifies number base (2,8,10,16, etc.)
// that corresponding parameters are written in
func NewCypherString(p, q string, pBase, qBase int) (*Cypher, error) {
	pBig := new(big.Int)
	qBig := new(big.Int)
	if _, ok := pBig.SetString(p, pBase); !ok {
		return nil, CypherError{"NewCypher", "fail to create big.Int for p"}
	}
	if _, ok := qBig.SetString(q, qBase); !ok {
		return nil, CypherError{"NewCypher", "fail to create big.Int for q"}
	}
	return NewCypher(pBig, qBig)
}

// Creates RSA cypher from int64 params
func NewCypherInt64(p, q int64) (*Cypher, error) {
	return NewCypher(big.NewInt(p), big.NewInt(q))
}

// Creates new RSA cypher with generated p and q
//
// n - size of p and q in bits
func NewCypherGenerated(n int64) *Cypher {
	nBig := big.NewInt(n)
	min := new(big.Int).Add(
		new(big.Int).Exp(bigTwo, new(big.Int).Sub(nBig, bigOne), nil),
		bigOne,
	)
	max := new(big.Int).Sub(
		new(big.Int).Exp(bigTwo, nBig, nil),
		bigOne,
	)
	fmt.Print("Generating p and q... ")

	// Generate p
	pCandidate := new(big.Int)
	for true {
		pCandidate, _ = helpers.RandomBigInt(min, max)
		if !DivBySmallPrim(pCandidate) && pCandidate.ProbablyPrime(20) {
			break
		}
	}

	// Generate q
	qCandidate := new(big.Int)
	for true {
		qCandidate, _ = helpers.RandomBigInt(min, max)
		if qCandidate.Cmp(pCandidate) != 0 && !DivBySmallPrim(qCandidate) && qCandidate.ProbablyPrime(20) {
			break
		}
	}

	fmt.Print(" DONE\n")
	c := Cypher{p: pCandidate, q: qCandidate}

	// generate keys
	fmt.Print("Generating keys...")
	c.GenKeys()
	fmt.Print(" DONE\n")
	return &c
}

// Generates public and private key paire
func (cypher *Cypher) GenKeys() {
	cypher.n = new(big.Int).Mul(cypher.p, cypher.q)

	phi := new(big.Int).Mul(
		new(big.Int).Sub(cypher.p, bigOne),
		new(big.Int).Sub(cypher.q, bigOne),
	)

	bigThree := big.NewInt(3)
	tmp := new(big.Int)

	// gen e
	e := new(big.Int)
	if phi.Cmp(big.NewInt(65537)) == 1 {
		e = big.NewInt(65537)
	} else {
		e.Sub(phi, bigOne)
	}
	for e.Cmp(bigThree) == 1 {
		if !DivBySmallPrim(e) && e.ProbablyPrime(20) {
			if tmp.Mod(phi, e).Cmp(bigZero) != 0 {
				cypher.e = e
				break
			}
		}
		e.Sub(e, bigOne)
	}

	// gen d
	cypher.d = new(big.Int).ModInverse(e, phi)
}

// Encrypt given text. If public key is not generated - returns error
func (cypher *Cypher) Encrypt(in string) (string, error) {
	if _, err := cypher.GetPrivateKey(); err != nil {
		return "", err
	}
	encrypted := strings.Builder{}

	for _, c := range in {
		encChar := new(big.Int).Exp(
			big.NewInt(int64(c)),
			cypher.e,
			cypher.n,
		)
		encrypted.WriteString(encChar.Text(16))
		encrypted.WriteString(" ")
	}
	result := strings.TrimSpace(encrypted.String())
	return result, nil
}

// Decrypts given string. If public key is not generated - returns error
func (cypher *Cypher) Decrypt(in string) (string, error) {
	if _, err := cypher.GetPrivateKey(); err != nil {
		return "", err
	}
	decripted := strings.Builder{}
	for _, c := range strings.Split(in, " ") {
		if cBig, ok := new(big.Int).SetString(c, 16); ok {
			decChar := new(big.Int).Exp(cBig, cypher.d, cypher.n)
			decripted.WriteByte(byte(decChar.Int64()))
		} else {
			return "", CypherError{"Decrypt", "Invalid input"}
		}
	}
	return decripted.String(), nil
}

func (cypher *Cypher) GetPrivateKey() (struct{ p, q, d string }, error) {
	private := struct{ p, q, d string }{}
	if cypher.p == nil || cypher.q == nil || cypher.d == nil {
		return private, CypherError{"Private Key", "Not set"}
	}
	private.p = cypher.p.String()
	private.q = cypher.q.String()
	private.d = cypher.d.String()
	return private, nil
}

func (cypher *Cypher) GetBublicKey() (struct{ n, e string }, error) {
	pub := struct{ n, e string }{}
	if cypher.n == nil || cypher.e == nil {
		return pub, CypherError{"Pub Key", "Not set"}
	}
	pub.n = cypher.n.String()
	pub.e = cypher.e.String()
	return pub, nil
}

func DivBySmallPrim(n *big.Int) bool {
	SmallPrimes := []int64{
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
		31, 37, 41, 43, 47, 53, 59, 61, 67,
		71, 73, 79, 83, 89, 97, 101, 103,
		107, 109, 113, 127, 131, 137, 139,
		149, 151, 157, 163, 167, 173, 179,
		181, 191, 193, 197, 199, 211, 223,
		227, 229, 233, 239, 241, 251, 257,
		263, 269, 271, 277, 281, 283, 293,
		307, 311, 313, 317, 331, 337, 347, 349,
	}
	bigZero := big.NewInt(0)
	tmp := new(big.Int)
	for _, v := range SmallPrimes {
		if tmp.Mod(n, big.NewInt(v)).Cmp(bigZero) == 0 {
			return true
		}
	}
	return false
}

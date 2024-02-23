package labcases

import (
	"fmt"

	"github.com/IKarasev/MifiCryptoLabs/diffiehellman"
	"github.com/IKarasev/MifiCryptoLabs/permutation"
	"github.com/IKarasev/MifiCryptoLabs/rsa"
	"github.com/IKarasev/MifiCryptoLabs/sign"
)

const IN_TEXT string = `Well, if you're ever travelling in the North Country fair
Where the winds hit heavy
On the borderline
Please say hello
To the one who's there
Cause she was once a true love of mine`

// Test permutation encriptions from lab.
// pos - permutation positions, where index is original position, value - new position.
// if pos is nil - uses values from lab
func LabTestPermutation(pos []int) {
	fmt.Println("Start permutation test")
	in := "Mama mila ramu, ramu mila mama"
	if pos == nil {
		pos = []int{4, 3, 0, 1, 2}
	}
	p, err := permutation.NewEncriptor(pos)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Input text:\n%q\n\n", in)

	enc := p.Encrypt(in)
	fmt.Printf("encripted:\n%q\n\n", enc)
	dec := p.Decrypt(enc)
	fmt.Printf("decripted:\n%q\n", dec)
}

// Executes test from lab Diffie Hellman on eliptic curves
func LabTestDiffieHellma() {
	fmt.Println("-- Start Lab Case Diffie Hellman --")
	var (
		a, b, p, gx, gy int64 = 2, 3, 97, 3, 6
		k1, k2          int64 = 6, 10
	)

	dh, err := diffiehellman.NewCypherInt64(a, b, p, gx, gy)
	if err != nil {
		fmt.Println(err)
		return
	}
	pub1, priv1 := dh.GenKeyPair(k1)
	pub2, priv2 := dh.GenKeyPair(k2)

	fmt.Printf("# User 1 keys\npublic: %s\nprivate: %s\n", pub1, priv1)
	fmt.Printf("# User 2 keys\npublic: %s\nprivate: %s\n", pub2, priv2)

	fmt.Println("Secrets equal: ", priv1.Equal(priv2))
}

func LabTestRSA() {
	fmt.Println("---- Lab Test RSA ----")
	r, err := rsa.NewCypherInt64(127, 89)

	if err != nil {
		fmt.Println(err)
		return
	}

	TestRsa(r)

}

// Test RSA with generated parameters.
// n - size of p and q in bits
func TestRSAGenerated(n int64) {
	fmt.Printf("--- Test Generated RSA: %d ---\n", n)
	r := rsa.NewCypherGenerated(n)
	TestRsa(r)
}

func TestRsa(r *rsa.Cypher) {
	pub, err := r.GetBublicKey()
	if err != nil {
		fmt.Println(err)
		return
	}

	priv, err := r.GetPrivateKey()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Public key:\n%v\n\n", pub)
	fmt.Printf("Private key:\n%v\n\n", priv)

	enc, err := r.Encrypt(IN_TEXT)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Input text:\n%s\n\nencrypted:\n%s\n\n", IN_TEXT, enc)

	dec, err := r.Decrypt(enc)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Decripted == input: %v\n", IN_TEXT == dec)
}

func LabTestSignature() {
	fmt.Println("-- Lab Case Sign --")
	var (
		p, q, a int64 = 23, 11, 6
		private int64 = 8
	)
	s, err := sign.NewSignGOSTInt64(p, q, a)

	if err != nil {
		fmt.Println(err)
		return
	}

	err = s.GenKeysInt64(private)
	if err != nil {
		fmt.Println(err)
		return
	}

	sign, err := s.CreateSign(IN_TEXT)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Signature:\n%s\n", sign)
	fmt.Println("Signature check:")
	fmt.Println(s.CheckSign(IN_TEXT, sign))
}

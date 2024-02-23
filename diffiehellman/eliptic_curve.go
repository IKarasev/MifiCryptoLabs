package diffiehellman

import (
	"fmt"
	"math/big"
)

type ElipticCurve struct {
	a, b, p *big.Int
}

type ElipticCurveError struct {
	block, msg string
}

func (e *ElipticCurveError) Error() string {
	return "Eliptic Curve : " + e.block + " : " + e.msg
}

// New Eliptic Curve from int64 params
func NewElipticCurve(a, b, p int64) (*ElipticCurve, error) {
	return NewElipticCurveBigI(
		big.NewInt(a),
		big.NewInt(b),
		big.NewInt(p),
	)
}

// New Eliptic Curve from big.Int values
func NewElipticCurveBigI(a, b, p *big.Int) (*ElipticCurve, error) {
	if !p.ProbablyPrime(20) {
		return nil, &ElipticCurveError{"New Curve", "p is not prime"}
	}
	c := ElipticCurve{p: p}
	err := c.setAB(a, b)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Sets params of eliptic curve for cypher
// If a and b are bad params for eliptic curve - returns error
func (c *ElipticCurve) setAB(a, b *big.Int) error {
	checkA := new(big.Int)
	checkA.
		Exp(a, big.NewInt(3), nil).
		Mul(checkA, big.NewInt(4))
	checkB := new(big.Int)
	checkB.
		Mul(b, b).
		Mul(checkB, big.NewInt(27)).
		Mod(checkB, c.p)

	if new(big.Int).Add(checkA, checkB).String() != "0" {
		c.a, c.b = a, b
		return nil
	}
	return &ElipticCurveError{"Set A and B", "bad a,b params"}
}

// Checks if point is on curve
func (c *ElipticCurve) PointOnCurve(p *ElipticCurvePoint) bool {
	//y1 := (p.x*p.x*p.x + c.a*p.x + c.b) % c.p

	y1 := new(big.Int)
	y1.
		Exp(p.x, big.NewInt(3), nil).
		Add(y1, new(big.Int).Mul(c.a, p.x)).
		Add(y1, c.b).
		Mod(y1, c.p)

	//if p.y*p.y == y1 {
	if new(big.Int).Mul(p.y, p.y).Cmp(y1) == 0 {
		return true
	}
	return false
}

// Sums given points
func (c *ElipticCurve) SumPoints(p1, p2 *ElipticCurvePoint) *ElipticCurvePoint {

	if p1.IsZero() {
		return p2.Copy()
	}

	if p2.IsZero() {
		return p1.Copy()
	}

	m := new(big.Int)

	if p1.x.Cmp(p2.x) == 0 {
		modInv := new(big.Int).ModInverse(
			new(big.Int).Mul(p1.y, big.NewInt(2)),
			c.p,
		)
		m.
			Mul(p1.x, p1.x).
			Mul(m, big.NewInt(3)).
			Add(m, c.a).
			Mul(m, modInv).
			Mod(m, c.p)
	} else {
		//m = ((p1.y + p2.y) * PowMod(p1.x-p2.x, -1, c.p)) % c.p
		modInv := new(big.Int).ModInverse(
			new(big.Int).Sub(p1.x, p2.x),
			c.p,
		)
		m.
			Sub(p1.y, p2.y).
			Mul(m, modInv).
			Mod(m, c.p)
	}

	px := new(big.Int)
	px.
		Mul(m, m).
		Sub(px, p1.x).
		Sub(px, p2.x).
		Mod(px, c.p)
	py := new(big.Int)
	py.
		Sub(p1.x, px).
		Mul(py, m).
		Sub(py, p1.y).
		Mod(py, c.p)

	return &ElipticCurvePoint{px, py}
}

// // Multiplyes give point by a number
func (c *ElipticCurve) MultiplyPointNum(p *ElipticCurvePoint, n int64) *ElipticCurvePoint {
	q := ZeroPoint()
	p1 := p.Copy()
	for _, b := range fmt.Sprintf("%b", n) {
		if b == '1' {
			q = c.SumPoints(q, p1)
		}
		p1 = c.SumPoints(p1, p1)
	}
	return q
}

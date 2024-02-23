package diffiehellman

import (
	"fmt"
	"math/big"
)

type ElipticCurvePoint struct {
	x, y *big.Int
}

func NewPoint() *ElipticCurvePoint {
	return &ElipticCurvePoint{new(big.Int), new(big.Int)}
}

// New point from Int64
func NewPointInt(x, y int64) *ElipticCurvePoint {
	return &ElipticCurvePoint{
		big.NewInt(x),
		big.NewInt(y),
	}
}

func ZeroPoint() *ElipticCurvePoint {
	return &ElipticCurvePoint{big.NewInt(0), big.NewInt(0)}
}

func (p *ElipticCurvePoint) String() string {
	return fmt.Sprintf("(%s, %s)", p.x, p.y)
}

func (p *ElipticCurvePoint) Equal(p1 *ElipticCurvePoint) bool {
	return p.x.Cmp(p1.x) == 0 && p.y.Cmp(p1.y) == 0
}

func (p *ElipticCurvePoint) IsZero() bool {
	return p.x.String() == "0" && p.y.String() == "0"
}

func (p *ElipticCurvePoint) Copy() *ElipticCurvePoint {
	newP := ElipticCurvePoint{
		x: new(big.Int).Set(p.x),
		y: new(big.Int).Set(p.y),
	}
	return &newP
}

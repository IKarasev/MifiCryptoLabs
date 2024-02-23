package helpers

import (
	"crypto/rand"
	"errors"
	"math/big"
)

// Returns random positive big.Int number between min and max
// max > min >= 0
func RandomBigInt(min, max *big.Int) (*big.Int, error) {
	if min.Cmp(big.NewInt(0)) < 0 {
		return nil, errors.New("Error : Random Big Int : min < 0")
	}
	if min.Cmp(max) >= 0 {
		return nil, errors.New("Error : Random Big Int : min >= max")
	}

	rmax := new(big.Int).Sub(max, min)
	r, err := rand.Int(rand.Reader, rmax)
	if err != nil {
		return nil, err
	}
	r.Add(r, min)
	return r, nil
}

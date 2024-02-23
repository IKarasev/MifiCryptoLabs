package diffiehellman

type Cypher struct {
	curve *ElipticCurve
	g     *ElipticCurvePoint
}

type CypherError struct {
	block, msg string
}

func (e CypherError) Error() string {
	return "CypherError : " + e.block + " : " + e.msg
}

// Creates new cypher from int64 parameters
func NewCypherInt64(a, b, p, gx, gy int64) (*Cypher, error) {
	c := Cypher{}
	curve, err := NewElipticCurve(a, b, p)
	if err != nil {
		return nil, err
	}
	c.curve = curve
	g := NewPointInt(gx, gy)
	if c.curve.PointOnCurve(g) {
		c.g = g
	} else {
		return nil, CypherError{"New Cypher", "bad point coordianates [x,y]"}
	}
	return &c, nil
}

// Generates public key
func (c *Cypher) GetPublicKey(secret int64) *ElipticCurvePoint {
	return c.curve.MultiplyPointNum(c.g, secret)
}

// Generates private key
func (c *Cypher) GetPrivateKey(secret int64, pubKey *ElipticCurvePoint) *ElipticCurvePoint {
	return c.curve.MultiplyPointNum(pubKey, secret)
}

func (c *Cypher) GenKeyPair(secret int64) (pub, priv *ElipticCurvePoint) {
	pub = c.GetPublicKey(secret)
	priv = c.GetPrivateKey(secret, pub)
	return
}

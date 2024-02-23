package mificryptolabs

import "github.com/IKarasev/MifiCryptoLabs/labcases"

var RSA_PQ_SIZE int64 = 256

// Run test cases from lab and little more.
// 0 - Premutations Cypher test case;
// 1 - Diffie Hellman on Eliptic Curve test case;
// 2 - Test RSA with generated parameters;
// 3 - Test RSA with lab data;
// 4 - Test Dgigtal Signature lab case;
func RunLabTestCase(n int) {
	switch n {
	case 0:
		labcases.LabTestPermutation(nil)
	case 1:
		labcases.LabTestDiffieHellma()
	case 2:
		labcases.LabTestRSA()
	case 3:
		labcases.TestRSAGenerated(RSA_PQ_SIZE)
	case 4:
		labcases.LabTestSignature()
	}
}

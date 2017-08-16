package main

import (
	"crypto/rand"
	"math/big"
)

func Mint() (CurvePoint, *big.Int, *big.Int) {
	r, e := rand.Int(rand.Reader, grouporder)
	Check(e)
	s, e := rand.Int(rand.Reader, grouporder)
	Check(e)
	c := Commit(s, r)
	return c, r, s
}

func Spend(r *big.Int, s *big.Int, msg string, c CurvePoint, cset []CurvePoint) ([]CurvePoint, *big.Int) {
	var l uint
	// inverse of com(s, 0)
	sinv := new(big.Int).Neg(s)
	comsinv := Commit(sinv, big.NewInt(0))
	var cprimes []CurvePoint
	for i := 0; i < len(cset); i++ {
		if cset[i] == c {
			l = uint(i)
		}
		ciprime := cset[i].Add(comsinv)
		cprimes = append(cprimes, ciprime)
	}

	proofa := SigmaCommit(cprimes, len(cset), l, r)
	challenge := []byte("i hate life")
	proofb := SigmaResponse(challenge)

	return proofa, proofb, s
}

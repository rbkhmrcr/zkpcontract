package main

import (
	"crypto/rand"
	// "fmt"
	"golang.org/x/crypto/sha3"
	"math/big"
	"strconv"
)

// Prover is the gk prover routine. it's needed in ring signatures and stuff.
// if Ring has a length (?) then we don't need to submit the length separately :)
func SigmaCommit(ring Ring, ringlength int, signerindex int, privatekey *big.Int) ([]CurvePoint, []*big.Int, *big.Int) {

	/* -----------------------------------------
	this is the first part of the sigma protocol
	----------------------------------------- */

	ringbin := strconv.FormatInt(int64(ringlength), 2)
	// TODO: check if the bitlength = n is correct!!
	n := uint(len(ringbin) + 1)
	randomvars := make([]*big.Int, 0)
	commitments := make([]CurvePoint, 0)
	// j is the bitwise index, always :) in the paper it's 1, ..., n, but we'll count from 0.
	for j := uint(0); j < n; j++ {
		// we could use a for loop here with i from 0 to 4 ?
		rj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, rj)
		// so r[j] will be randomvars[5*j]
		aj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, aj)
		// so a[j] will be randomvars[5*j + 1]
		sj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, sj)
		// so s[j] will be randomvars[5*j + 2]
		tj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, tj)
		// so t[j] will be randomvars[5*j + 3]
		rhok, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		randomvars = append(randomvars, rhok)
		// so rho[k] will be randomvars[5*j + 4]
		// should these actually not just use the variables aj, sj, etc, as they are still
		// set to the ones that are needed? is this lots of unnecessary array fetching?

		// clj = lj * g + rj * h
		bigintbit := big.NewInt(int64(((signerindex >> j) & 0x1)))
		newcommitment := Commit(bigintbit, randomvars[5*j])
		commitments = append(commitments, newcommitment)
		// clj will be commitments[3*j]

		// caj = aj * g + sj * h
		commitments = append(commitments, Commit(randomvars[5*j+1], randomvars[5*j+2]))
		// caj will be commitments[4*j + 1]

		// cbj = (lj * aj) * g + tj * h
		z := new(big.Int)
		ljaj := z.Mul(bigintbit, randomvars[5*j+1])
		ljaj = z.Mod(ljaj, grouporder)
		commitments = append(commitments, Commit(ljaj, randomvars[5*j+3]))
		// cbj will be commitments[4*j + 2]

		// cdk = (for i = 0, ..., N-1) p[i][k] * ci + 0 * g + rhok * h
		// product temp is p[i][k] * c[i]
		var producttemp CurvePoint
		for i := 0; i < ringlength; i++ {
			// polytemp is p[i][k]
			polytemp := PolynomialBuilder(signerindex, ringlength, i)
			// cdk lhs is p[i][k] * c[i] for a given i
			// fmt.Println("signerindex : ", signerindex)
			// fmt.Println("i : ", i)
			// fmt.Println("j : ", j)
			// fmt.Println("poly : ", polytemp)
			cdklhs := (ring.PubKeys[i]).ScalarMult(polytemp[j])

			if i == 0 {
				// each type we loop through the k and start on a new i we reset the product
				producttemp = ring.PubKeys[i].ScalarMult(polytemp[j])
			} else {
				// we're using EC points so multiplication is really addition
				// this is adding p[i][k] * c[i] to the previous ones (for given k)
				z := producttemp.Add(cdklhs)
				producttemp = z
			}
		}
		// cdk = above product + 0 * g + rho * h
		newcommitment = Commit(big.NewInt(0), randomvars[5*j+4])
		commitments = append(commitments, newcommitment.Add(producttemp))
		// cdk will be commitments[4*j + 3]
	}
}

	/* ------------------------------------
	this is where we generate the challenge
	------------------------------------ */

	// should we just carry on the loop above? who cares
	// we need to convert the challenge into a big int :(
	array := sha3.Sum256([]byte("lots of cool stuff including the commitments"))
	challenge := Convert(array[:])

	/* ------------------------------------------
	this is the second part of the sigma protocol
	------------------------------------------ */
func SigmaResponse(challenge *big.Int, ring Ring, ringlength int, signerindex int, privatekey *big.Int) ([]CurvePoint, []*big.Int, *big.Int) {

	var responses []*big.Int
	for j := uint(0); j < n; j++ {

		z := new(big.Int)
		// fj = lj * x + aj
		lj := big.NewInt(int64(((signerindex >> j) & 0x1)))
		fj := z.Mul(lj, challenge)
		fj = z.Mod(fj, grouporder)
		fj = z.Add(fj, randomvars[5*j+1])
		fj = z.Mod(fj, grouporder)
		// so fj = responses[3*j]
		responses = append(responses, fj)

		// zaj = rj * x + sj
		z = new(big.Int)
		zaj := z.Mul(randomvars[5*j], challenge)
		zaj = z.Mod(zaj, grouporder)
		zaj = z.Add(zaj, randomvars[5*j+2])
		zaj = z.Mod(zaj, grouporder)
		// so zaj = responses[3*j + 1]
		responses = append(responses, zaj)

		// zbj = rj * (x - fj) + tj
		z = new(big.Int)
		// x - fj
		zbj := z.Sub(challenge, fj)
		zbj = z.Mod(zbj, grouporder)
		// rj * (x - fj)
		zbj = z.Mul(randomvars[5*j], zbj)
		zbj = z.Mod(zbj, grouporder)
		// rj * (x - fj) + tj
		zbj = z.Add(zbj, randomvars[5*j+3])
		zbj = z.Mod(zbj, grouporder)
		// so zbj = responses[3*j + 2]
		responses = append(responses, zbj)

	}

	// zd = r * x ** n - sum from k = 0 to k = n - 1 of rhok * x ** k
	z := new(big.Int)
	ztemp := new(big.Int)
	zdsum := new(big.Int)

	// zd (lhs) = r * x ** n
	rxn := z.Exp(challenge, big.NewInt(int64(n)), grouporder)
	rxn = z.Mod(rxn, grouporder)
	rxn = z.Mul(rxn, privatekey)
	rxn = z.Mod(rxn, grouporder)

	for k := uint(0); k < n; k++ {
		z := new(big.Int)
		// x ** k
		xk := z.Exp(challenge, big.NewInt(int64(k)), grouporder)
		// zd = SUM( rhok * x ** k )
		zdelement := z.Mul(randomvars[5*k+4], xk)
		zdelement = z.Mod(zdelement, grouporder)
		// zd = sum over k of the above
		zdsum = z.Add(zdsum, zdelement)
		zdsum = z.Mod(zdsum, grouporder)
		ztemp = zdsum
	}

	zd := z.Sub(rxn, ztemp)
	zd = z.Mod(zd, grouporder)

	return commitments, responses, zd
}

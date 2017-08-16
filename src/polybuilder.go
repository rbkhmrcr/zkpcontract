package main

import (
	"crypto/rand"
	poly "github.com/jongukim/polynomial"
	"math/big"
	"strconv"
)

// PolynomialBuilder builds the weird polynomials we need in the GK proving algo
func PolynomialBuilder(signerindex int, ringsize int, currenti int) poly.Poly {

	// this is just to print and get the bit length, n
	// TODO: print this and see if its right
	// signerindexbin := strconv.FormatInt(int64(signerindex), 2)
	ringbin := strconv.FormatInt(int64(ringsize), 2)
	// the product should be of length = bitlength(ringsize)
	var product poly.Poly
	// the products of functions defined by each i form distinct polynomials (one per i)
	// this polynomial will have degree max bitlength(ringlength)

	// things need to be uint so the bitshifting works
	// len(ringbin) = n
	// ------------------------------------------------------------------------------
	// is it gonna cause problems that we're running 0 -> n - 1 rather than 1 -> n :(

	// j is the bit index.
	// the functions defined in this bit get multiplied together to form the poly above
	for j := uint(0); j < uint(len(ringbin)); j++ {

		var functiontemp poly.Poly
		aj, e := rand.Int(rand.Reader, grouporder)
		Check(e)
		z, e := rand.Int(rand.Reader, grouporder)
		Check(e)

		// we compare i (the current index) to l (the signer index), bitwise
		if (currenti >> j & 0x1) == 0 {
			if ((signerindex >> j) & 0x1) == 0 {
				// f = x - aj
				functiontemp = append(functiontemp, z.ModInverse(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(1))
			}
			if ((signerindex >> j) & 0x1) == 1 {
				// otherwise it's just - aj
				functiontemp = append(functiontemp, z.ModInverse(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(0))
			}
		}

		if (currenti >> j & 0x1) == 1 {
			if ((signerindex >> j) & 0x1) == 1 {
				// f = x + aj
				// this mod is super redundant
				functiontemp = append(functiontemp, z.Mod(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(1))
			}
			if ((signerindex >> j) & 0x1) == 0 {
				// otherwise it's just aj
				// this mod is super redundant
				functiontemp = append(functiontemp, z.Mod(aj, grouporder))
				functiontemp = append(functiontemp, big.NewInt(0))
			}
		}

		if j == 0 {
			// i should do this in some prettier way hey?
			// is there a way to make sure the polynomials are always a certain length
			// even is lots of entries are 0? :/
			product = poly.NewPolyInts(0)
			product = functiontemp
		} else {
			product = product.Mul(functiontemp, grouporder)
			product = append(product, big.NewInt(0))
			product = append(product, big.NewInt(0))
			product = append(product, big.NewInt(0))
			product = append(product, big.NewInt(0))
		}
	}
	return product
}

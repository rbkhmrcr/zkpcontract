package main

import (
	"crypto/rand"
	"math/big"
	"github.com/bitherhq/go-bither/crypto/bn256"
)

/*
To sign a message m:
	- Choose random k from F_order
	- Let r = g^k 
	- Let e = H ( r ∥ m )
	- Let s = k − x e (mod order)
	- signature = (s, e) 
*/

func main () {

	// read in message from stdio
	m := 
	// scalars from here
	order := bn256.Order
	// Choose random k from F_order
	k := bn256.RandScalar()
	// Let r = g^k 
	r := bn256.BaseMult(k)
	// Let e = H ( r ∥ m )
	e := Sha256.Digest(r)
	e = Sha256.Digest(m)
	// Let s = k − x e (mod order)
	s := 
	// print signature (s, e) to stdio 
	// (change these to rpcs using metamask?)


}



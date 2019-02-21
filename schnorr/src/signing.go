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

	// scalars from here
	bn256.Order

}



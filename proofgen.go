package main

import (
  secp "github.com/btcsuite/btcec"
  "crypto/sha256"
  "math/big"
)

func main() {
  var G *secp.KoblitzCurve = secp.S256()
  // We're going to create a nizp here. Exciting.
}

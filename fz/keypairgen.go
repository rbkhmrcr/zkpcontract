package main

import (
  secp "btcec"
  "crypto/rand"
  //"bytes"
  "fmt"
  //"math/big"
)

func main() {
  var G *secp.KoblitzCurve
  G = secp.S256()
  grouporder := G.N
  //fieldOrder := group.P

  for j := 0; j < 4; j++ {
    privkey, e := rand.Int(rand.Reader, grouporder)
    check(e)

    px, py := G.ScalarBaseMult(privkey.Bytes())
    fmt.Println(privkey, px, py)
  }
}

func check(e error) {
  if e != nil {
    panic(e) // This should probably return an error shouldn't it
  }
}

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	secp "github.com/btcsuite/btcd/btcec" // dependencies can be changed to my package is this is ever any better
	"golang.org/x/crypto/sha3"            // we need a hash function that isn't vuln to length extension attacks
	"io/ioutil"
	"log"
	"math/big"
	"os"
)

var Group *secp.KoblitzCurve

// Should i have these as just numbers now for simplicity/testing? i guess putting
// them in json is just as easy :) and better for testing!
type CurvePoint struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:'y"`
}

// Function to return stuff as strings so we can use them in eth transactions
func (c CurvePoint) String() string {
	return fmt.Sprintf("X: %s, Y: %s", c.X, c.Y)
}

func (c CurvePoint) ScalarBaseMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarBaseMult(x.Bytes())
	return CurvePoint{px, py}
}

func (c CurvePoint) ScalarMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarMult(c.X, c.Y, x.Bytes())
	return CurvePoint{px, py}
}

func (c CurvePoint) Add(y CurvePoint) CurvePoint {
	px, py := Group.Add(c.X, c.Y, y.X, y.Y)
	return CurvePoint{px, py}
}

type PubKeyStr struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type RingStr struct {
	PubKeys []PubKeyStr `json:"pubkeys"`
}

type PrivKeysStr struct {
	Keys []string `json:"privkeys"`
}

type PubKey struct {
	CurvePoint
}

type Ring struct {
	PubKeys []PubKey `json:"pubkeys"`
}

type RingSignature struct {
	Tau    CurvePoint `json:"tau"`
	Ctlist []*big.Int `json:"ctlist"`
}

type ContractJSON struct {
	keys   []*big.Int
	tau    []*big.Int
	ctlist []*big.Int
}

func (s RingSignature) String() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("tau: %s\n", s.Tau))
	buffer.WriteString(fmt.Sprintf("ctlist: [\n"))
	for i := 0; i < len(s.Ctlist); i++ {
		buffer.WriteString(fmt.Sprintf("\t%s\n", s.Ctlist[i]))
	}
	buffer.WriteString(fmt.Sprintf("]\n"))

	return buffer.String()
}

func (r Ring) String() string {
	var buffer bytes.Buffer

	for i := 0; i < len(r.PubKeys); i++ {
		buffer.WriteString(fmt.Sprintf("%s\n", r.PubKeys[i]))
	}

	return buffer.String()
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func init() {

	Group = secp.S256()
}

func (c CurvePoint) ParameterPointAdd(tj *big.Int, cj *big.Int) CurvePoint {
	a := CurvePoint{}.ScalarBaseMult(tj)
	pk := c.ScalarMult(cj)

	return a.Add(pk)
}

func (c CurvePoint) HashPointAdd(hashSP CurvePoint, tj *big.Int, cj *big.Int) CurvePoint {
	b := c.ScalarMult(tj)
	bj := hashSP.ScalarMult(cj)

	return b.Add(bj)
}

func SignAndVerify(Rn Ring, privBN *big.Int, message []byte) {

	pub := CurvePoint{}.ScalarBaseMult(privBN)
	signerNumber := keyCompare(pub, Rn)

	signature := RingSign(Rn, privBN, message, signerNumber)
	//fmt.Println(signature)

	verif := RingVerif(Rn, message, signature)
	//fmt.Println("Signature verification:", verif)
	if verif != true {
		fmt.Println(signature)
		log.Fatal("signature failed to verify")
	}

	var ct []*big.Int

	for i := 0; i < len(signature.Ctlist); i++ {
		ct = append(ct, signature.Ctlist[i])
	}

	ctJS, _ := json.MarshalIndent(ct, "", "\t")

	fmt.Println("[")
	fmt.Printf("\t%s,\n", signature.Tau.X)
	fmt.Printf("\t%s,\n", signature.Tau.Y)
	fmt.Printf("%s\n", string(ctJS))
	fmt.Println("],")

}

func main() {
	args := os.Args[1:]
	privkeyfile, err := ioutil.ReadFile("privkeys.json")
	pk := PrivKeysStr{}
	if err = json.Unmarshal(privkeyfile, &pk); err != nil {
		panic(err)
	}
	keyfile, _ := ioutil.ReadFile("pubkeys.json")
	rn := RingStr{}
	if err = json.Unmarshal(keyfile, &rn); err != nil {
		panic(err)
	}
	Rn := convertPubKeys(rn)
	//fmt.Println(Rn)
	// we need to find out which public key the private key corresponds to.

	var message []byte
	if len(args) > 0 {
		message, err = hex.DecodeString(args[0])
		//fmt.Println(hex.EncodeToString(message))
		if err != nil {
			panic(err)
		}
	}

	for i := 0; i < len(pk.Keys); i++ {
		privbytes, err := hex.DecodeString(pk.Keys[i])
		if err != nil {
			panic(err)
		}
		privBN := new(big.Int).SetBytes(privbytes)
		SignAndVerify(Rn, privBN, message)
	}
}

func RingSign(R Ring, ski *big.Int, m []byte, signer int) RingSignature {
	N := Group.N

	mR := RingToBytes(R)
	byteslist := append(mR, m...)
	hashp, _ := HashToCurve(byteslist)
	//fmt.Println("HashPoint:", hashp)
	ski.Mod(ski, N)
	hashSP := hashp.ScalarMult(ski)
	//fmt.Println("hashPoint^sk", hashSP)

	n := len(R.PubKeys)
	var ctlist []*big.Int
	var hashlist []*big.Int
	var a, b CurvePoint
	var ri *big.Int
	var e error
	csum := big.NewInt(0)

	for j := 0; j < n; j++ {

		if j != signer {
			cj, e := rand.Int(rand.Reader, N)
			check(e)
			tj, e := rand.Int(rand.Reader, N)
			check(e)

			a = R.PubKeys[j].ParameterPointAdd(tj, cj)

			b = hashp.HashPointAdd(hashSP, tj, cj)
			ctlist = append(ctlist, cj)
			ctlist = append(ctlist, tj)
			csum.Add(csum, cj)
		}

		if j == signer {
			dummy := big.NewInt(0)
			ctlist = append(ctlist, dummy)
			ctlist = append(ctlist, dummy)
			ri, e = rand.Int(rand.Reader, N)
			check(e)
			a = CurvePoint{}.ScalarBaseMult(ri)
			b = hashp.ScalarMult(ri)
		}
		hashlist = addtolist(hashlist, a.X, a.Y, b.X, b.Y, j)
	}
	for _, v := range hashlist {
		xx := v.Bytes()
		byteslist = append(byteslist, xx[:]...)
	}

	hasha := sha3.Sum256(byteslist)
	hashb := Convert(hasha[:])
	hashb.Mod(hashb, N)
	csum.Mod(csum, N)
	c := new(big.Int).Sub(hashb, csum)
	c.Mod(c, N)

	cx := new(big.Int).Mul(c, ski)
	cx.Mod(cx, N)

	ti := new(big.Int).Sub(ri, cx)
	ti.Mod(ti, N)
	ctlist[2*signer] = c
	ctlist[2*signer+1] = ti

	return RingSignature{hashSP, ctlist}
}

func RingVerif(R Ring, m []byte, sigma RingSignature) bool {
	// ring verification
	// assumes R = pk1, pk2, ..., pkn
	// sigma = H(m||R)^x_i, c1, t1, ..., cn, tn = taux, tauy, c1, t1, ..., cn, tn
	tau := sigma.Tau
	ctlist := sigma.Ctlist
	n := len(R.PubKeys)
	N := Group.N
	var hashlist []*big.Int

	mR := RingToBytes(R)
	byteslist := append(mR, m...)
	hashp, _ := HashToCurve(byteslist)
	csum := big.NewInt(0)

	//fmt.Println(len(ctlist))

	for j := 0; j < n; j++ {
		cj := ctlist[2*j]
		tj := ctlist[2*j+1]
		cj.Mod(cj, N)
		tj.Mod(tj, N)
		H := hashp.ScalarMult(tj)             //H(m||R)^t
		gt := CurvePoint{}.ScalarBaseMult(tj) //g^t
		yc := R.PubKeys[j].ScalarMult(cj)     // y^c = g^(xc)
		tauc := tau.ScalarMult(cj)            //H(m||R)^(xc)
		gt = gt.Add(yc)
		H = H.Add(tauc) // fieldJacobianToBigAffine `normalizes' values before returning so yes - normalize uses fast reduction using specialised form of secp256k1's prime! :D
		hashlist = addtolist(hashlist, gt.X, gt.Y, H.X, H.Y, j)
		csum.Add(csum, cj)
	}
	for _, v := range hashlist {
		xx := v.Bytes()
		byteslist = append(byteslist, xx[:]...)
	}

	hash := sha3.Sum256(byteslist)
	hashhash := Convert(hash[:])
	hashhash.Mod(hashhash, N)
	csum.Mod(csum, N)
	if csum.Cmp(hashhash) == 0 {
		return true
	}
	return false
}

func convertPubKeys(rn RingStr) Ring {

	rl := len(rn.PubKeys)
	//fmt.Println("Length : ", rl)
	var ring Ring

	for i := 0; i < rl; i++ {
		var bytesx []byte
		var bytesy []byte
		bytesx, _ = hex.DecodeString(string(rn.PubKeys[i].X))
		bytesy, _ = hex.DecodeString(string(rn.PubKeys[i].Y))
		pubkeyx := new(big.Int).SetBytes(bytesx) // This makes big int
		pubkeyy := new(big.Int).SetBytes(bytesy) // So we can do EC arithmetic
		ring.PubKeys = append(ring.PubKeys, PubKey{CurvePoint{pubkeyx, pubkeyy}})
	}
	return ring
}

func RingToBytes(rn Ring) []byte {
	var rbytes []byte
	for i := 0; i < len(rn.PubKeys); i++ {
		rbytes = append(rbytes, rn.PubKeys[i].X.Bytes()...)
	}
	for i := 0; i < len(rn.PubKeys); i++ {
		rbytes = append(rbytes, rn.PubKeys[i].Y.Bytes()...)
	}

	return rbytes
}

func addtolist(list []*big.Int, a *big.Int, b *big.Int, c *big.Int, d *big.Int, j int) []*big.Int {
	list = append(list, a)
	list = append(list, b)
	list = append(list, c)
	list = append(list, d)
	return list
}

func keyCompare(pub CurvePoint, R Ring) int {
	j := 0
	for i := 0; i < len(R.PubKeys); i++ {
		if pub.X.Cmp(R.PubKeys[i].X) == 0 && pub.Y.Cmp(R.PubKeys[i].Y) == 0 {
			j = i
		}
	}
	return j
}

func Convert(data []byte) *big.Int {
	z := new(big.Int)
	z.SetBytes(data)
	return z
}

func HashToCurve(s []byte) (CurvePoint, error) {
	q := Group.P

	x := big.NewInt(0)
	y := big.NewInt(0)
	z := big.NewInt(0)
	z.SetString("57896044618658097711785492504343953926634992332820282019728792003954417335832", 10)

	array := sha3.Sum256(s) // Sum outputs an array of 32 bytes :)
	x = Convert(array[:])
	for true {
		//s := []byte(str)
		//fmt.Println("x point: ", x)
		xcube := new(big.Int).Exp(x, big.NewInt(3), q)
		xcube7 := new(big.Int).Add(xcube, big.NewInt(7))
		y.ModSqrt(xcube7, q)
		y.Set(q)
		y.Add(y, big.NewInt(1))
		y.Rsh(y, 2)
		y.Exp(xcube7, y, q)
		//fmt.Println("y point: ", y)
		z = z.Exp(y, big.NewInt(2), q)
		curveout := Group.IsOnCurve(x, y)
		//fmt.Println("curve out: ", curveout)
		if curveout == true {
			return CurvePoint{x, y}, nil
		}
		x.Add(x, big.NewInt(1))
	}
	return CurvePoint{}, errors.New("no curve point found")
}

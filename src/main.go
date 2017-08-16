package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	secp "github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"math/big"
)

// Group is secp256k1 as defined in btcec
var Group = secp.S256()
var grouporder = Group.N

// H is an EC point with unknown DL
var H, _ = HashToCurve([]byte("i am a stupid moron"))

// we need a curve point type so that curve points are just one thing
// as opposed to being representing by their bigint affine coordinates x, y :)

// CurvePoint lets us use the bigint affine point rep as one var not two :)
type CurvePoint struct {
	X *big.Int `json:"x"`
	Y *big.Int `json:"y"`
}

// String takes a CurvePoint and converts to a string for pretty printing (& interfacing?)
func (c CurvePoint) String() string {
	return fmt.Sprintf("X: %s, Y: %s", c.X, c.Y)
}

// ScalarBaseMult lets us do g.mult(scalar) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) ScalarBaseMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarBaseMult(x.Bytes())
	return CurvePoint{px, py}
}

// ScalarMult lets us do point.mult(scalar) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) ScalarMult(x *big.Int) CurvePoint {
	px, py := Group.ScalarMult(c.X, c.Y, x.Bytes())
	return CurvePoint{px, py}
}

// Add lets us do point1.Add(point2) from btcec with CurvePoints rather than (x, y)
func (c CurvePoint) Add(y CurvePoint) CurvePoint {
	px, py := Group.Add(c.X, c.Y, y.X, y.Y)
	return CurvePoint{px, py}
}

// PrivKeysStr is an array of the private keys as strings
type PrivKeysStr struct {
	Keys []string `json:"privkeys"`
}

// PubKeyStr is a single public key, represented by its affine coords (as strings)
type PubKeyStr struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// RingStr is an array of PubKeyStrs, which are pubkeys as strings
type RingStr struct {
	PubKeys []PubKeyStr `json:"pubkeys"`
}

// PubKey = CurvePoint = affine, bigint representation of EC points
type PubKey struct {
	CurvePoint
}

// Ring is an array of PubKeys (bigint EC point coords). Acts as a list of public keys.
type Ring struct {
	PubKeys []PubKey `json:"pubkeys"`
}

func main() {

	// we should have a case where the public and private keys are
	// generated at random on the fly and stored in arrays rather than
	// read in from a json file. I think this'll be esssential for testing?

	// read in all the private keys
	privkeyfile, err := ioutil.ReadFile("privkeys.json")
	sk := PrivKeysStr{} // because all json files are read in as strings
	if err = json.Unmarshal(privkeyfile, &sk); err != nil {
		panic(err) // we should do better error handling lol
	}

	// read in all the public keys
	keyfile, _ := ioutil.ReadFile("pubkeys.json")
	pk := RingStr{}
	if err = json.Unmarshal(keyfile, &pk); err != nil {
		panic(err)
	}
	pubkeys := ConvertPubKeys(pk)
	privkey := big.NewInt(0)
	// ive just picked the 3rd (2nd counting from 0th) privkey here :)
	// why not just read it from the file ?????
	privkey.SetString("23246495091784532220524749001303194962250020895499760086019834032589186452479", 10)

	proofa, proofb, proofc := SigmaCommit(pubkeys, 3, 2, privkey)

	/* ------------------------------------
	this is where we generate the challenge
	------------------------------------ */
	// should we just carry on the loop above? who cares
	// we need to convert the challenge into a big int :(
	array := sha3.Sum256([]byte("lots of cool stuff including the commitments"))
	challenge := Convert(array[:])

	proofa, proofb, proofc, = SigmaResponse(challenge pubkeys, 3, 2, privkey)
	pv := Verify(pubkeys, 3, proofa, proofb, proofc)
	fmt.Println("verificaaaationnnnnnn : ", pv)
}

/* now we unwrap all the private keys
	for i := 0; i < len(sk.Keys); i++ {
		privbytes, err := hex.DecodeString(sk.Keys[i])
		if err != nil {
			panic(err)
		}
		privbn := new(big.Int).SetBytes(privbytes)
	}

	// len(sk.Keys) is a silly hacky way of getting the ring size.
	// it should defs be changed irl
	var polyarray []poly.Poly
	for i := 0; i < len(sk.Keys); i++ {
		randompoly := PolynomialBuilder(int(3), len(sk.Keys), int(i))
		// we build polyarray like p[0][k], p[1][k], ...
		polyarray = append(polyarray, randompoly)
	}
	fmt.Println(polyarray)

}


func Mint() CurvePoint, *big.Int, *big.Int {
	privkey, e := rand.Int(rand.Reader, grouporder)
	check(e)
	serial, e := rand.Int(rand.Reader, grouporder)
	check(e)
	c := commit(serial, privkey)
	return c, privkey, serial
}

func Spend(pp, M, c, C) *big.Int {
}

func SpendVerify(pp, M, serial, C, pi) {
}

*/

// Commit forms & returns a pedersen commitment with the two arguments given
func Commit(a *big.Int, b *big.Int) CurvePoint {
	ga := CurvePoint{}.ScalarBaseMult(a)
	hb := H.ScalarMult(b)
	return hb.Add(ga)
}

// HashToCurve takes a byteslice and returns a CurvePoint (whose DL remains unknown!)
func HashToCurve(s []byte) (CurvePoint, error) {
	q := Group.P
	x := big.NewInt(0)
	y := big.NewInt(0)
	z := big.NewInt(0)
	// what is this magical number
	z.SetString("57896044618658097711785492504343953926634992332820282019728792003954417335832", 10)

	// sum256 outputs an array of 32 bytes :) => are we menna use   keccak? does this work?
	array := sha3.Sum256(s)
	x = Convert(array[:])
	for true {
		xcubed := new(big.Int).Exp(x, big.NewInt(3), q)
		xcubed7 := new(big.Int).Add(xcubed, big.NewInt(7))
		y.ModSqrt(xcubed7, q)
		y.Set(q)
		y.Add(y, big.NewInt(1))
		y.Rsh(y, 2)
		y.Exp(xcubed7, y, q)
		z = z.Exp(y, big.NewInt(2), q)
		posspoint := Group.IsOnCurve(x, y)
		if posspoint == true {
			return CurvePoint{x, y}, nil
		}
		x.Add(x, big.NewInt(1))
	}
	return CurvePoint{}, errors.New("no curve point found")
}

// ConvertPubKeys takes the string rep of coords ('x', 'y') and changes to *big.Ints
func ConvertPubKeys(rn RingStr) Ring {

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

// Convert goes byte slice -> *big.Int
func Convert(data []byte) *big.Int {
	z := new(big.Int)
	z.SetBytes(data)
	return z
}

// Check just does rly trivial error handling
func Check(e error) {
	if e != nil {
		panic(e)
	}
}

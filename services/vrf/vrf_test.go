package vrf

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func panicErr(err error) {
	if err != nil {
		panic(err)
	}
}

func TestVRF_safePrime(t *testing.T) {
	// Short, because this is slow. Greater than 64+1, because rand.Prime
	// logic changes for smaller bit lengths
	bitLen := 256
	p := safePrime(uint32(bitLen), 1000)
	assert.Equal(t, p.BitLen(), bitLen)
	assert.True(t, p.ProbablyPrime(1000), "p should be prime")
	halfPMinusOne := new(big.Int).Rsh(p, 1)
	assert.True(t, halfPMinusOne.ProbablyPrime(1000),
		"(p-1)/2 should be prime")
}

// bigFromHex concatenates an array of 256-bit words, represented as hex, and
// interprets it as a big-endian integer.
//
// Huge numbers are represented as 256-bit words in this file (64-nybbles) for
// easy comparison to the javascript / solidity examples, which naturally break
// numbers up into 256-bits words for application to the bigModExp precompile.
func bigFromHex(s []string) *big.Int {
	for _, word := range s {
		if len(word) != 64 {
			panic("Entries should be 256 bits")
		}
	}
	n, ok := new(big.Int).SetString(strings.Join(s, ""), 16)
	if !ok {
		panic(fmt.Errorf("failed to convert %+v to big.Int as hex", s))
	}
	return n
}

// fullKey is a full 2048-bit RSA private key. Included here because these are
// slow to generate with MakeKey.
var fullKey = rsa.PrivateKey{
	PublicKey: rsa.PublicKey{
		N: bigFromHex([]string{
			"a1831fe6ce5898008c4fad030d49222dcdec735e5485a0429a2e5d053ce6099f",
			"35b498475c6217cd417c59b149604464f8b3adc0eceaa11fe8d8b40be0d0300d",
			"e34f4c7606399f408599ad2429c407cffbd4513f629966214320df82b7d3b027",
			"f18d5105823d290ab78f6fe794588e241841b337ab1aa3d90092532a8d470722",
			"06d4741ee5b7a97b43ff671b95b9f1432e14e602b6b4530c69f2c2480f8a6835",
			"0ab51d4620f993ab6ca34413a1636e43ddfa5e6947fba3be0a395bf67becdaa5",
			"0f64ed21b3c9cf3a65f99ead07bd57ac4620a5cfa5307bbd2987fdba42ef2e41",
			"144358a4209fc330d76f827f77447ed2e49be25b1e44410ee32562e968cc0e9d"}),
		E: 3,
	},
	D: bigFromHex([]string{
		"6bacbfef343b10005d8a73575e30c173de9da23ee303c02c66c99358d344066a",
		"23cdbada3d96ba88d652e67630ead8435077c92b489c6b6a9b3b22b295e02009",
		"4234dda404266a2b03bbc8c2c682afdffd38362a41bb996b8215ea572537cac5",
		"4bb38b59017e1b5c7a5f9fefb83b096d658122251cbc6d3b55b6e21c5e2f5a15",
		"a013c182f4e42ca8a2114a2984bffa68b2c02c958135da452ab316ec75fc5337",
		"6dcab7e72797d42d6edff45490751a21082b4f0da3e26d6d5604a2f6450da2f1",
		"92d575ac1b566e952b4a5fba62e89ad5c889b1b7f331d718a4548a61b967503e",
		"cdf6adb5a8dd49f3afebd3aca4177d4aaa369e45a7e311ee7dd88dba2d2b2d13",
	}),
	Primes: []*big.Int{
		bigFromHex([]string{
			"c8b764e9fd0a4acfa28be39cddfb2531f449562c942653a4cc89e14f6168fd6d",
			"21a9a604f42d08ed8b6b7a6eb6a2a1e7181f8d4c38f897fcf5c88a88bb506c2b",
			"a74e3cede3db4cda3578452207d62697ec2f168cdcce3690c7d5606038509d37",
			"2551b45d72ff3be2f577e1a47dbaab03ad0adc69a4f503fba1a2d9599aa3788b",
		}),
		bigFromHex([]string{
			"cdff6cf079571baeae599440709ed4742dab4cf5e0bd37ffdd5c3e95fd26edf4",
			"c45b63667168cc79bae7db261211252b3999da88992f679d1369dcfc5907fa0f",
			"0bd67fb1a6ecdc806f91c9f36b8a48d3ad2304aedb9782876b33cdc7748398ab",
			"b9ff9fb6305498605a15e358036697df383f1888fd7aa22d84bdb4f88a67d277",
		}),
	},
}

func testKey(t *testing.T, k *rsa.PrivateKey) {
	for seed := 1; seed < 100; seed++ {
		proof, err := Generate(k, big.NewInt(int64(seed)))
		panicErr(err)
		ok, err := proof.Verify()
		panicErr(err)
		assert.True(t, ok, "rejected a valid key")
		proof.Seed = big.NewInt(int64(seed + 1))
		ok, err = proof.Verify()
		panicErr(err)
		assert.False(t, ok, "accepted an invalid key")
	}
}

func TestVRF_fullKey(t *testing.T) {
	fullKey.Precompute()
	testKey(t, &fullKey)
}

func TestVRF_Generate(t *testing.T) {
	// Make a short key, to speed testing. Remove MakeKey argument, to
	// generate a full key
	k, err := MakeKey(256)
	panicErr(err)
	testKey(t, k)
}

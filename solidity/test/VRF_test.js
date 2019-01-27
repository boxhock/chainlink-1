import { randomBytes } from 'crypto'

import { deploy, bigNum, keccak } from './support/helpers'
import { assertBigNum } from './support/matchers'

const BN = require('bn.js')

const wordSizeBits = 256
const wordSizeBytes = wordSizeBits / 8

const keySizeBits = 2048
assert(keySizeBits % wordSizeBits === 0, `Key size must be multiple of words`)
const keySizeWords = keySizeBits / wordSizeBits
const keySizeBytes = keySizeBits / 8
const publicExponent = 3

// Representations of these huge numbers are structured as 256-bit (64-nybble)
// words, to simplify comparison to the word-based I/O with the solidity
// contract.

// A roughly 2048-bit prime, per https://2ton.com.au/getprimes/random/2048...
const prime = bigNum(
  '0x91d18d4420ab0cae83964b2310dc7277e61ad331d8e37de4923b355308cd2387' +
    '46dbd85833993853724b0b7048c0d331b177ecc9486ba14142a38cf292b8be6c' +
    '861852d02fa41f1a12b5c0e13716fba0887bb5568b7caf1eac255fa6fded398b' +
    'ff863ab3391450edc27ec52dc92bd66df1dc818fa58259aca354d5cbdfe427fa' +
    'ec81c497231ae625c8f3afc0a37b8fe7752ad8c0cd04fd2a1177680d0334b2a1' +
    'ee60cd49f629a8c5e71ad3cc1af7b26fc29c7112be6162604b82f0cba28cc2d3' +
    '521f09edbdf598be03adcf4797b50b948418bc01e298ae1815d5d2c7af41f795' +
    '4471f3f52b60da23e73b8e27706ea90c877071ddc20e3ad78404f352306157b7')

// 2048-bit RSA modulus, taken from vrf_test.go
const publicKeyModulus = bigNum(
  '0xa1831fe6ce5898008c4fad030d49222dcdec735e5485a0429a2e5d053ce6099f' +
    '35b498475c6217cd417c59b149604464f8b3adc0eceaa11fe8d8b40be0d0300d' +
    'e34f4c7606399f408599ad2429c407cffbd4513f629966214320df82b7d3b027' +
    'f18d5105823d290ab78f6fe794588e241841b337ab1aa3d90092532a8d470722' +
    '06d4741ee5b7a97b43ff671b95b9f1432e14e602b6b4530c69f2c2480f8a6835' +
    '0ab51d4620f993ab6ca34413a1636e43ddfa5e6947fba3be0a395bf67becdaa5' +
    '0f64ed21b3c9cf3a65f99ead07bd57ac4620a5cfa5307bbd2987fdba42ef2e41' +
    '144358a4209fc330d76f827f77447ed2e49be25b1e44410ee32562e968cc0e9d')

// An example proof, taken from vrf_test.go output, using publicKeyModulus and
// publicExponent. Extracted using the following code, in vrf_test.go/testKey:
//
//   if proof.Seed.Int64() == 17 {
//     fmt.Printf("Decryption %x\nOutput %x\n", proof.Decryption, proof.Output)
//   }
//
// Put this just after `assert.True(t, ok, "rejected a valid key")`, and take the
// first output.
const proofTopBitOff = {
  seed: bigNum(17),
  decryption: bigNum(
    '0x4f123301f86c0eb90862d18cca79bbf5ccbc215aaac605eb709862db2aa91c5d' +
      'baf0d608ff966e10669bb6404cf89fda0b39fc57b772adee432dd8c5d466b376' +
      'a76270882253a68d573557d3e049fcfa898e3ce7720a0c4239c192011f8b8594' +
      '93a3e45bd08390de53f991d250be2ec6ac068eecb79bd01dc9e278903e46e338' +
      '08e1e372fd8562623ae7eddb755efef1b1924a0b24df3fa2258b1d706a6a0bca' +
      '7746f0006efbd445a051504b3d5283ffc20cabdc5fce4ce2ca66f50f9ab856c0' +
      '5d83c3ac3eaaf04230442d4544d5e14a7343a13e33a8965f8a0c15079627cd3d' +
      '8ddd29850662a3fa5c2cc1c9348cb39af556dfe524fff247601fa84b1231a0bc'),
  output: bigNum(
    '0x8c669fd3f0e2ea6a5363ec8d4453ab8921d52c52b3d2eba3aa10f364945814dd')
}

const proofTopBitOn = {
  seed: bigNum(1),
  decryption: bigNum(
    '0xedd854d80ee43153afc8f22b698a648e1cac3b416f9976d4c9e073a2846b0723' +
      '81f2b133695e21b9959908c5d55f570c05f97f62f5b09459a3d73a145b1f4260' +
      '680a1d08114581a1f533e4a8771f0649c6b4b228d28c59ecd427434ca45879ea' +
      'bd39dbbb7a14e3a4216d3caf62220aff0c60dae77667f965fa9ebe95b4d0f461' +
      'f382b59c019879992324e1eaeb0529e1a6e7c6719894f1ad7fa8d307e3c1d20c' +
      'fd8f419077c7ab72fdd38366ff5eda75ff7d3e4b1ec718c593d3702d787ad727' +
      '90b0f797994f1b8957e0ee92a61b106d9693721fefd5b531da9d5cd35fc369a1' +
      'b892ee97e8016b00f017997633a2d6d33098f3dbb745efce3df4a2285059bea'),
  output: bigNum(
    '0x825013502ff1508b5812117f4b3bef5882f4023c2a521065cf83db8ca23d06b8')
}

const toHexString = byteArray =>
  byteArray.map(byte => ('0' + (byte & 0xFF).toString(16)).slice(-2)).join('')

const numToUint256Array = n => { // n as keySizeWords-length array of uint256's
  const asBytes = bigNum(n).toArray('be', keySizeBytes)
  const rv = []
  for (let bytesStart = 0; bytesStart < asBytes.length; bytesStart += wordSizeBytes) {
    const uint256AsBytes = asBytes.slice(bytesStart, bytesStart + wordSizeBytes)
    rv.push(bigNum('0x' + toHexString(uint256AsBytes)))
  }
  assert(rv.length === keySizeWords)
  rv.forEach(c => assert(c.bitLength() <= wordSizeBits, 'Should be uint256 chunks'))
  const asHex = '0x' +
        rv.map(w => '0'.repeat(64 - w.bitLength() / 4) + w.toString(16)).join('')
  assertBigNum(n, bigNum(asHex), 'rv should be uint256 chunking of n')
  return rv
}

const uint256ArrayToNum = a => {
  const asBytes = [].concat(...a.map(e => bigNum(e).toArray('be', wordSizeBytes)))
  return bigNum('0x' + toHexString(asBytes))
}

// Check that p will exercise turning off the top bit, in VRF#seedToRingValue
const proofExercisesDisablingTopBitOfRingValue = p => {
  const serialization = '0x' + toHexString(p.seed.toArray('be', wordSizeBytes))
  const firstWord = bigNum(keccak(serialization))
  return firstWord.cmp(bigNum(numToUint256Array(publicKeyModulus)[0])) === 1
}

contract('VRF', async () => {
  context('Accurately computes some bigModExp\'s', async () => {
    let exp
    const minusOne = prime.sub(bigNum(1))
    beforeEach(async () => {
      const VRF = await deploy('VRF.sol', numToUint256Array(prime))
      exp = async n => uint256ArrayToNum(
        await VRF.bigModExp(numToUint256Array(n)))
    })
    it('knows 2³≡8 mod p', async () => { assertBigNum(await exp(2), 8) })
    it('knows p³≡0 mod p', async () => { assertBigNum(await exp(prime), 0) })
    it('knows (-1)³≡-1 mod p', async () => {
      assertBigNum(await exp(minusOne), minusOne)
    })
    it('knows (x^{publicExponent^{-1} mod (p-1)})³≡x mod p ("RSA" with one factor)', async () => {
      const bytes = randomBytes(keySizeBytes)
      const ℤslashPℤ = BN.red(prime)
      const ℤslashPMinusOneℤ = BN.red(minusOne)
      const bigExponent = bigNum(publicExponent).toRed(ℤslashPMinusOneℤ)
      // bigExponent.redInvm() doesn't do what I expect.
      // Do CRT by hand... Want inverse of 3 mod (p-1)
      assert(minusOne.mod(bigExponent.fromRed()), 1)
      const seekretKey = minusOne.div(bigExponent.fromRed()).toRed(
        ℤslashPMinusOneℤ).redNeg()
      assertBigNum(seekretKey.redMul(bigExponent), 1,
        'seekretKey * publicExponent ≡ 1 mod (p-1)')
      const seekretMsg = bigNum('0x' + toHexString(bytes)).toRed(ℤslashPℤ)
      const enkcreepted = seekretMsg.redPow(seekretKey.fromRed())
      const dekcreepted = await exp(enkcreepted)
      assertBigNum(dekcreepted, seekretMsg, '')
    })
  })
  context('Can tell good proofs from bad', async () => {
    let VRF
    const checkProof = async p => VRF.isValidVRFOutput(
      p.seed.toString(), numToUint256Array(p.decryption), p.output.toString())
    beforeEach(async () => {
      VRF = await deploy('VRF.sol', numToUint256Array(publicKeyModulus))
    })
    it('knows a good proof whose seedToRingValue exceeds the modulus', async () => {
      assert(proofExercisesDisablingTopBitOfRingValue(proofTopBitOn),
        `Must choose proof which requires disabling the top bit in VRF#seedToRingValue.
Find one by checking ringValueBytes[0]&128 in vrf.go/seedToRingValue`)
      assert(await checkProof(proofTopBitOn), 'Proof failed')
    })
    it('knows a good proof whose seedToRingValue is less than the modulus', async () => {
      assert(!proofExercisesDisablingTopBitOfRingValue(proofTopBitOff),
        `Must choose proof which does not require disabling the top bit in VRF#seedToRingValue.
Find one by checking ringValueBytes[0]&128 in vrf.go/seedToRingValue`)
      assert(await checkProof(proofTopBitOff), 'Proof failed')
    })
    it('knows a bad proof', async () => {
      const badProof = {
        ...proofTopBitOn, seed: proofTopBitOn.seed.add(bigNum(1))
      }
      assert(!(await checkProof(badProof)), 'Failed to recognize a bad proof')
    })
  })
})

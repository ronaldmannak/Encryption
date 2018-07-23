//: RSA encryption demo

import Cocoa

typealias Key = Int

/**
 Extended Euclidean algorithm, used to calculate the private key
 Algorithm:  publicKey * a + φ(max) * b = gcd(a: publicKey, b: max) where a = private key
 */
func egcd(a: Int, b: Int, x: Int = 0, y: Int = 1) -> (Int, Int) {
    guard a != 0 else {
        return (0, 1)
    }
    let gcd = egcd(a: b % a, b: a)
    let x = gcd.1 - (b / a) * gcd.0
    let y = gcd.0
    return (x, y)
}

/**
 Calculate the private key, which is the inverse of publicKey mod φ(pq)
 */
func generatePrivateKey(p: Int, q: Int, publicKey: Key) -> Key {
    let φ = (p - 1) * (q - 1)
    return (egcd(a: publicKey, b: φ)).0
}

/**
 Encrypts single UInt8.
 Pass public key to encrypt or validate, public key to decrypt or sign
 */
func encrypt(_ c: UInt8, key: Key, max: Int) -> UInt8 {
//    return UInt8(UInt64(pow(Double(c),Double(key))) % UInt64(max)) Causes overflow when encrypting or decrypting with a large key

    let c = UInt64(c)
    var total = c
    for _ in 0 ..< key - 1 {
        total = ((total * c) % UInt64(max))
    }
    return UInt8(total)
}

/**
 Encrypts a String.
 Pass public key to encrypt or validate, public key to decrypt or sign
 */
func encrypt(_ plaintext: String, key: Key, max: Int) -> [UInt8] {
    let plaintext = plaintext.utf8
    var ciphertext = [UInt8]()
    plaintext.map{ ciphertext.append(encrypt($0, key: key, max: max)) }
    return ciphertext
}

/**
 Encrypts an array of utf8 characters
 Pass public key to encrypt or validate, public key to decrypt or sign
 */
func encrypt(_ c: [UInt8], key: Key, max: Int) -> String {
    var plaintextArray = [UInt8]()
    c.map { plaintextArray.append(encrypt($0, key: key, max: max)) }
    return String(bytes: plaintextArray, encoding: .utf8)!
}

/**
 Encrypts and decrypts plaintext.
 */
func encryptionRoundtrip(plaintext: String, publicKey: Key, privateKey: Key, max: Int) -> Bool {
    let ciphertext = encrypt(plaintext, key: publicKey, max: max)
    let decodedtext = encrypt(ciphertext, key: privateKey, max: max)
    guard decodedtext == plaintext else { return false }
    return true
}

/**
 Signs and verifies signature of a message
 */
func signatureRoundtrip(message: String, publicKey: Key, privateKey: Key, max: Int) -> Bool {
    let hash = "\(message.hashValue)"     // Using a string to avoid integer overflows
    let signature = encrypt(hash, key: privateKey, max: max)
    
    // Validate signature with the public key
    let plaintextHash = encrypt(signature, key: publicKey, max: max)
    guard Int(plaintextHash) == message.hashValue else { return false }
    return true
}

/*
 Roundtrips using primes and public Key from the example in https://arstechnica.com/information-technology/2013/10/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/
 */

let p = 13                  // Random prime 1
let q = 7                   // Random prime 2
let max = p * q             // N = maximum number
let publicKey: Key = 5      // Random prime
let privateKey = generatePrivateKey(p: p, q: q, publicKey: publicKey)

let message = "CLOUD"

_ = encryptionRoundtrip(plaintext: message, publicKey: publicKey, privateKey: privateKey, max: max)

_ = signatureRoundtrip(message: message, publicKey: publicKey, privateKey: privateKey, max: max)


/*
 Roundtrips using randomly generated p, q and publicKey
 */

/**
 Generates random prime number. Default max is 20
 */
func rand_prime(max: Int = 20) -> Int {
    let prime = Int(arc4random_uniform(UInt32(max)))
    guard prime.isPrime == true else {
        return rand_prime(max: max)
    }
    return prime
}

extension Int {
    var isPrime: Bool {
        return self > 1 && !(2..<self).contains { self % $0 == 0 }
    }
}

let p2 = rand_prime()
let q2 = rand_prime()
let max2 = p2 * q2
let publicKey2 = rand_prime()
let privateKey2 = generatePrivateKey(p: p2, q: q2, publicKey: publicKey2) // Sometimes returns a negative value, which causes exception in the next line

_ = encryptionRoundtrip(plaintext: message, publicKey: publicKey2, privateKey: privateKey2, max: max2)

_ = signatureRoundtrip(message: message, publicKey: publicKey2, privateKey: privateKey2, max: max2)

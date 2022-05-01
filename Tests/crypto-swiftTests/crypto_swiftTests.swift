import XCTest
import BigInt
@testable import crypto_swift

final class crypto_swiftTests: XCTestCase {
    func test_mod_int() throws {
        let a = mod_int(value: 5, modulus: 10)
        let b = mod_int(value: 15, modulus: 10)

        XCTAssertEqual(a.value, 5)
        XCTAssertEqual(b.value, 5)
        XCTAssertEqual(a.value, b.value)
        XCTAssertEqual(a, b)

        let zero: mod_int = mod_int(
                value: BigInt.zero, modulus: BigInt(11)
        )

        // 0 mod 11 = 0
        // (0 mod 11)^-1 = 11 mod 11 = 0
        let neg_zero: mod_int = -zero;
        XCTAssertEqual(BigInt(0), neg_zero.value)
        XCTAssertEqual(BigInt(11), neg_zero.modulus)


        let one: mod_int = mod_int(
                value: BigInt(23),
                modulus: BigInt(11)
        )

        // 23 mod 11 = 1
        // (23 mod 11)^-1 = 10
        let neg_one: mod_int = -one;
        XCTAssertEqual(BigInt(10), neg_one.value)
        XCTAssertEqual(BigInt(11), neg_one.modulus)

        let two: mod_int = mod_int(
                value: BigInt(2),
                modulus: BigInt(11)
        )

        // 2 mod 11 = 2
        // (2 mod 11)^-1 = 9
        let neg_two = -two;
        XCTAssertEqual(BigInt(9), neg_two.value)
        XCTAssertEqual(BigInt(11), neg_two.modulus)

        let two_mod_four: mod_int = mod_int(value: 2, modulus: 4)
        let three_mod_four: mod_int = mod_int(value: 3, modulus: 4)
        let two_mod_four_times_three_mod_four: mod_int = two_mod_four * three_mod_four
        XCTAssertEqual(BigInt(2), two_mod_four_times_three_mod_four.value)
        XCTAssertEqual(BigInt(4), two_mod_four_times_three_mod_four.modulus)
    }

    func test_encrypt_decrypt_el_gamal_test() throws {
        let p: mod_int = mod_int(value: 23, modulus: 0)
        let q: mod_int = (p - mod_int.from(value: 1)) / mod_int.from(value: 2)
        let private_key: PrivateKey = PrivateKey(
                p: p,
                q: q,
                g: mod_int(value: 2, modulus: p.value),
                x: mod_int.rand(upper_bound: p.value)
        )

        let public_key: PublicKey = PublicKey(
                p: private_key.p,
                q: private_key.q,
                h: mod_int(
                        value: private_key.g.pow(power: private_key.x).value,
                        modulus: private_key.p.value
                ),
                g: private_key.g
        )

        print(private_key)
        print(public_key)

        let message: mod_int = public_key.make_message(value: 1)
        let cipher_text: CipherText = public_key.encrypt(plain_text: message)
        let plain_text: PlainText = private_key.decrypt(cipher_text: cipher_text)

        XCTAssertEqual(message.value, plain_text.value)
    }

    func test_membership_proof() throws {
        let p: mod_int = mod_int(value: BigInt("1449901879557492303016150949425292606294424240059"), modulus: 0)
        let q: mod_int = (p - mod_int.from(value: 1)) / mod_int.from(value: 2)
        let private_key: PrivateKey = PrivateKey(
                p: p,
                q: q,
                g: mod_int(value: BigInt("650614565471833138727952492078522919745801716191"), modulus: p.value),
                x: mod_int(value: BigInt("896771263533775491364511200158444196377569745583"), modulus: p.value)
        )

        let public_key: PublicKey = PublicKey(
                p: private_key.p,
                q: private_key.q,
                h: mod_int(
                        value: private_key.g.pow(power: private_key.x).value,
                        modulus: private_key.p.value
                ),
                g: private_key.g
        )

        print(private_key.x)
        print(private_key)
        print(public_key)
        while true {
            let message: mod_int = public_key.make_message(value: 1)
            let cipher_text: CipherText = public_key.encrypt(plain_text: message)
//        let cipher_text: CipherText = CipherText(
//                g_r: mod_int(value: BigInt("114174391746769211179057064050450668223944675624"), modulus: BigInt("1449901879557492303016150949425292606294424240059")),
//                g_v__s: mod_int(value: BigInt("885476757034082641428791475482165474592721569831"), modulus: BigInt("1449901879557492303016150949425292606294424240059")),
//                random: mod_int(value: BigInt("7146048211113775906570416131721832206513831805"), modulus: BigInt("724950939778746151508075474712646303147212120029"))
//        )

            let domain: Array<mod_int> = [mod_int.zero, mod_int(value: 1, modulus: 0)]

            let proof: MembershipProof = MembershipProof(
                    public_key: public_key,
                    plain_text: message,
                    cipher_text: cipher_text,
                    domain: domain
            )

            print(proof.verify(public_key: public_key, cipher_text: cipher_text, domain: domain))

            XCTAssert(proof.verify(public_key: public_key, cipher_text: cipher_text, domain: domain))
        }
    }

    func test_bits() {
        let a: BigInt = BigInt(172481312312173852)
        a.to_bytes_le()
    }
}

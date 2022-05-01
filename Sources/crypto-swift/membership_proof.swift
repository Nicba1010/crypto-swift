//
// Created by roberto on 4/30/22.
//

import BigInt
import Crypto
import Foundation

struct MembershipProof {
    let s: Array<mod_int>
    let c: Array<mod_int>

    init(public_key: PublicKey, plain_text: PlainText, cipher_text: CipherText, domain: Array<mod_int>) {
        var s: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)
        var c: Array<mod_int> = Array<mod_int>(repeating: mod_int.zero, count: domain.count)

        let s_for_valid: mod_int = mod_int.rand(upper_bound: public_key.q.value)
//        let s_for_valid: mod_int = mod_int(value: BigInt("16870143206178733140190693110102914592767898127"), modulus: public_key.q.value)

//        print(s_for_valid)
//        print(cipher_text)

        var sha512: SHA512 = SHA512()
        sha512.update(data: public_key.g.to_bytes())
        sha512.update(data: public_key.h.to_bytes())
        sha512.update(data: cipher_text.g_r.to_bytes())
        sha512.update(data: cipher_text.g_v__s.to_bytes())
//        print(sha512.finalize())

        var chosen_domain_element_idx: Int = 0

        for domain_element_idx in domain.indices {
//            print("LOOP BEGIN")
//            print(sha512.finalize())
            let a, b: mod_int

            let domain_element: mod_int = domain[domain_element_idx]

            if domain_element == plain_text {
                a = public_key.g.pow(power: s_for_valid)
                b = public_key.h.pow(power: s_for_valid)
//                print(a)
//                print(b)
                chosen_domain_element_idx = domain_element_idx
            } else {
                s[domain_element_idx] = mod_int.rand(upper_bound: public_key.q.value)
                c[domain_element_idx] = mod_int.rand(upper_bound: public_key.q.value)
//                print(s[domain_element_idx])
//                print(c[domain_element_idx])
//                s[domain_element_idx] = mod_int(value: BigInt("340426178212846383764710607281056135739139464083"), modulus: public_key.q.value)
//                c[domain_element_idx] = mod_int(value: BigInt("359230415343133064330408750969231566014081435744"), modulus: public_key.q.value)

                a = public_key.g.pow(power: s[domain_element_idx]) * cipher_text.g_r.pow(power: -c[domain_element_idx])
                b = public_key.h.pow(power: s[domain_element_idx]) * (cipher_text.g_v__s / (public_key.g.pow(power: domain_element))).pow(power: -c[domain_element_idx])
//                print(public_key.g.pow(power: s[domain_element_idx]))
//                print(c[domain_element_idx])
//                print(-c[domain_element_idx])
//                print(cipher_text.g_r.pow(power: -c[domain_element_idx]))
//                print(a)
//                print(b)
            }

            sha512.update(data: a.to_bytes())
            sha512.update(data: b.to_bytes())
//            print("LOOP END")
//            print(sha512.finalize())
        }

        var h_b: Array<UInt8> = Array<UInt8>()
        h_b.append(2)
        h_b.append(contentsOf: sha512.finalize())

//        print(sha512.finalize())

        var c_0: mod_int = mod_int(value: [BigInt(Data(h_b)), BigInt(0)].last!, modulus: public_key.q.value)
//        print(c_0)
        c.forEach { c_ in
//            print(c_)
            c_0 = c_0 - c_
//            print(c_0)
        }

        s[chosen_domain_element_idx] = c_0 * cipher_text.random + s_for_valid
        c[chosen_domain_element_idx] = c_0

        self.s = s
        self.c = c
    }

    func verify(public_key: PublicKey, cipher_text: CipherText, domain: Array<mod_int>) -> Bool {
        assert(s.count == domain.count)

        var sha512: SHA512 = SHA512()
        sha512.update(data: public_key.g.to_bytes())
        sha512.update(data: public_key.h.to_bytes())
        sha512.update(data: cipher_text.g_r.to_bytes())
        sha512.update(data: cipher_text.g_v__s.to_bytes())

        for c_i in c.indices {
            let domain_element: mod_int = domain[c_i]

            let s = s[c_i]
            let c = c[c_i]

            let a = public_key.g.pow(power: s) * cipher_text.g_r.pow(power: -c)
            let b = public_key.h.pow(power: s) * (cipher_text.g_v__s / public_key.g.pow(power: domain_element)).pow(power: -c)
            sha512.update(data: a.to_bytes())
            sha512.update(data: b.to_bytes())
        }

        var h_b: Array<UInt8> = Array<UInt8>()
        h_b.append(2)
        h_b.append(contentsOf: sha512.finalize())

        let new_c: mod_int = mod_int(value: [BigInt(Data(h_b)), BigInt(0)].last!, modulus: public_key.q.value)
        let c_sum = c.reduce(mod_int(value: 0, modulus: c.first!.modulus), +)

        return c_sum == new_c
    }
}
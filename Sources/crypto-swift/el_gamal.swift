import BigInt

typealias PlainText = mod_int

struct CipherText {
    let g_r: mod_int
    let g_v__s: mod_int
    let random: mod_int

    static func +(lhs: CipherText, rhs: CipherText) -> CipherText {
        CipherText(
                g_r: lhs.g_r * rhs.g_r,
                g_v__s: lhs.g_v__s * rhs.g_v__s,
                random: lhs.random + rhs.random
        )
    }
}

struct PublicKey {
    let p: mod_int
    let q: mod_int
    let h: mod_int
    let g: mod_int

    func encrypt(plain_text: PlainText) -> CipherText {
        let random: mod_int = mod_int.rand(upper_bound: q.value)

        return CipherText(
                g_r: g.pow(power: random),
                g_v__s: h.pow(power: random) * g.pow(power: plain_text),
                random: random
        )
    }

    func make_message(value: BigInt) -> PlainText {
        mod_int(value: value, modulus: g.modulus)
    }
}

struct PrivateKey {
    let p: mod_int
    let q: mod_int
    let g: mod_int
    let x: mod_int

    func decrypt(cipher_text: CipherText) -> PlainText {
        let g_to_m: mod_int = cipher_text.g_v__s / cipher_text.g_r.pow(power: x)

        var i: BigInt = BigInt(0)

        while true {
            let target: mod_int = mod_int(
                    value: g.value,
                    modulus: g_to_m.modulus
            ).pow(power: mod_int(
                    value: i,
                    modulus: g_to_m.modulus
            ))

            if (target == g_to_m) {
                return mod_int(value: i, modulus: g_to_m.modulus);
            }

            i += 1;
        }
    }

    func make_message(value: BigInt) -> PlainText {
        mod_int(value: value, modulus: p.value)
    }
}
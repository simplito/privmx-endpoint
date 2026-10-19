// Porownanie sciezek podpisu: privmx::crypto (ECCImpl) vs pmx-crypto (AsyncKeyUtils)
// Odtwarza dokladnie te same wywolania OpenSSL co obie implementacje.
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

static std::string hex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string r;
    for (unsigned char c : b) { r += d[c >> 4]; r += d[c & 15]; }
    return r;
}
static Bytes unhex(const std::string& s) {
    Bytes r;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        r.push_back((unsigned char)std::stoi(s.substr(i, 2), nullptr, 16));
    return r;
}
static Bytes sha256(const Bytes& in) {
    Bytes out(32); unsigned int l = 32;
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), nullptr);
    EVP_DigestUpdate(c, in.data(), in.size());
    EVP_DigestFinal_ex(c, out.data(), &l);
    EVP_MD_CTX_free(c);
    return out;
}

// ---------------------------------------------------------------- klucz
static EC_KEY* g_eckey = nullptr;
static EVP_PKEY* g_pkey = nullptr;

static void makeKey(const std::string& privHex) {
    g_eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM* p = BN_new();
    BN_hex2bn(&p, privHex.c_str());
    EC_KEY_set_private_key(g_eckey, p);
    const EC_GROUP* grp = EC_KEY_get0_group(g_eckey);
    EC_POINT* pub = EC_POINT_new(grp);
    BN_CTX* ctx = BN_CTX_new();
    EC_POINT_mul(grp, pub, p, nullptr, nullptr, ctx);
    EC_KEY_set_public_key(g_eckey, pub);
    g_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(g_pkey, g_eckey);
    BN_CTX_free(ctx); EC_POINT_free(pub); BN_free(p);
}

static Bytes pubCompressed() {
    const EC_GROUP* grp = EC_KEY_get0_group(g_eckey);
    const EC_POINT* pub = EC_KEY_get0_public_key(g_eckey);
    BN_CTX* ctx = BN_CTX_new();
    Bytes out(33);
    EC_POINT_point2oct(grp, pub, POINT_CONVERSION_COMPRESSED, out.data(), 33, ctx);
    BN_CTX_free(ctx);
    return out;
}

// -------------------------------------------- privmx::crypto (ECCImpl.cpp)
// ECCImpl::sign(data) -> ECDSA_do_sign(data) ; data JEST digestem
static Bytes privmx_ecc_sign(const Bytes& digest) {
    ECDSA_SIG* sig = ECDSA_do_sign(digest.data(), (int)digest.size(), g_eckey);
    Bytes out(65, 0); out[0] = 27;
    const BIGNUM *r, *s; ECDSA_SIG_get0(sig, &r, &s);
    BN_bn2bin(r, &out[1 + 32 - BN_num_bytes(r)]);
    BN_bn2bin(s, &out[33 + 32 - BN_num_bytes(s)]);
    ECDSA_SIG_free(sig);
    return out;
}
static bool privmx_ecc_verify(const Bytes& digest, const Bytes& sig65) {
    if (sig65.size() != 65 || sig65[0] < 27 || sig65[0] > 42) return false;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_new(); BIGNUM* s = BN_new();
    BN_bin2bn(&sig65[1], 32, r);
    BN_bin2bn(&sig65[33], 32, s);
    ECDSA_SIG_set0(sig, r, s);
    int res = ECDSA_do_verify(digest.data(), (int)digest.size(), sig, g_eckey);
    ECDSA_SIG_free(sig);
    return res == 1;
}
// PrivateKey::signToCompactSignatureWithHash(m) = ECC::sign(sha256(m))
static Bytes privmx_signWithHash(const Bytes& m)                 { return privmx_ecc_sign(sha256(m)); }
static bool  privmx_verifyWithHash(const Bytes& m, const Bytes& s){ return privmx_ecc_verify(sha256(m), s); }

// ------------------------------------------ pmx-crypto (AsyncKeyUtils.cpp)
// sign_ds(msg, EVP_sha256()) -> EVP_DigestSign : sam liczy sha256(msg)
static Bytes pmx_sign_ds(const Bytes& msg) {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_DigestSignInit(c, nullptr, EVP_sha256(), nullptr, g_pkey);
    size_t len = 0;
    EVP_DigestSign(c, nullptr, &len, msg.data(), msg.size());
    Bytes sig(len);
    EVP_DigestSign(c, sig.data(), &len, msg.data(), msg.size());
    sig.resize(len);
    EVP_MD_CTX_free(c);
    return sig;
}
static bool pmx_verify_ds(const Bytes& msg, const Bytes& asn1) {
    EVP_MD_CTX* c = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(c, nullptr, EVP_sha256(), nullptr, g_pkey);
    int r = EVP_DigestVerify(c, asn1.data(), asn1.size(), msg.data(), msg.size());
    EVP_MD_CTX_free(c);
    return r == 1;
}
// signAsn2rs
static Bytes pmx_asn2rs(const Bytes& asn1) {
    const unsigned char* p = asn1.data();
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, (long)asn1.size());
    Bytes out(65, 0); out[0] = 27;
    const BIGNUM *r, *s; ECDSA_SIG_get0(sig, &r, &s);
    BN_bn2binpad(r, &out[1], 32);
    BN_bn2binpad(s, &out[33], 32);
    ECDSA_SIG_free(sig);
    return out;
}
// signRS2Asn
static Bytes pmx_rs2asn(const Bytes& sig65) {
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* r = BN_new(); BIGNUM* s = BN_new();
    BN_bin2bn(&sig65[1], 32, r);
    BN_bin2bn(&sig65[33], 32, s);
    ECDSA_SIG_set0(sig, r, s);
    Bytes out(72); unsigned char* p = out.data();
    int len = i2d_ECDSA_SIG(sig, &p);
    out.resize(len);
    ECDSA_SIG_free(sig);
    return out;
}
// SigScheme::Compact
static Bytes pmx_sign_Compact(const Bytes& m)                     { return pmx_asn2rs(pmx_sign_ds(m)); }
static bool  pmx_verify_Compact(const Bytes& m, const Bytes& s)   { return pmx_verify_ds(m, pmx_rs2asn(s)); }
// SigScheme::CompactWithHash  ->  Compact(sha256(m))
static Bytes pmx_sign_CompactWithHash(const Bytes& m)             { return pmx_sign_Compact(sha256(m)); }
static bool  pmx_verify_CompactWithHash(const Bytes& m, const Bytes& s) { return pmx_verify_Compact(sha256(m), s); }

// ------- deterministyczny podpis (ustalone k) - zeby bajty byly odtwarzalne
static Bytes signFixedK(const Bytes& digest, const char* kHex) {
    const EC_GROUP* grp = EC_KEY_get0_group(g_eckey);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* k = BN_new(); BN_hex2bn(&k, kHex);
    BIGNUM* order = BN_new(); EC_GROUP_get_order(grp, order, ctx);
    EC_POINT* kg = EC_POINT_new(grp);
    EC_POINT_mul(grp, kg, k, nullptr, nullptr, ctx);
    BIGNUM* x = BN_new(); BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(grp, kg, x, y, ctx);
    BIGNUM* rp = BN_new(); BN_mod(rp, x, order, ctx);
    BIGNUM* kinv = BN_new(); BN_mod_inverse(kinv, k, order, ctx);
    ECDSA_SIG* sig = ECDSA_do_sign_ex(digest.data(), (int)digest.size(), kinv, rp, g_eckey);
    Bytes out(65, 0); out[0] = 27;
    if (sig) {
        const BIGNUM *r, *s; ECDSA_SIG_get0(sig, &r, &s);
        BN_bn2binpad(r, &out[1], 32);
        BN_bn2binpad(s, &out[33], 32);
        ECDSA_SIG_free(sig);
    }
    BN_free(k); BN_free(order); BN_free(x); BN_free(y);
    BN_free(rp); BN_free(kinv); EC_POINT_free(kg); BN_CTX_free(ctx);
    return out;
}

static void row(const char* label, bool v) { printf("  %-62s %s\n", label, v ? "OK   (przechodzi)" : "FAIL (odrzucony)"); }

int main() {
    const std::string PRIV = "813de00eb43c227eaf824740bcee66f8b8e4c08383348365"
                             "8c8c65e7d9cd76c9";
    makeKey(PRIV);

    const std::string msgStr = "Message to sign";
    Bytes m(msgStr.begin(), msgStr.end());

    Bytes d1 = sha256(m);
    Bytes d2 = sha256(d1);

    printf("=========================================================================\n");
    printf(" DANE WEJSCIOWE\n");
    printf("=========================================================================\n");
    printf("  krzywa                  secp256k1\n");
    printf("  WIF                     L1YwTwAr8dQCBzfmXBzh6ggBkYbLuu15Tc7s4bajrRNDbsogs9a5\n");
    printf("  klucz prywatny (32B)    %s\n", PRIV.c_str());
    printf("  klucz publiczny (33B)   %s\n", hex(pubCompressed()).c_str());
    printf("  wiadomosc m             \"%s\"\n", msgStr.c_str());
    printf("\n");
    printf("  sha256(m)               %s\n", hex(d1).c_str());
    printf("  sha256(sha256(m))       %s\n", hex(d2).c_str());
    printf("\n");

    printf("=========================================================================\n");
    printf(" JAKI DIGEST TRAFIA POD ECDSA\n");
    printf("=========================================================================\n");
    printf("  privmx  signToCompactSignatureWithHash(m)   -> %s\n", hex(d1).c_str());
    printf("  pmx     sign(m, SigScheme::Compact)         -> %s\n", hex(d1).c_str());
    printf("  pmx     sign(m, SigScheme::CompactWithHash) -> %s   <-- INNY\n", hex(d2).c_str());
    printf("\n");

    printf("=========================================================================\n");
    printf(" PODPISY - PRZEBIEG ODTWARZALNY (ustalone k = 0x01..be, wylacznie dla demo)\n");
    printf("=========================================================================\n");
    const char* K = "01BEEF00000000000000000000000000000000000000000000000000000000BE";
    Bytes s_d1 = signFixedK(d1, K);
    Bytes s_d2 = signFixedK(d2, K);
    printf("  ECDSA nad sha256(m)          (privmx WithHash == pmx Compact)\n");
    printf("    65B  %s\n", hex(s_d1).c_str());
    printf("  ECDSA nad sha256(sha256(m))  (pmx CompactWithHash)\n");
    printf("    65B  %s\n", hex(s_d2).c_str());
    printf("\n  To samo k, ten sam klucz, ta sama wiadomosc - inne R i S,\n");
    printf("  bo podpisywany jest inny digest.\n");
    printf("\n");

    printf("=========================================================================\n");
    printf(" PODPISY - PRZEBIEG RZECZYWISTY (k losowe, jak w obu bibliotekach)\n");
    printf("=========================================================================\n");
    Bytes sigPrivmx = privmx_signWithHash(m);
    Bytes sigCompact = pmx_sign_Compact(m);
    Bytes sigCWH = pmx_sign_CompactWithHash(m);
    Bytes asn1 = pmx_sign_ds(m);
    printf("  privmx signToCompactSignatureWithHash(m)   [%zuB] %s\n", sigPrivmx.size(), hex(sigPrivmx).c_str());
    printf("  pmx    sign(m, Compact)                    [%zuB] %s\n", sigCompact.size(), hex(sigCompact).c_str());
    printf("  pmx    sign(m, CompactWithHash)            [%zuB] %s\n", sigCWH.size(), hex(sigCWH).c_str());
    printf("  pmx    sign(m, Default)  [ASN.1 DER]       [%zuB] %s\n", asn1.size(), hex(asn1).c_str());
    printf("\n");

    printf("=========================================================================\n");
    printf(" MACIERZ WERYFIKACJI KRZYZOWEJ\n");
    printf("=========================================================================\n");
    printf("\n  podpis wytworzony przez: privmx signToCompactSignatureWithHash(m)\n");
    row("privmx verifyCompactSignatureWithHash(m, sig)", privmx_verifyWithHash(m, sigPrivmx));
    row("pmx    verify(m, sig, SigScheme::Compact)", pmx_verify_Compact(m, sigPrivmx));
    row("pmx    verify(m, sig, SigScheme::CompactWithHash)", pmx_verify_CompactWithHash(m, sigPrivmx));

    printf("\n  podpis wytworzony przez: pmx sign(m, SigScheme::Compact)\n");
    row("privmx verifyCompactSignatureWithHash(m, sig)", privmx_verifyWithHash(m, sigCompact));
    row("pmx    verify(m, sig, SigScheme::Compact)", pmx_verify_Compact(m, sigCompact));
    row("pmx    verify(m, sig, SigScheme::CompactWithHash)", pmx_verify_CompactWithHash(m, sigCompact));

    printf("\n  podpis wytworzony przez: pmx sign(m, SigScheme::CompactWithHash)\n");
    row("privmx verifyCompactSignatureWithHash(m, sig)", privmx_verifyWithHash(m, sigCWH));
    row("pmx    verify(m, sig, SigScheme::Compact)", pmx_verify_Compact(m, sigCWH));
    row("pmx    verify(m, sig, SigScheme::CompactWithHash)", pmx_verify_CompactWithHash(m, sigCWH));

    printf("\n=========================================================================\n");
    printf(" ZGODNOSC RAMKI 65B (niezalezna od problemu digestu)\n");
    printf("=========================================================================\n");
    printf("  bajt naglowka privmx  : 0x%02x (%d)\n", sigPrivmx[0], sigPrivmx[0]);
    printf("  bajt naglowka pmx     : 0x%02x (%d)\n", sigCompact[0], sigCompact[0]);
    printf("  uklad                 : [0]=tag, [1..32]=R, [33..64]=S  - identyczny\n");
    printf("  round-trip asn2rs/rs2asn zachowuje ASN.1: %s\n",
           hex(pmx_rs2asn(pmx_asn2rs(asn1))) == hex(asn1) ? "TAK" : "NIE");
    return 0;
}

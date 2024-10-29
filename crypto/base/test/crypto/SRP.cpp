#include <string>
#include <algorithm>
#include <gtest/gtest.h>
//#include <iostream>

#include <privmx/crypto/SRP.hpp>
#include <privmx/crypto/SrpLogic.hpp>
#include <privmx/utils/Utils.hpp>
#include <gmpxx.h>

using namespace std;

namespace privmx {
namespace crypto {
namespace {

TEST(SRPLogicTest, RegisterAndLogin) {
    EXPECT_TRUE(true);

    //wszystko jest napisane na sha1

    string N_16_string = "EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576"
                         "D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4 8E495C1D 6089DAD1"
                         "5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29 7BCF1885 C529F566 660E57EC"
                         "68EDBC3C 05726CC0 2FD4CBF4 976EAA9A FD5138FE 8376435B 9FC61D2F C0EB06E3";
    N_16_string.erase(remove(N_16_string.begin(), N_16_string.end(), ' '), N_16_string.end());
    mpz_class N(N_16_string, 16);

    mpz_class g(2);

    string I = "alice";
    string p = "password123";

    string s_16_string = "BEB25379 D1A8581E B5A72767 3A2441EE";
    s_16_string.erase(remove(s_16_string.begin(), s_16_string.end(), ' '), s_16_string.end());
    mpz_class s(s_16_string, 16);

    string k_16_string = "1A1A4C14 0CDE70AE 360C1EC33 A33155B1 022DF951 732A476A 862EB3A B8206A5C";
    k_16_string.erase(remove(k_16_string.begin(), k_16_string.end(), ' '), k_16_string.end());
    mpz_class k(k_16_string, 16);

    string x_16_string = "0065AC38 DFF8BC34 AE0F259E 91FBD0F4 CA2FA430 81C9050C EC7CAC20 D015F303";
    x_16_string.erase(remove(x_16_string.begin(), x_16_string.end(), ' '), x_16_string.end());
    mpz_class x(x_16_string, 16);

    string v_16_string = "27E2855A C715F625 981DBA23 8667955D B341A3BD D9198689 43BC0497 36C7804C"
                         "D8E0507D FEFBF5B8 573F5AAE 7BAC19B2 57034254 119AB520 E1F7CF3F 45D01B15"
                         "90168472 01D14C8D C95EC34E 8B26EE25 5BC4CB28 D4F97E0D B97B65BD D196C4D2"
                         "951CD84F 493AFD7B 34B90984 35798860 1A364335 8B81689D FD0CB0D2 1E21CF6E";
    v_16_string.erase(remove(v_16_string.begin(), v_16_string.end(), ' '), v_16_string.end());
    mpz_class v(v_16_string, 16);

    string a_16_string = "60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393";
    a_16_string.erase(remove(a_16_string.begin(), a_16_string.end(), ' '), a_16_string.end());
    mpz_class a(a_16_string, 16);

    string b_16_string = "E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20";
    b_16_string.erase(remove(b_16_string.begin(), b_16_string.end(), ' '), b_16_string.end());
    mpz_class b(b_16_string, 16);

    string A_16_string = "61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4 4352E890"
                         "3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC 8E393561 79EAE45E"
                         "42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44 BE087EF0 6530E69F 66615261"
                         "EEF54073 CA11CF58 58F0EDFD FE15EFEA B349EF5D 76988A36 72FAC47B 0769447B";
    A_16_string.erase(remove(A_16_string.begin(), A_16_string.end(), ' '), A_16_string.end());
    mpz_class A(A_16_string, 16);

    string B_16_string = "439B7630 EC82C94D 3BBD466A 068D663A 40B8D5B1 D9B006BA 43F5D715 498088CC"
                         "A8547BBE 3DE6406C 79F15FFA 7356BC93 580E4783 22DAF8B2 D0143478 59234F01"
                         "555C457A B8B7F214 875224FC 9BFD07A6 8F37BAD4 D74BC846 7CE10EA3 9301D360"
                         "4E91FFF5 F881D52C 558187E6 8FAC3268 DF289730 7DA5C58A 8C667E0F A8DC837E";
    B_16_string.erase(remove(B_16_string.begin(), B_16_string.end(), ' '), B_16_string.end());
    mpz_class B(B_16_string, 16);

    string u_16_string = "C557AF60 30C3DF27 B4704462 DF2ECEAE AED5D16B 4C7D87FD F992E282 F985293E";
    u_16_string.erase(remove(u_16_string.begin(), u_16_string.end(), ' '), u_16_string.end());
    mpz_class u(u_16_string, 16);

    string S_16_string = "7094D74B 440EA4BF FA275269 4F196002 68D61893 AD55CAC7 59A18378 DCE55020"
                         "742DF26F 96965154 82626372 AF87D447 88D931E6 0BA0D4D8 B31984B3 0BA285D5"
                         "DB443753 ADE4504A E124EB63 D16DB568 E6850ADF 953B353C 1255E8EC 230E59A9"
                         "04F37840 02845A31 D12D8F44 8DD6D1BC 3ECDED0B BA328046 B907546F 9E3B338C";
    S_16_string.erase(remove(S_16_string.begin(), S_16_string.end(), ' '), S_16_string.end());
    mpz_class S(S_16_string, 16);

    
    EXPECT_EQ(SrpLogic::get_k(g,N).get_str(16), k.get_str(16));
    EXPECT_EQ(SrpLogic::get_x(privmx::utils::Hex::toString(s.get_str(16)),I,p).get_str(16), x.get_str(16));
    EXPECT_EQ(SrpLogic::get_v(g,N,x).get_str(16), v.get_str(16));
    EXPECT_EQ(SrpLogic::get_A(g,N,a).get_str(16), A.get_str(16));
    EXPECT_EQ(SrpLogic::get_u(A,B,N).get_str(16), u.get_str(16));
    EXPECT_EQ(SrpLogic::getClient_S(B,k,v,a,u,x,N).get_str(16), S.get_str(16));

}


} // namespace
} // namespace crypto
} // namespace privmx
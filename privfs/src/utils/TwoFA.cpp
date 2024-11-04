/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/ByteOrder.h>
#include <Poco/Timestamp.h>
#include <Poco/Types.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/TwoFA.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using Poco::JSON::Object;

Object::Ptr TwoFA::generateToken(const string& secret) {
    Int64 current_timestamp = Timestamp().raw() / 30000000;
    string key = Base32::decode(Utils::formatToBase32(secret));
    UInt64 ts = ByteOrder::toBigEndian(UInt64(current_timestamp));
    string message = string((const char *)&ts, 8);
    string h = Crypto::hmacSha1(key, message);
    int offset = h[19] & 0xf;
    UInt32 v = ByteOrder::fromBigEndian((*(UInt32 *)(h.data() + offset))) & 0x7fffffff;
    string token = to_string(v % 1000000);

    Object::Ptr result = new Object();
    result->set("token", string(6 - token.length(), '0') + token);
    result->set("startTimestamp", Int64(current_timestamp * 30));
    result->set("expiryTimestamp", Int64((current_timestamp + 1) * 30));
    return result;
}

Object::Ptr TwoFA::generateToken(const Poco::JSON::Object::Ptr data) {
    string secret = data->getValue<string>("secret");
    string algorithm = data->getValue<string>("algorithm");
    int digits = data->getValue<int>("digits");
    int period = data->getValue<int>("period");
    
    Int64 current_timestamp = Timestamp().raw() / (period * 1000000);
    string key = Base32::decode(Utils::formatToBase32(secret));
    UInt64 ts = ByteOrder::toBigEndian(UInt64(current_timestamp));
    string message = string((const char *)&ts, 8);
    string h;
    if (algorithm == "SHA1") {
        h = Crypto::hmacSha1(key, message);
    } else if (algorithm == "SHA256") {
        h = Crypto::hmacSha256(key, message);
    } else if (algorithm == "SHA512") {
        h = Crypto::hmacSha512(key, message);
    }
    
    int offset = h[19] & 0xf;
    UInt32 v = ByteOrder::fromBigEndian((*(UInt32 *)(h.data() + offset))) & 0x7fffffff;
    string token = to_string(v % Int32(digits == 6 ? 1000000 : 100000000));

    Object::Ptr result = new Object();
    result->set("token", string(digits - token.length(), '0') + token);
    result->set("startTimestamp", Int64(current_timestamp * period));
    result->set("expiryTimestamp", Int64(current_timestamp * period + period));
    return result;
}

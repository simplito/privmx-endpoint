// Creates the bridge-side half of a dataset: an API key, a solution, two contexts and three users,
// then writes `ServerData.ini` for `DockerSetupData` to append its fixtures to.
//
// This used to be `DockerSetupInit.sh`, which carried the three users' key pairs as literals. That
// cannot work once more than one key algorithm exists: a user is registered under the exact string of
// their public key, so the keys in a dataset have to be the ones a client built from this very tree
// will present. Here they are derived by the library itself, so they follow
// `PRIVMX_DEFAULT_KEY_ALGORITHM` with no list to keep in step and nothing to pass in by hand.
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>

#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/BackendRequester.hpp>
#include <privmx/endpoint/core/Exception.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>
#include <privmx/utils/Utils.hpp>

using namespace std;
using namespace privmx;
using namespace privmx::endpoint;

namespace {

/**
 * The three identities every dataset is built on.
 *
 * Only the *secrets* are fixed. The keys come from `PrivateKey::fromRaw`, which builds an identity of
 * whatever algorithm this build generates with, so the same three users come out as secp256k1 or as
 * Ed25519 depending on nothing but `PRIVMX_DEFAULT_KEY_ALGORITHM`.
 *
 * They are the secrets the datasets have always used, so a secp256k1 build still produces exactly the
 * keys recorded in `test/env/datasets/Dataset` and the dataset does not churn.
 */
constexpr array<const char*, 3> USER_SECRETS_HEX{
    "1bc25e645a5ebc87b2b6d3f58b191cfd00edb0e7a765f12b3d39a12144e8c824",
    "982cd19c58f22eb0d66a0ac84733d1350a937705b0aab415a56d5fdeccbfa611",
    "2612bbe901594900e64054b48567c40cd77a2a220a3abf7c7f13a0baae3ddd59",
};

struct Identity {
    string id;
    string privKey;
    string pubKey;
};

struct ApiKey {
    string id;
    string secret;
};

/// A deleter type rather than `decltype(&pclose)`: `pclose` is declared with attributes, and naming
/// its function-pointer type as a template argument drops them, which the compiler warns about.
struct PipeCloser {
    void operator()(FILE* pipe) const { pclose(pipe); }
};

string runCommand(const string& command) {
    array<char, 256> buffer{};
    string output;
    unique_ptr<FILE, PipeCloser> pipe(popen(command.c_str(), "r"));
    if (pipe == nullptr) {
        throw runtime_error("cannot run: " + command);
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        output += buffer.data();
    }
    // Closed by hand so the child's exit status can be read — a deleter has nowhere to report it, and
    // a command that fails must not be mistaken for one that printed nothing. That is how the shell
    // version this replaced let a broken bridge pass for a working one. The handle above still covers
    // the throwing path.
    const int status = pclose(pipe.release());
    if (status != 0) {
        throw runtime_error(
            command + " exited with status " + to_string(status) + (output.empty() ? "" : ":\n" + output)
        );
    }
    return output;
}

/// Reads `KEY=value` lines, which is the shape `pmxbridge_createapikey` prints and `api_key.ini` keeps.
string valueOf(const string& text, const string& key) {
    const string needle = key + "=";
    size_t at = text.find(needle);
    if (at == string::npos) {
        throw runtime_error("no " + key + " in:\n" + text);
    }
    at += needle.size();
    size_t end = text.find_first_of("\r\n", at);
    return text.substr(at, end == string::npos ? string::npos : end - at);
}

ApiKey createApiKey(const string& dockerName) {
    cout << "Creating api key" << endl;
    const string printed = runCommand("docker exec " + dockerName + " pmxbridge_createapikey");
    // Kept on disk because the dataset's consumers expect to find it there, same as before.
    ofstream file("api_key.ini", ios::trunc);
    file << printed;
    file.close();
    return ApiKey{.id = valueOf(printed, "API_KEY_ID"), .secret = valueOf(printed, "API_KEY_SECRET")};
}

class Bridge {
public:
    Bridge(string url, ApiKey apiKey) : _url(std::move(url)), _apiKey(std::move(apiKey)) {}

    /**
     * One JSON-RPC call, through the endpoint's own `BackendRequester` rather than curl.
     *
     * Unlike the shell version this *checks the answer*. That script only echoed what came back, so a
     * bridge that refused every user — an image too old to know a key's algorithm tag, say — looked
     * exactly like a successful run, and the mistake only surfaced much later as a login failure.
     */
    Poco::JSON::Object::Ptr call(const string& method, Poco::JSON::Object::Ptr params) {
        const string raw = core::BackendRequester::backendRequest(
            _url, _apiKey.id, _apiKey.secret, 0, method, utils::Utils::stringify(params)
        );
        Poco::JSON::Object::Ptr response = utils::Utils::parseJsonObject(raw);
        if (response->has("error") || !response->has("result")) {
            throw runtime_error(method + " failed: " + raw);
        }
        // The bridge needs a moment between writes for the next call to see them; inherited from the
        // shell version, which slept after every curl.
        this_thread::sleep_for(chrono::milliseconds(500));
        return response->getObject("result");
    }

private:
    string _url;
    ApiKey _apiKey;
};

Poco::JSON::Object::Ptr params() {
    return Poco::JSON::Object::Ptr(new Poco::JSON::Object());
}

Identity identityFor(size_t index) {
    const string secret = utils::Hex::toString(USER_SECRETS_HEX.at(index));
    const core::PrivateKey priv = core::PrivateKey::fromRaw(secret);
    return Identity{
        .id = "user_" + to_string(index + 1),
        // Both halves are self-describing: a secp256k1 private key spells itself as a WIF, any other
        // as `Base58Check(algTag || secret)`, and a public key always carries its tag. So a dataset
        // can be read by a build configured for a different algorithm than the one that wrote it.
        .privKey = priv.toWIF(),
        .pubKey = priv.getPublicKey().toBase58DER(),
    };
}

string createContext(Bridge& bridge, const string& solutionId, const string& name, const string& description) {
    cout << "Creating " << name << endl;
    auto p = params();
    p->set("name", name);
    p->set("solution", solutionId);
    p->set("description", description);
    p->set("scope", "private");
    return bridge.call("context/createContext", p)->getValue<string>("contextId");
}

void addUserToContext(Bridge& bridge, const string& contextId, const Identity& user) {
    cout << "Adding " << user.id << " to " << contextId << endl;
    auto p = params();
    p->set("contextId", contextId);
    p->set("userId", user.id);
    p->set("userPubKey", user.pubKey);
    bridge.call("context/addUserToContext", p);
}

void writeServerData(
    const array<Identity, 3>& users,
    const string& solutionId,
    const ApiKey& apiKey,
    const string& contextId_1,
    const string& contextId_2
) {
    // Truncating, not appending: `DockerSetupData` appends its fixtures to this file afterwards, so a
    // leftover from an earlier run would be read as part of this dataset.
    ofstream ini("ServerData.ini", ios::trunc);
    ini << "[Login]\n";
    for (const auto& user : users) {
        ini << user.id << "_privKey = " << user.privKey << "\n"
            << user.id << "_pubKey = " << user.pubKey << "\n"
            << user.id << "_id = " << user.id << "\n";
    }
    ini << "solutionId = " << solutionId << "\n"
        << "instanceUrl = http://localhost/\n"
        << "[Api]\n"
        << "apiKeyId = " << apiKey.id << "\n"
        << "apiKeySecret = " << apiKey.secret << "\n"
        << "[Context_1]\n"
        << "contextId = " << contextId_1 << "\n"
        << "[Context_2]\n"
        << "contextId = " << contextId_2 << "\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        cerr << "usage: " << argv[0] << " <teamserver docker container name>" << endl;
        return 1;
    }
    try {
        const char* port = getenv("DOCKER_BRIDGE_PORT");
        if (port == nullptr) {
            throw runtime_error("DOCKER_BRIDGE_PORT is not set; it comes from default_values.sh");
        }
        const ApiKey apiKey = createApiKey(argv[1]);
        Bridge bridge("http://localhost:" + string(port), apiKey);

        cout << "Creating solution" << endl;
        auto solutionParams = params();
        solutionParams->set("name", "Main");
        const string solutionId =
            bridge.call("solution/createSolution", solutionParams)->getValue<string>("solutionId");

        cout << "Creating Contexts" << endl;
        const string contextId_1 = createContext(bridge, solutionId, "MainContext", "Context nr 1");
        const string contextId_2 = createContext(bridge, solutionId, "SecondaryContext", "Context nr 2");

        const array<Identity, 3> users{identityFor(0), identityFor(1), identityFor(2)};

        cout << "Adding users to Contexts" << endl;
        for (const auto& user : users) {
            addUserToContext(bridge, contextId_1, user);
            addUserToContext(bridge, contextId_2, user);
        }

        writeServerData(users, solutionId, apiKey, contextId_1, contextId_2);
        return 0;
    } catch (const core::Exception& e) {
        cerr << e.getFull() << endl;
        return 1;
    } catch (const exception& e) {
        cerr << e.what() << endl;
        return 1;
    }
}

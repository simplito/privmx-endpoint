/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Pson/BinaryString.hpp>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/kvdb/cinterface/kvdb.h"
#include "privmx/endpoint/kvdb/varinterface/KvdbApiVarInterface.hpp"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/cinterface/InterfaceException.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>
#include <privmx/endpoint/group/varinterface/GroupApiVarInterface.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newKvdbApi(Connection* connectionPtr, GroupApi* groupApiPtr, KvdbApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    group::GroupApiVarInterface* _groupApiPtr = (group::GroupApiVarInterface*)groupApiPtr;
    kvdb::KvdbApiVarInterface* ptr = new kvdb::KvdbApiVarInterface(
        _connectionPtr->getApi(),
        core::VarSerializer::Options{.addType = true, .binaryFormat = core::VarSerializer::Options::PSON_BINARYSTRING},
        _groupApiPtr ? std::make_optional(_groupApiPtr->getApi()) : std::nullopt
    );
    *outPtr = (KvdbApi*)ptr;
    return 1;
}

int privmx_endpoint_freeKvdbApi(KvdbApi* ptr) {
    delete (kvdb::KvdbApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execKvdbApi(KvdbApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&] {
        kvdb::KvdbApiVarInterface* _ptr = (kvdb::KvdbApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((kvdb::KvdbApiVarInterface::METHOD)method, argsVal);
    });
}
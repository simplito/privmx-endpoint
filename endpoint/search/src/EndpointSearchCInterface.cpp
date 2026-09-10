/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/search/cinterface/search.h"
#include "privmx/endpoint/search/varinterface/SearchApiVarInterface.hpp"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>
#include <privmx/endpoint/kvdb/varinterface/KvdbApiVarInterface.hpp>
#include <privmx/endpoint/lock/varinterface/LockApiVarInterface.hpp>
#include <privmx/endpoint/store/varinterface/StoreApiVarInterface.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newSearchApi(
    Connection* connectionPtr,
    StoreApi* storeApiPtr,
    KvdbApi* kvdbApiPtr,
    LockApi* lockApiPtr,
    SearchApi** outPtr
) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    store::StoreApiVarInterface* _storeApiPtr = (store::StoreApiVarInterface*)storeApiPtr;
    kvdb::KvdbApiVarInterface* _kvdbApiPtr = (kvdb::KvdbApiVarInterface*)kvdbApiPtr;
    lock::LockApiVarInterface* _lockApiPtr = (lock::LockApiVarInterface*)lockApiPtr;
    search::SearchApiVarInterface* ptr = new search::SearchApiVarInterface(
        _connectionPtr->getApi(), _storeApiPtr->getApi(), _kvdbApiPtr->getApi(), _lockApiPtr->getApi(),
        core::VarSerializer::Options{.addType = true, .binaryFormat = core::VarSerializer::Options::PSON_BINARYSTRING}
    );
    *outPtr = (SearchApi*)ptr;
    return 1;
}

int privmx_endpoint_freeSearchApi(SearchApi* ptr) {
    delete (search::SearchApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execSearchApi(SearchApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&] {
        search::SearchApiVarInterface* _ptr = (search::SearchApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((search::SearchApiVarInterface::METHOD)method, argsVal);
    });
}

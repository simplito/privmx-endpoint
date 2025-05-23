/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <functional>
#include <string>
#include <unordered_map>
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Pson/BinaryString.hpp>

#include <privmx/utils/Utils.hpp>


#include "privmx/endpoint/inbox/cinterface/inbox.h"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/cinterface/InterfaceException.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>
#include <privmx/endpoint/thread/varinterface/ThreadApiVarInterface.hpp>
#include <privmx/endpoint/store/varinterface/StoreApiVarInterface.hpp>
#include "privmx/endpoint/inbox/varinterface/InboxApiVarInterface.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newInboxApi(Connection* connectionPtr, ThreadApi* threadApiPtr, StoreApi* storeApiPtr, InboxApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    thread::ThreadApiVarInterface* _threadApiPtr = (thread::ThreadApiVarInterface*)threadApiPtr;
    store::StoreApiVarInterface* _storeApiPtr = (store::StoreApiVarInterface*)storeApiPtr;
    inbox::InboxApiVarInterface* ptr = new inbox::InboxApiVarInterface(_connectionPtr->getApi(), _threadApiPtr->getApi(), _storeApiPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (InboxApi*)ptr;
    return 1;
}

int privmx_endpoint_freeInboxApi(InboxApi* ptr) {
    delete (inbox::InboxApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execInboxApi(InboxApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        inbox::InboxApiVarInterface* _ptr = (inbox::InboxApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((inbox::InboxApiVarInterface::METHOD)method, argsVal);
    });
}
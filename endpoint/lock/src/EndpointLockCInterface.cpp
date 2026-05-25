/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <Poco/Dynamic/Var.h>

#include "privmx/endpoint/lock/cinterface/lock.h"
#include "privmx/endpoint/lock/varinterface/LockApiVarInterface.hpp"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newLockApi(Connection* connectionPtr, LockApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    lock::LockApiVarInterface* ptr = new lock::LockApiVarInterface(
        _connectionPtr->getApi(),
        core::VarSerializer::Options{.addType = true, .binaryFormat = core::VarSerializer::Options::PSON_BINARYSTRING}
    );
    *outPtr = (LockApi*)ptr;
    return 1;
}

int privmx_endpoint_freeLockApi(LockApi* ptr) {
    delete (lock::LockApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execLockApi(LockApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&] {
        lock::LockApiVarInterface* _ptr = (lock::LockApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((lock::LockApiVarInterface::METHOD)method, argsVal);
    });
}

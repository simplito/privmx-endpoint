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

#include "privmx/endpoint/interface/thread/thread.h"
#include "privmx/endpoint/interface/core/CApiExecutor.hpp"
#include "privmx/endpoint/interface/core/InterfaceException.hpp"

#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"
#include "privmx/endpoint/thread/varinterface/ThreadApiVarInterface.hpp"
#include "privmx/endpoint/core/Config.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newThreadApi(Connection* connectionPtr, ThreadApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    thread::ThreadApiVarInterface* ptr = new thread::ThreadApiVarInterface(_connectionPtr->getApi(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (ThreadApi*)ptr;
    return 1;
}

int privmx_endpoint_freeThreadApi(ThreadApi* ptr) {
    delete (thread::ThreadApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execThreadApi(ThreadApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        thread::ThreadApiVarInterface* _ptr = (thread::ThreadApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((thread::ThreadApiVarInterface::METHOD)method, argsVal);
    });
}
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

#include "privmx/endpoint/core/cinterface/core.h"
#include "privmx/endpoint/core/cinterface/CApiExecutor.hpp"
#include "privmx/endpoint/core/cinterface/InterfaceException.hpp"

#include "privmx/endpoint/core/varinterface/BackendRequesterVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/EventQueueVarInterface.hpp"
#include "privmx/endpoint/core/varinterface/UtilsVarInterface.hpp"
#include "privmx/endpoint/core/Config.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newEventQueue(EventQueue** outPtr) {
    core::EventQueueVarInterface* ptr = new core::EventQueueVarInterface(core::EventQueue::getInstance(), core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (EventQueue*)ptr;
    return 1;
}

int privmx_endpoint_freeEventQueue(EventQueue* ptr) {
    delete (core::EventQueueVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execEventQueue(EventQueue* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        core::EventQueueVarInterface* _ptr = (core::EventQueueVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((core::EventQueueVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newConnection(Connection** outPtr) {
    core::ConnectionVarInterface* ptr = new core::ConnectionVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (Connection*)ptr;
    return 1;
}

int privmx_endpoint_freeConnection(Connection* ptr) {
    delete (core::ConnectionVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_setUserVerifier(Connection* ptr, void* ctx, privmx_user_verifier verifier, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        core::ConnectionVarInterface* _ptr = (core::ConnectionVarInterface*)ptr;
        return _ptr->setUserVerifier(
            [ctx, verifier](const Poco::Dynamic::Var& request) {
                pson_value* res = nullptr;
                pson_value* args = (pson_value*)(new Poco::Dynamic::Var(request)); // alock memory
                try {
                    verifier(ctx, args, &res);
                } catch (...) {
                    //memory leeks protection
                    if(args != nullptr) { // free args memory
                        delete (Poco::Dynamic::Var*)args; 
                        args = nullptr;
                    }
                    if(res != nullptr) { // free res memory
                        pson_free_value(res); 
                        res = nullptr;
                    }
                    // rethrow captured exception
                    std::exception_ptr e_ptr = std::current_exception();
                    if(e_ptr) {
                        std::rethrow_exception(e_ptr);
                    }
                }
                if(args != nullptr) { // free args memory
                    delete (Poco::Dynamic::Var*)args;
                    args = nullptr;
                }
                const Poco::Dynamic::Var resVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(res));
                if(res != nullptr) { // free res memory
                    pson_free_value(res); 
                    res = nullptr;
                }
                return resVal;
            }
        );
    });
}

int privmx_endpoint_execConnection(Connection* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        core::ConnectionVarInterface* _ptr = (core::ConnectionVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((core::ConnectionVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newBackendRequester(BackendRequester** outPtr) {
    core::BackendRequesterVarInterface* ptr = new core::BackendRequesterVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (BackendRequester*)ptr;
    return 1;
}

int privmx_endpoint_freeBackendRequester(BackendRequester* ptr) {
    delete (core::BackendRequesterVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execBackendRequester(BackendRequester* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        core::BackendRequesterVarInterface* _ptr = (core::BackendRequesterVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((core::BackendRequesterVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_newUtils(Utils** outPtr) {
    core::UtilsVarInterface* ptr = new core::UtilsVarInterface(core::VarSerializer::Options{.addType=true, .binaryFormat=core::VarSerializer::Options::PSON_BINARYSTRING});
    *outPtr = (Utils*)ptr;
    return 1;
}

int privmx_endpoint_freeUtils(Utils* ptr) {
    delete (core::UtilsVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execUtils(Utils* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&]{
        core::UtilsVarInterface* _ptr = (core::UtilsVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((core::UtilsVarInterface::METHOD)method, argsVal);
    });
}

int privmx_endpoint_setCertsPath(const char* certsPath) {
    try {
        core::Config::setCertsPath(certsPath);
        return 1;
    } catch(...) {}
    return 0;
}

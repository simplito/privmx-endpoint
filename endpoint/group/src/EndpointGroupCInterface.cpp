#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Array.h>
#include <Pson/BinaryString.hpp>
#include <functional>
#include <string>
#include <unordered_map>

#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/cinterface/group.h"
#include "privmx/endpoint/group/varinterface/GroupApiVarInterface.hpp"
#include <privmx/endpoint/core/cinterface/CApiExecutor.hpp>
#include <privmx/endpoint/core/cinterface/InterfaceException.hpp>
#include <privmx/endpoint/core/varinterface/ConnectionVarInterface.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::cinterface;

int privmx_endpoint_newGroupApi(Connection* connectionPtr, GroupApi** outPtr) {
    core::ConnectionVarInterface* _connectionPtr = (core::ConnectionVarInterface*)connectionPtr;
    group::GroupApiVarInterface* ptr = new group::GroupApiVarInterface(
        _connectionPtr->getApi(),
        core::VarSerializer::Options{.addType = true, .binaryFormat = core::VarSerializer::Options::PSON_BINARYSTRING}
    );
    *outPtr = (GroupApi*)ptr;
    return 1;
}

int privmx_endpoint_freeGroupApi(GroupApi* ptr) {
    delete (group::GroupApiVarInterface*)ptr;
    return 1;
}

int privmx_endpoint_execGroupApi(GroupApi* ptr, int method, const pson_value* args, pson_value** res) {
    return CApiExecutor::execFunc(res, [&] {
        group::GroupApiVarInterface* _ptr = (group::GroupApiVarInterface*)ptr;
        const Poco::Dynamic::Var argsVal = *(reinterpret_cast<const Poco::Dynamic::Var*>(args));
        return _ptr->exec((group::GroupApiVarInterface::METHOD)method, argsVal);
    });
}

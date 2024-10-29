#include "privmx/endpoint/core/EventVarSerializer.hpp"

using namespace privmx::endpoint::core;

std::shared_ptr<VarSerializer> EventVarSerializer::_serializer;

std::shared_ptr<VarSerializer> EventVarSerializer::getInstance() {
    if (!_serializer) {
        _serializer = std::make_shared<VarSerializer>(
            VarSerializer::Options{.addType = true, .binaryFormat = VarSerializer::Options::PSON_BINARYSTRING});
    }
    return _serializer;
}

/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

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

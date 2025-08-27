/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Mapper.hpp"

using namespace privmx::endpoint::core;

CollectionItemChange Mapper::mapToCollectionChangeItem(const server::CollectionItemChange& data) {
    return {
        .itemId = data.itemId(),
        .action = data.action()
    };
}

std::vector<CollectionItemChange> Mapper::mapToCollectionChangeItems(const privmx::utils::List<server::CollectionItemChange>& data) {
    std::vector<CollectionItemChange> result;
    result.reserve(data.size());
    for (auto item : data) {
        result.push_back(mapToCollectionChangeItem(item));
    }
    return result;
}

CollectionChangeEventData Mapper::mapToCollectionChangeEventData(const std::string& moduleType, const server::CollectionChangeEventData& data) {
    return {
        .moduleType = moduleType,
        .moduleId = data.containerId(),
        .affectedItemsCount = data.affectedItemsCount(),
        .items = mapToCollectionChangeItems(data.items())

    };
}

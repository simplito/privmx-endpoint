/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/Factory.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include <Poco/Dynamic/Var.h>
#include <Poco/JSON/Object.h>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core;

Poco::Dynamic::Var Factory::createPolicyServerObject(const privmx::endpoint::core::ContainerPolicy& policy) {
    Poco::JSON::Object::Ptr model = new Poco::JSON::Object();
    if (policy.get.has_value()) {
        model->set("get", policy.get.value());
    }
    if (policy.listMy.has_value()) {
        model->set("listMy", policy.listMy.value());
    }
    if (policy.listAll.has_value()) {
        model->set("listAll", policy.listAll.value());
    }
    if (policy.create.has_value()) {
        model->set("create", policy.create.value());
    }
    if (policy.update.has_value()) {
        model->set("update", policy.update.value());
    }
    if (policy.delete_.has_value()) {
        model->set("delete", policy.delete_.value());
    }
    if (policy.updatePolicy.has_value()) {
        model->set("updatePolicy", policy.updatePolicy.value());
    }
    if (policy.creatorHasToBeManager.has_value()) {
        model->set("creatorHasToBeManager", policy.creatorHasToBeManager.value());
    }
    if (policy.updaterCanBeRemovedFromManagers.has_value()) {
        model->set("updaterCanBeRemovedFromManagers", policy.updaterCanBeRemovedFromManagers.value());
    }
    if (policy.ownerCanBeRemovedFromManagers.has_value()) {
        model->set("ownerCanBeRemovedFromManagers", policy.ownerCanBeRemovedFromManagers.value());
    }
    if (policy.canOverwriteContextPolicy.has_value()) {
        model->set("canOverwriteContextPolicy", policy.canOverwriteContextPolicy.value());
    }
    if (policy.item.has_value()) {
        Poco::JSON::Object::Ptr itemModel = new Poco::JSON::Object();
        auto itemPolicy = policy.item.value();

        if (itemPolicy.get.has_value()) {
            itemModel->set("get", itemPolicy.get.value());
        }
        if (itemPolicy.listMy.has_value()) {
            itemModel->set("listMy", itemPolicy.listMy.value());
        }
        if (itemPolicy.listAll.has_value()) {
            itemModel->set("listAll", itemPolicy.listAll.value());
        }
        if (itemPolicy.create.has_value()) {
            itemModel->set("create", itemPolicy.create.value());
        }
        if (itemPolicy.update.has_value()) {
            itemModel->set("update", itemPolicy.update.value());
        }
        if (itemPolicy.delete_.has_value()) {
            itemModel->set("delete", itemPolicy.delete_.value());
        }
        
        model->set("item", itemModel);
    }

    return model;
}


Poco::Dynamic::Var Factory::createPolicyServerObject(const privmx::endpoint::core::ContainerPolicyWithoutItem& policy) {
    Poco::JSON::Object::Ptr model = new Poco::JSON::Object();
    if (policy.get.has_value()) {
        model->set("get", policy.get.value());
    }
    if (policy.listMy.has_value()) {
        model->set("listMy", policy.listMy.value());
    }
    if (policy.listAll.has_value()) {
        model->set("listAll", policy.listAll.value());
    }
    if (policy.create.has_value()) {
        model->set("create", policy.create.value());
    }
    if (policy.update.has_value()) {
        model->set("update", policy.update.value());
    }
    if (policy.delete_.has_value()) {
        model->set("delete", policy.delete_.value());
    }
    if (policy.updatePolicy.has_value()) {
        model->set("updatePolicy", policy.updatePolicy.value());
    }
    if (policy.creatorHasToBeManager.has_value()) {
        model->set("creatorHasToBeManager", policy.creatorHasToBeManager.value());
    }
    if (policy.updaterCanBeRemovedFromManagers.has_value()) {
        model->set("updaterCanBeRemovedFromManagers", policy.updaterCanBeRemovedFromManagers.value());
    }
    if (policy.ownerCanBeRemovedFromManagers.has_value()) {
        model->set("ownerCanBeRemovedFromManagers", policy.ownerCanBeRemovedFromManagers.value());
    }
    if (policy.canOverwriteContextPolicy.has_value()) {
        model->set("canOverwriteContextPolicy", policy.canOverwriteContextPolicy.value());
    }
    return model;
}



ContainerPolicy Factory::parsePolicyServerObject(const Poco::Dynamic::Var& serverPolicyObject) {
    if (serverPolicyObject.isEmpty()) {
        return {};
    }
    Poco::JSON::Object::Ptr obj = serverPolicyObject.extract<Poco::JSON::Object::Ptr>();
    ContainerPolicy result {};
    result.get = obj->optValue<std::string>("get", std::string());
    result.listMy = obj->optValue<std::string>("listMy", std::string());
    result.listAll = obj->optValue<std::string>("listAll", std::string());
    result.create = obj->optValue<std::string>("create", std::string());
    result.update = obj->optValue<std::string>("update", std::string());
    result.delete_ = obj->optValue<std::string>("delete", std::string());
    result.updatePolicy = obj->optValue<std::string>("updatePolicy", std::string());
    result.creatorHasToBeManager = obj->optValue<std::string>("creatorHasToBeManager", std::string());
    result.updaterCanBeRemovedFromManagers = obj->optValue<std::string>("updaterCanBeRemovedFromManagers", std::string());
    result.ownerCanBeRemovedFromManagers = obj->optValue<std::string>("ownerCanBeRemovedFromManagers", std::string());
    result.canOverwriteContextPolicy = obj->optValue<std::string>("canOverwriteContextPolicy", std::string());

    if (obj->isObject("item")) {
        auto itemObj = obj->getObject("item");
        ItemPolicy itemResult {};
        itemResult.get = itemObj->optValue<std::string>("get", std::string());
        itemResult.listMy = itemObj->optValue<std::string>("listMy", std::string());
        itemResult.listAll = itemObj->optValue<std::string>("listAll", std::string());
        itemResult.create = itemObj->optValue<std::string>("create", std::string());
        itemResult.update = itemObj->optValue<std::string>("update", std::string());
        itemResult.delete_ = itemObj->optValue<std::string>("delete", std::string());
        result.item = itemResult;
    }        
    return result;
}


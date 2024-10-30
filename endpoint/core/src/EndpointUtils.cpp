#include "privmx/endpoint/core/EndpointUtils.hpp"

using namespace privmx::endpoint::core;

std::vector<privmx::endpoint::core::UserWithPubKey> EndpointUtils::uniqueListUserWithPubKey(const std::vector<core::UserWithPubKey>& list1, const std::vector<core::UserWithPubKey>& list2) {
    std::map<std::string, core::UserWithPubKey> map;
    for(const auto &a : list1) {
        map[a.userId+a.pubKey] = a;
    }
    for(const auto &a : list2) {
        map[a.userId+a.pubKey] = a;
    }
    std::vector<core::UserWithPubKey> unique_list;
    for(const auto &a : map) {
        unique_list.push_back(a.second);
    }
    return unique_list;
}


std::vector<std::string> EndpointUtils::getDifference(const std::vector<std::string>& baseList, const std::vector<std::string>& subList) {
    auto vec1 {baseList};
    auto vec2 {subList};
    std::sort(vec1.begin(), vec1.end());
    std::sort(vec2.begin(), vec2.end());
    std::vector<std::string> diff{};

    size_t i = 0;
    while (i < vec1.size() && i < vec2.size() && vec1[i].compare(vec2[i]) == 0) {
        i++;
    }
    for (size_t n = i; n < vec1.size(); ++n) {
        if (std::find(vec2.begin() + i, vec2.end(), vec1[n]) == vec2.end()) {
            diff.push_back(vec1[n]);
        }
    }
    return diff;
}

std::vector<std::string> EndpointUtils::uniqueList(const std::vector<std::string> &list1, const std::vector<std::string> &list2) {
    std::set<std::string> input{};
    std::vector<std::string> output;
    for (auto & x : list1) {
        input.insert(x);
    }
    for (auto & x : list2) {
        input.insert(x);
    }
    std::copy(input.begin(), input.end(), std::back_inserter(output));
    return output;
}

std::vector<std::string> EndpointUtils::usersWithPubKeyToIds(std::vector<core::UserWithPubKey>& users) {
    std::vector<std::string> ids{};
    for (auto & user : users) {
        ids.push_back(user.userId);
    }
    return ids;
}
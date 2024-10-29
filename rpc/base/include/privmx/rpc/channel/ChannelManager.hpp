#ifndef _PRIVMXLIB_RPC_CHANNELMANAGER_HPP_
#define _PRIVMXLIB_RPC_CHANNELMANAGER_HPP_

#include <future>
#include <istream>
#include <unordered_map>
#include <Poco/URI.h>
#include <Poco/SharedPtr.h>

#include <privmx/rpc/channel/SingleServerChannels.hpp>
#include <privmx/utils/Types.hpp>

namespace privmx {
namespace rpc {

class ChannelManager
{
public:
    using Ptr = Poco::SharedPtr<ChannelManager>;

    static ChannelManager::Ptr getInstance();
    SingleServerChannels::Ptr add(const Poco::URI& uri);
    void remove(const Poco::URI& uri);

private:
    struct SingleServer
    {
        SingleServerChannels::Ptr server;
        int count;
    };

    static ChannelManager::Ptr _instance;
    std::unordered_map<std::string, SingleServer> _servers;
    utils::Mutex _servers_mutex;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_CHANNELMANAGER_HPP_

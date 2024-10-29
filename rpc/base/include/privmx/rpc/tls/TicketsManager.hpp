#ifndef _PRIVMXLIB_RPC_TICKETSMANAGER_HPP_
#define _PRIVMXLIB_RPC_TICKETSMANAGER_HPP_

#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <Poco/JSON/Array.h>
#include <Poco/Types.h>

namespace privmx {
namespace rpc {

struct SessionTicket {
    SessionTicket(const std::string& id, const std::string& master_secret) : id(id), master_secret(master_secret) {}
    std::string id;
    std::string master_secret;
};

class TicketsManager
{
public:
    void saveTickets(const Poco::JSON::Array::Ptr tickets, int ttl, const std::string& master_secret);
    SessionTicket useTicket();
    void clear();
    unsigned int ticketsCount();
    bool shouldAskForNewTickets(Poco::Int32 min_count);

    std::function<void(void)> on_tickets_equal_zero;
    std::mutex request_mutex;

private:
    static const Poco::Int64 NULL_TTL = -1;

    void dropExpiredTickets();

    std::multimap<Poco::Int64, SessionTicket> _tickets;
    std::mutex _tickets_mutex;
    Poco::Int64 _min_ticket_ttl = 5 * 1000;
    Poco::Int64 _ttl_threshold = 15 * 1000;
    Poco::Int64 _tickets_ttl = NULL_TTL;
};

} // rpc
} // privmx

#endif // _PRIVMXLIB_RPC_TICKETSMANAGER_HPP_

/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <algorithm>
#include <Pson/BinaryString.hpp>

#include <privmx/utils/Debug.hpp>
#include <privmx/rpc/tls/TicketsManager.hpp>
#include <privmx/utils/PrivmxException.hpp>
#include <privmx/utils/Utils.hpp>
#include <privmx/rpc/RpcException.hpp>

using namespace privmx;
using namespace privmx::rpc;
using namespace privmx::utils;
using namespace std;
using namespace Poco;
using namespace Poco::JSON;
using Pson::BinaryString;

void TicketsManager::saveTickets(const Array::Ptr tickets, int ttl, const string& master_secret) {
    string ticket;
    lock_guard<mutex> lock(_tickets_mutex);
    Int64 now = Utils::getNowTimestamp();
    Int64 new_tickets_ttl = now + (ttl * 1000) - _min_ticket_ttl;
    for (Array::ConstIterator it = tickets->begin(); it != tickets->end(); ++it) {
        ticket = it->extract<BinaryString>();
        _tickets.emplace(new_tickets_ttl, SessionTicket(ticket, master_secret));
    }
    _tickets_ttl = max(_tickets_ttl, new_tickets_ttl);
}

SessionTicket TicketsManager::useTicket() {
    dropExpiredTickets();
    if (ticketsCount() == 0) {
        if (on_tickets_equal_zero) {
            on_tickets_equal_zero();
        } else {
            throw TicketsCountIsEqualZeroException();
        }
    }
    lock_guard<mutex> lock(_tickets_mutex);
    auto it = _tickets.begin();
    SessionTicket ticket = (*it).second;
    _tickets.erase(it);
    return ticket;
}

void TicketsManager::clear() {
    lock_guard<mutex> lock(_tickets_mutex);
    _tickets.clear();
}

unsigned int TicketsManager::ticketsCount() {
    PRIVMX_DEBUG("ticketsCount", _tickets.size())
    lock_guard<mutex> lock(_tickets_mutex);
    return _tickets.size();
}

bool TicketsManager::shouldAskForNewTickets(Int32 min_count) {
    Int64 now = Utils::getNowTimestamp();
    lock_guard<mutex> lock(_tickets_mutex);
    if ((Int32)_tickets.size() < min_count || (_tickets_ttl != NULL_TTL && _tickets_ttl-_ttl_threshold < now)) {
        return true;
    }
    return false;
}

void TicketsManager::dropExpiredTickets() {
    Int64 now = Utils::getNowTimestamp();
    lock_guard<mutex> lock(_tickets_mutex);
    auto it = _tickets.upper_bound(now);
    if (it == _tickets.begin()) {
        return;
    }
    _tickets.erase(_tickets.begin(), it);
}

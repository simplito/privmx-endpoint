#ifndef _UTILS_HPP_
#define _UTILS_HPP_

#include <map>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <privmx/endpoint/thread/Types.hpp>

namespace utils {
    struct ConsoleItem {
        int type;
        std::string stringValue;
        int keyValue;
    };

    template <typename T>
    class TSQueue {
    private:
        std::queue<T> m_queue;
        std::mutex m_mutex;
        std::condition_variable m_cond;

    public:
        void push(T item) {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_queue.push(item);
            m_cond.notify_one();
        }

        size_t size() {
            std::unique_lock<std::mutex> lock(m_mutex);
            size_t size = m_queue.size();
            m_cond.notify_one();
            return size;
        }

        T pop() {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cond.wait(lock,
                [this]() { return !m_queue.empty(); }
            );

            T item = m_queue.front();
            m_queue.pop();
            return item;
        }
    };

    std::map<std::string, std::string> loadSettings(const std::string& filePath);
    std::string getSetting(const std::map<std::string, std::string>& values, const std::string &key);

    void printOption(const std::string & selector, const std::string & option);
    void printOption(const std::string & selector, const std::string & option, const std::string & option2);
    std::string renderMsg(const privmx::endpoint::thread::Message& message);
    void printMsg(const privmx::endpoint::thread::Message& message);    
    void printMsg(const std::string& userId, const std::string& msg);
    void printMenu();
    void clearScreen();
    void printPrompt(const std::string& threadId, const std::string& input);
    void setupNCurses();
    void printQueueStringItem(const ConsoleItem& item);
}



#endif
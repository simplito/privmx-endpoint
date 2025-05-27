/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <string>
#include <algorithm>
#include <gtest/gtest.h>

#include <privmx/utils/VersionNumber.hpp>
#include "privmx/utils/PrivmxExtExceptions.hpp"
#include <gmpxx.h>

using namespace std;

namespace privmx {
namespace utils {

TEST(VersionNumber, Construction) {
    std::vector<std::string> correctTestVersions = {
        "1.0",
        "1.0.*",
        "1.0.1",
        "1.0.1-rc1",
        "1.9.2rc_1"
    };
    EXPECT_NO_THROW({
        auto tmp = VersionNumber(correctTestVersions[0]);
    });
    EXPECT_NO_THROW({
        auto tmp = VersionNumber(correctTestVersions[1]);
    });
    EXPECT_NO_THROW({
        auto tmp = VersionNumber(correctTestVersions[2]);
    });
    EXPECT_NO_THROW({
        auto tmp = VersionNumber(correctTestVersions[3]);
    });
    std::vector<std::string> incorrectTestVersions = {
        "1.-0",
        "1",
        "1.0-rc2",
        "blach"
    };
    EXPECT_THROW({
        auto tmp = VersionNumber(incorrectTestVersions[0]);
    }, InvalidVersionFormatException);
    EXPECT_THROW({
        auto tmp = VersionNumber(incorrectTestVersions[1]);
    }, InvalidVersionFormatException);
    EXPECT_THROW({
        auto tmp = VersionNumber(incorrectTestVersions[2]);
    }, InvalidVersionFormatException);
    EXPECT_THROW({
        auto tmp = VersionNumber(incorrectTestVersions[3]);
    }, InvalidVersionFormatException);
}


TEST(VersionNumber, Comparator) {
    std::vector<VersionNumber> testVersionsSorted = {
        VersionNumber("1.0"),
        VersionNumber("1.0.0-rc1"),
        VersionNumber("1.0.0-rc2"),
        VersionNumber("1.0.0"),
        VersionNumber("1.0.1-rc2"),
        VersionNumber("1.0.1"),
        VersionNumber("1.1"),
        VersionNumber("1.1.1"),
    };
    for(size_t i = 0; i < testVersionsSorted.size(); i++) {
        for(size_t j = 0; j < testVersionsSorted.size(); j++) {
            if(i == j) {
                EXPECT_TRUE(testVersionsSorted[i] == testVersionsSorted[i]);
            } else {
                EXPECT_FALSE(testVersionsSorted[i] == testVersionsSorted[j]);
            }
        }
    }

    for(size_t i = 0; i < testVersionsSorted.size(); i++) {
        for(size_t j = i+1; j < testVersionsSorted.size(); j++) {
            EXPECT_TRUE(testVersionsSorted[i] < testVersionsSorted[j]);
            EXPECT_FALSE(testVersionsSorted[j] < testVersionsSorted[i]);
        }
    }
    for(size_t i = 1; i < testVersionsSorted.size(); i++) {
        for(int j = i-1; j >= 0; j--) {
            EXPECT_TRUE(testVersionsSorted[i] > testVersionsSorted[j]);
            EXPECT_FALSE(testVersionsSorted[j] > testVersionsSorted[i]);
        }
    }
}


} // utils
} // privmx

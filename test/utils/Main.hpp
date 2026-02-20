#ifndef _PRIVMXLIB_TEST_MAIN_HPP_
#define _PRIVMXLIB_TEST_MAIN_HPP_

#include <gtest/gtest.h>
#include <string>

std::string BRIDGE_URL;
std::string INI_FILE_PATH;


int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--bridge_url" || arg == "-b") && i + 1 < argc) {
            BRIDGE_URL = argv[++i];
        } else if ((arg == "--ini_file_path" || arg == "-i") && i + 1 < argc) {
            INI_FILE_PATH = argv[++i];
        }
    }

    return RUN_ALL_TESTS();
}

#endif // _PRIVMXLIB_TEST_MAIN_HPP_

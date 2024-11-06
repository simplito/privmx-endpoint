## PrivMX Endpoint
Programming library used by applications and devices which are the ends of PrivMX secure communication channels. It encrypts and decrypts data, manages network connections and provides a functional API, allowing the applications to build their E2EE communication channels based on a few universal, client-side encrypted tools: Threads, Stores, and Inboxes.

PrivMX Endpoint is a modular, low-level library written in C++, ready to be configured and used on any device (including IoT, VR + more) and any operating system.

Initialization of the application’s Endpoint requires providing an address of the application’s Bridge and the user's private key.

### Architecture
Types of architecture included:
- for Linux:
	- x86_64
	- arm
	- arm64
- for MacOS:
	- macos64 - x86_64
	- macos64 - arm64
	- ios64 - arm64
	- arm64simulator
- for Windows:
	- x86_64
- for Android:
	- arm (armeabi-v7a)
	- arm64 (arm64-v8a)
	- x86 (i386)
	- x86_64

## How to start

### Install and configure Conan
To use PrivMX Endpoint you need to add it to your project using Conan Repository Manager. 
[How to install Conan](https://docs.conan.io/2/installation.html).

#### Setup Conan with our repository
```bash
conan profile detect --force
conan remote add privmx https://libs.simplito.com/artifactory/api/conan/privmx
```

### Adding to a project - sample C++ program (CMake)


After installing Conan - create a Conan config file in the root dir of your project:

#### **`conanfile.txt`**
```
[requires]
privmx-endpoint/2.0.1

[generators]
CMakeDeps
CMakeToolchain

[layout]
cmake_layout
```


Next, add privmx-endpoint library dependency to your CMakeLists.txt:
#### **`CMakeLists.txt`**
```cmake
cmake_minimum_required(VERSION 3.15)
project(test_program)
set(CMAKE_CXX_STANDARD 17)

find_package(privmxendpoint REQUIRED)

add_executable(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)
target_link_libraries(test_program PUBLIC 
		privmxendpoint::privmxendpointcore 
		privmxendpoint::privmxendpointthread 
		privmxendpoint::crypto
)
```

#### **`main.cpp`**
```cpp
#include <optional>
#include <iostream>
#include <privmx/endpoint/crypto/CryptoApi.hpp>

using namespace privmx::endpoint::crypto;
int main() {
    auto cryptoApi {CryptoApi::create()};
	auto priv = cryptoApi.generatePrivateKey(std::nullopt);
	auto pub = cryptoApi.derivePublicKey(priv);
	std::cout << "Generated private key: " << priv << std::endl
		      << "Generated public key: " << pub << std::endl;
	return 0;
}
```
### Build project

```bash
conan install . --output-folder=build -r privmx --build-missing
cd build
cmake .. -G "Unix Makefiles" -DCMAKE_TOOLCHAIN_FILE=build/Release/generators/conan_toolchain.cmake \
        -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Run project

```bash
source build/Release/generators/conanrun.sh
./test_program
```

### Initial requirements for connecting with Endpoint to PrivMX Bridge

To use the library's elements in a C++ app, you have to provide:

1. PrivMX Endpoint address (platformUrl):

```
https://<your_instance_of_bridge_server:port>
```

2. SolutionId:

```
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

#### You must also ensure that:

1. There is an appropriate context with assigned users on the Bridge Server side.

2. The users have pairs of public and private keys (`Pubkey` and `PrivKey`) and the user's private key is known in the app.

3. Public keys of all the users are added to the `Context`.
 
4. The app's user knows the public keys of all the other users who are supposed to be added to a module (Thread/Store/Inbox).

Hint: 
- Instructions on how to add the user to the Context can be found in the [Bridge Installation Guide](https://docs.privmx.dev/bridge/getting-started).
- a pair of keys for that user can be generated, for example, using the code example above or by calling `genKeyPair.sh` script coming with the [PrivMX Bridge Server docker](https://github.com/simplito/privmx-bridge-docker).

#### Example of using Threads API:

``` cpp
#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/thread/ThreadApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Config.hpp>

using namespace privmx::endpoint;

int main() {
...
```
1. A single connection with the server is managed by the `connection` - instance of `privmx::endpoint::core::Connection`.
2. When connecting via HTTPS - setup begins by specifying a PEM file with the SSL certificate. If there is no certificate file given, a default system certificate will be used.

``` cpp
	core::Config::setCertsPath(PATH_TO_PEM_CERT_FILE);

```
3. Now you need some details to establish connection:

``` cpp
	// the values below should be replaced by the ones corresponding to your Brigde Server instance.
	auto solutionId {"6716bb7950041e112ddeaf18"};
	auto contextId {"6716bb79763760280a77b6a0"};
	auto userPubKey {"51WPnnGwztNPWUDEbhncYDxZCZWAFS4M9Yqv94N2335nL92fEn"};
	auto userPrivKey {"L3ycXibEzJm9t9swoJ4KtSmJsenHmmgRnYY79Q2TqfJMwTGaWfA7"};
	auto userId {"user1"};
	auto platformUrl {"http://localhost:9111"};

	// setup some defaults
	core::PagingQuery defaultListQuery = {.skip = 0, .limit = 100, .sortOrder = "desc"};
	std::vector<core::UserWithPubKey> threadUsers;
	threadUsers.push_back({.userId = userId, .pubKey = userPubKey});
```
Endpoint connection starts by calling Connection factory method: `core::Connection::platformConnect(...)`.

``` cpp
	try { 
		auto connection {core::Connection::connect(userPrivKey, solutionId, platformUrl)};
	} catch (privmx::endpoint::core::Exception& e) {
		std::cout << e.getFull() << std::endl;
	}
```

4. As soon as you get the `connection` object you can create one of the modules APIs - Thread API for example:


``` cpp
	auto threadApi {thread::ThreadApi::create(connection)};
	auto threadId {threadApi.createThread(contextId, threadUsers, threadUsers, core::Buffer::from("some thread's public meta-data"), core::Buffer::from("some thread's private meta-data"))};

	// send messages to thread and read them back
	threadApi.sendMessage(threadId, core::Buffer::from("some public meta-data"), core::Buffer::from("some private meta-data"), core::Buffer::from("message"));

	// get thread's messages
	auto messages = threadApi.listMessages(threadId, defaultListQuery);
	for (auto msg: messages.readItems) {
		std::cout << "message: " << msg.data.stdString()
			<< " / public meta: " << msg.publicMeta.stdString() 
			<< " / private meta: " << msg.privateMeta.stdString() 
			<< std::endl;
		}
	return 0;
}
```
After building and running the program above, you will get the output showing messages that were sent to the provided Thread.

A complete project that uses the above code example can be found [here](https://github.com/simplito/privmx-webendpoint/tree/main/examples/minimal).

## Available APIs:

1. [Threads](https://docs.privmx.dev/reference/cpp/endpoint/thread/thread-api) - text message sending
2. [Stores](https://docs.privmx.dev/reference/cpp/endpoint/store/store-api) - file storage
3. [Inboxes](https://docs.privmx.dev/reference/cpp/endpoint/inbox/inbox-api) - i.e: public forms
4. [Crypto](https://docs.privmx.dev/reference/cpp/endpoint/crypto/crypto-api) - helper class with methods to manage keys etc.


For more detailed information about API functions, visit https://docs.privmx.dev.

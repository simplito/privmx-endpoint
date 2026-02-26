# PrivMX Endpoint API Reference {#mainpage}

*Library written in C++ allowing applications to build E2EE communication channels.*

## About PrivMX

[PrivMX](https://privmx.dev) allows developers to build end-to-end encrypted apps used for
communication. The Platform works according to privacy-by-design mindset, so all of our solutions
are based on Zero-Knowledge architecture. This project extends PrivMX’s commitment to security by
making its encryption features accessible to developers using C++.

### Key Features

- End-to-End Encryption: Ensures that data is encrypted at the source and can only be decrypted by
  the intended recipient.
- Native C++ Library Integration: Leverages the performance and security of C++ while making it
  accessible in C# applications.
- Cross-Platform Compatibility: Designed to support PrivMX on multiple operating systems and
  environments.
- Simple API: Easy-to-use interface for C# developers without compromising security.

## Library

PrivMX Endpoint is the fundamental wrapper library, essential for the Platform’s operational
functionality.
As the most minimalist library available, it provides the highest degree of flexibility in
customizing the Platform to meet your specific requirements.

This library implements models, exception catching, and the following modules:

- @ref privmx::endpoint::crypto::CryptoApi - Cryptographic methods used to encrypt/decrypt and sign your data or generate keys to
  work with PrivMX.
- @ref privmx::endpoint::core::Connection - Methods for managing connection with PrivMX.
- @ref privmx::endpoint::thread::ThreadApi - Methods for managing Threads and sending/reading messages.
- @ref privmx::endpoint::store::StoreApi - Methods for managing Stores and sending/reading files.
- @ref privmx::endpoint::inbox::InboxApi - Methods for managing Inboxes and entries.

## License Information

**PrivMX Endpoint**

Copyright © 2026 Simplito sp. z o.o.

This project is part of the PrivMX Platform (https://privmx.dev).
This project is Licensed under the MIT License.

PrivMX Endpoint and PrivMX Bridge are licensed under the PrivMX Free License.
See the License for the specific language governing permissions and limitations under the License.

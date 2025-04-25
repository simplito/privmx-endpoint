## PrivMX Endpoint
Programming library used by applications and devices which are the ends of PrivMX secure communication channels. It encrypts and decrypts data, manages network connections and provides a functional API, allowing the applications to build their E2EE communication channels based on a few universal, client-side encrypted tools: Threads, Stores, and Inboxes.

PrivMX Endpoint is a modular, low-level library written in C++, ready to be configured and used on any device (including IoT, VR + more) and any operating system.

## Key Benefits
 - **Modular and Flexible**: PrivMX Endpoint is designed to allow developers to easily configure and integrate it into any device or operating system. Developed in C++, PrivMX Endpoint is designed to be **platform-independent**, making it suitable for a wide range of devices, including IoT, VR, and more. Wrappers for other languages (like JavaScript, Java, Kotlin, Swift, C#) can be found in our other [repositories](https://github.com/orgs/simplito/repositories?q=privmx).
    
- **Secure Communication**: PrivMX Endpoint encrypts and decrypts data, ensuring secure communication between applications and devices. It leverages the user's private key to establish the **end-to-end encrypted** channels.
    
- **Simplified Development**: The library provides a functional API that allows developers to focus on building their core application features. Together with PrivMX Bridge (which serves as the backend), you receive a **full-fledged solution** allowing for rapid development of secure end-to-end encrypted applications across all major platforms.

## PrivMX Bridge
To use PrivMX to develop your apps, you also need PrivMX Bridge. It is a **zero-knowledge server** that intermediates in the **transfer of encrypted data** and notifications between PrivMX Endpoints and **stores encrypted data**. See how to install and use PrivMX Bridge in its [repository](https://github.com/simplito/privmx-bridge).
## Containers
PrivMX enables communication through **text messages**, **secure file storage** and **real-time data streaming**. **PrivMX Containers** are sets of events and APIs designed to setup your app for specific types of communication.
- **Thread** –  a structured communication tool used for **message-based communication.**
- **Store** –  data storage and communication tool used for **file exchange and management**.
- **Inbox** – a communication tool used for **one-way communication with external users**.

## Resources

- [PrivMX Documentation](https://docs.privmx.dev/)
- [API Reference](https://docs.privmx.dev/docs/latest/start/api-reference)
- [other PrivMX repositories](https://github.com/orgs/simplito/repositories?q=privmx) (libraries and wrappers)

## License
PrivMX Free License
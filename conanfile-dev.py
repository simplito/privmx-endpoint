from conan import ConanFile
from conan.tools.files import copy
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
import os


class PrivmxEndpointDevRecipe(ConanFile):
    name = "privmx-endpoint"
    package_type = "library"
    license = "PrivMX Free License"

    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "private_headers": [True, False],
        "with_webrtc": [True, False],
        "with_cli": [True, False],
        "with_tests": [True, False],
    }
    default_options = {
        "shared": True,
        "fPIC": False,
        "private_headers": False,
        "with_webrtc": False,
        "with_cli": False,
        "with_tests": True,
        "*:shared": True,
        "pson/*:fPIC": False,
        "sqlite3/*:enable_fts5": True,
        "poco/*:enable_jwt": False,
        "poco/*:enable_net": True,
        "poco/*:enable_pdf": False,
        "poco/*:enable_xml": True,
        "poco/*:enable_zip": False,
        "poco/*:enable_data": False,
        "poco/*:enable_fork": True,
        "poco/*:enable_json": True,
        "poco/*:enable_util": True,
        "poco/*:enable_redis": False,
        "poco/*:enable_crypto": True,
        "poco/*:enable_netssl": True,
        "poco/*:enable_mongodb": False,
        "poco/*:enable_pocodoc": False,
        "poco/*:enable_sevenzip": False,
        "poco/*:with_sql_parser": False,
        "poco/*:enable_cppparser": False,
        "poco/*:enable_data_odbc": False,
        "poco/*:enable_encodings": True,
        "poco/*:enable_data_mysql": False,
        "poco/*:enable_prometheus": False,
        "poco/*:enable_data_sqlite": False,
        "poco/*:enable_activerecord": False,
        "poco/*:enable_pagecompiler": False,
        "poco/*:enable_apacheconnector": False,
        "poco/*:enable_data_postgresql": False,
        "poco/*:enable_activerecord_compiler": False,
        "poco/*:enable_pagecompiler_file2page": False,
    }

    # Development recipe for a local checkout: the single entry point for local
    # and CI builds (conan install conanfile-dev.py -o with_webrtc=True ...).
    exports_sources = (
        "CMakeLists.txt",
        "LICENSE.md",
        "utils/*",
        "crypto/*",
        "rpc/*",
        "privfs/*",
        "endpoint/*",
    )

    def requirements(self):
        # private headers #include the dependencies' headers, so consumers must see them
        headers = bool(self.options.private_headers)
        # privmxdrvcrypto and privmxdrvecc are gone: all cryptography goes through pmx-crypto, which
        # is a Conan package rather than the git submodule it used to be. pmx-crypto's headers reach
        # a consumer's compiler unconditionally — core's public headers (crypto/PrivateKey.hpp and
        # relatives) and endpoint/crypto's ExtKey.hpp include privmx/cryptoservice/*, so this one is
        # not gated on `private_headers` the way the rest are.
        self.requires("pmx-crypto/0.1", transitive_headers=True)
        self.requires("privmxdrvnet/1.0.3", transitive_headers=headers)
        self.requires("gmp/6.3.0", transitive_headers=headers)
        # Widened from the old >=3.0 <3.1: that pin existed because privmxdrvcrypto was built against
        # OpenSSL 1.x-era APIs and forced the whole graph down with it. With the drivers gone, the
        # range is pmx-crypto's own.
        self.requires("openssl/[>=3.5.9 <3.6]")
        self.requires("poco/1.13.2", transitive_headers=headers)
        self.requires("pson/1.0.7", transitive_headers=headers)
        self.requires("sqlite3/[^3.50.4]", transitive_headers=headers)
        if self.options.with_webrtc:
            # consumers implementing WebRTCInterface call libwebrtc symbols directly
            self.requires("libwebrtc/m125.1.0", transitive_headers=headers, transitive_libs=headers)
        if self.options.with_cli:
            self.requires("readline/[^8.2.0]")
        if self.options.with_tests:
            self.requires("gtest/[^1.15.0]")

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.set_property("Pson::Pson", "cmake_target_name", "Pson")
        deps.generate()

        tc = CMakeToolchain(self)
        tc.variables["PRIVMX_CONAN"] = True
        tc.variables["PRIVMX_BUILD_ENDPOINT"] = True
        # No PRIVMX_DRIVER_CRYPTO: the option no longer exists in CMakeLists.txt, because there is
        # no crypto driver left to switch on.
        tc.variables["PRIVMX_DRIVER_NET"] = True
        tc.variables["PRIVMX_BUILD_WITH_WEBRTC"] = bool(self.options.with_webrtc)
        tc.variables["USE_PREBUILT_WEBRTC"] = bool(self.options.with_webrtc)
        tc.variables["PRIVMX_BUILD_CLI"] = bool(self.options.with_cli)
        tc.variables["PRIVMX_ENABLE_TESTS"] = bool(self.options.with_tests)
        tc.variables["PRIVMX_INSTALL_PRIVATE_HEADERS"] = bool(self.options.private_headers)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        copy(self, "LICENSE.md", src=self.source_folder, dst=os.path.join(self.package_folder, "licenses"))
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "privmxendpoint")

        if self.options.private_headers:
            self.cpp_info.components["privmx"].libs = ["privmx"]
            self.cpp_info.components["privmx"].set_property("cmake_target_name", "privmxendpoint::privmx")
            self.cpp_info.components["privmx"].requires = [
                "gmp::gmp",
                "pson::Pson",
                "poco::poco",
                "privmxdrvnet::privmxdrvnet",
                "pmx-crypto::pmx-crypto",
            ]

        self.cpp_info.components["privmxendpointcore"].libs = ["privmxendpointcore"]
        self.cpp_info.components["privmxendpointcore"].set_property("cmake_target_name", "privmxendpoint::privmxendpointcore")
        self.cpp_info.components["privmxendpointcore"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
            # core links privmxcryptolib PUBLIC: its public headers expose pmx-crypto types.
            "pmx-crypto::pmx-crypto",
        ]

        self.cpp_info.components["privmxendpointcrypto"].libs = ["privmxendpointcrypto"]
        self.cpp_info.components["privmxendpointcrypto"].set_property("cmake_target_name", "privmxendpoint::privmxendpointcrypto")
        self.cpp_info.components["privmxendpointcrypto"].requires = [
            "gmp::gmp",
            # ExtKey.hpp is a public header and includes privmx/cryptoservice/*.
            "pmx-crypto::pmx-crypto",
        ]

        self.cpp_info.components["privmxendpointthread"].libs = ["privmxendpointthread"]
        self.cpp_info.components["privmxendpointthread"].set_property("cmake_target_name", "privmxendpoint::privmxendpointthread")
        self.cpp_info.components["privmxendpointthread"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointstore"].libs = ["privmxendpointstore"]
        self.cpp_info.components["privmxendpointstore"].set_property("cmake_target_name", "privmxendpoint::privmxendpointstore")
        self.cpp_info.components["privmxendpointstore"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointinbox"].libs = ["privmxendpointinbox"]
        self.cpp_info.components["privmxendpointinbox"].set_property("cmake_target_name", "privmxendpoint::privmxendpointinbox")
        self.cpp_info.components["privmxendpointinbox"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointevent"].libs = ["privmxendpointevent"]
        self.cpp_info.components["privmxendpointevent"].set_property("cmake_target_name", "privmxendpoint::privmxendpointevent")
        self.cpp_info.components["privmxendpointevent"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointkvdb"].libs = ["privmxendpointkvdb"]
        self.cpp_info.components["privmxendpointkvdb"].set_property("cmake_target_name", "privmxendpoint::privmxendpointkvdb")
        self.cpp_info.components["privmxendpointkvdb"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointgroup"].libs = ["privmxendpointgroup"]
        self.cpp_info.components["privmxendpointgroup"].set_property("cmake_target_name", "privmxendpoint::privmxendpointgroup")
        self.cpp_info.components["privmxendpointgroup"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointstream"].libs = ["privmxendpointstream"]
        self.cpp_info.components["privmxendpointstream"].set_property("cmake_target_name", "privmxendpoint::privmxendpointstream")
        if self.options.with_webrtc:
            self.cpp_info.components["privmxendpointstream"].requires = [
                "gmp::gmp",
                "libwebrtc::libwebrtc",
                "pson::Pson",
                "poco::poco",
                "privmxdrvnet::privmxdrvnet",
            ]
        else:
            self.cpp_info.components["privmxendpointstream"].requires = [
                "gmp::gmp",
                "pson::Pson",
                "poco::poco",
                "privmxdrvnet::privmxdrvnet",
            ]

        self.cpp_info.components["privmxendpointsearch"].libs = ["privmxendpointsearch"]
        self.cpp_info.components["privmxendpointsearch"].set_property("cmake_target_name", "privmxendpoint::privmxendpointsearch")
        self.cpp_info.components["privmxendpointsearch"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
            "sqlite3::sqlite",
        ]

        self.cpp_info.components["privmxendpointlock"].libs = ["privmxendpointlock"]
        self.cpp_info.components["privmxendpointlock"].set_property("cmake_target_name", "privmxendpoint::privmxendpointlock")
        self.cpp_info.components["privmxendpointlock"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvnet::privmxdrvnet",
        ]
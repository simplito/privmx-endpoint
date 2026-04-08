from conan import ConanFile
from conan.tools.files import copy
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
import os


class PrivmxEndpointDevRecipe(ConanFile):
    name = "privmx-endpoint"
    version = "2.7.4-dev.1"
    package_type = "library"
    license = "PrivMX Free License"

    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False], "private_headers": [True, False]}
    default_options = {"shared": True, "fPIC": False, "private_headers": False}

    # Test recipe for local development checkout. Put this file in the root of
    # the Endpoint repository so Conan builds from local sources instead of GitHub.
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
        self.requires("privmxdrvcrypto/1.0.3")
        self.requires("privmxdrvecc/1.0.2")
        self.requires("privmxdrvnet/1.0.3")
        self.requires("gmp/6.3.0")
        self.requires("libwebrtc/m125")
        self.requires("poco/1.13.2")
        self.requires("pson/1.0.7")

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")
        self.options["poco/*"].shared = True
        self.options["poco/*"].enable_jwt = False
        self.options["poco/*"].enable_net = True
        self.options["poco/*"].enable_pdf = False
        self.options["poco/*"].enable_xml = False
        self.options["poco/*"].enable_zip = False
        self.options["poco/*"].enable_data = False
        self.options["poco/*"].enable_fork = True
        self.options["poco/*"].enable_json = True
        self.options["poco/*"].enable_util = True
        self.options["poco/*"].enable_redis = False
        self.options["poco/*"].enable_crypto = True
        self.options["poco/*"].enable_netssl = True
        self.options["poco/*"].enable_mongodb = False
        self.options["poco/*"].enable_pocodoc = False
        self.options["poco/*"].enable_sevenzip = False
        self.options["poco/*"].with_sql_parser = False
        self.options["poco/*"].enable_cppparser = False
        self.options["poco/*"].enable_data_odbc = False
        self.options["poco/*"].enable_encodings = True
        self.options["poco/*"].enable_data_mysql = False
        self.options["poco/*"].enable_prometheus = False
        self.options["poco/*"].enable_data_sqlite = False
        self.options["poco/*"].enable_activerecord = False
        self.options["poco/*"].enable_pagecompiler = False
        self.options["poco/*"].enable_apacheconnector = False
        self.options["poco/*"].enable_data_postgresql = False
        self.options["poco/*"].enable_activerecord_compiler = False
        self.options["poco/*"].enable_pagecompiler_file2page = False

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
        tc.variables["PRIVMX_DRIVER_CRYPTO"] = True
        tc.variables["PRIVMX_DRIVER_NET"] = True
        tc.variables["PRIVMX_BUILD_WITH_WEBRTC"] = True
        tc.variables["USE_PREBUILT_WEBRTC"] = True
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
                "privmxdrvcrypto::privmxdrvcrypto",
                "privmxdrvecc::privmxdrvecc",
                "privmxdrvnet::privmxdrvnet",
            ]

        self.cpp_info.components["privmxendpointcore"].libs = ["privmxendpointcore"]
        self.cpp_info.components["privmxendpointcore"].set_property("cmake_target_name", "privmxendpoint::privmxendpointcore")
        self.cpp_info.components["privmxendpointcore"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointcrypto"].libs = ["privmxendpointcrypto"]
        self.cpp_info.components["privmxendpointcrypto"].set_property("cmake_target_name", "privmxendpoint::privmxendpointcrypto")
        self.cpp_info.components["privmxendpointcrypto"].requires = [
            "gmp::gmp",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
        ]

        self.cpp_info.components["privmxendpointthread"].libs = ["privmxendpointthread"]
        self.cpp_info.components["privmxendpointthread"].set_property("cmake_target_name", "privmxendpoint::privmxendpointthread")
        self.cpp_info.components["privmxendpointthread"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointstore"].libs = ["privmxendpointstore"]
        self.cpp_info.components["privmxendpointstore"].set_property("cmake_target_name", "privmxendpoint::privmxendpointstore")
        self.cpp_info.components["privmxendpointstore"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointinbox"].libs = ["privmxendpointinbox"]
        self.cpp_info.components["privmxendpointinbox"].set_property("cmake_target_name", "privmxendpoint::privmxendpointinbox")
        self.cpp_info.components["privmxendpointinbox"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointevent"].libs = ["privmxendpointevent"]
        self.cpp_info.components["privmxendpointevent"].set_property("cmake_target_name", "privmxendpoint::privmxendpointevent")
        self.cpp_info.components["privmxendpointevent"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointkvdb"].libs = ["privmxendpointkvdb"]
        self.cpp_info.components["privmxendpointkvdb"].set_property("cmake_target_name", "privmxendpoint::privmxendpointkvdb")
        self.cpp_info.components["privmxendpointkvdb"].requires = [
            "gmp::gmp",
            "pson::Pson",
            "poco::poco",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
            "privmxdrvnet::privmxdrvnet",
        ]

        self.cpp_info.components["privmxendpointstream"].libs = ["privmxendpointstream"]
        self.cpp_info.components["privmxendpointstream"].set_property("cmake_target_name", "privmxendpoint::privmxendpointstream")
        self.cpp_info.components["privmxendpointstream"].requires = [
            "gmp::gmp",
            "libwebrtc::libwebrtc",
            "pson::Pson",
            "poco::poco",
            "privmxdrvcrypto::privmxdrvcrypto",
            "privmxdrvecc::privmxdrvecc",
            "privmxdrvnet::privmxdrvnet",
        ]

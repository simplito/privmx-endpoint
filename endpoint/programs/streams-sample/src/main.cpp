#include <optional>
#include <iostream>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/stream/StreamApi.hpp>
#include <privmx/endpoint/event/EventApi.hpp>
#include <privmx/endpoint/crypto/CryptoApi.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/EventQueue.hpp>
#include <privmx/endpoint/stream/Events.hpp>
#include <fstream>
#include <vector>
#include <map>
#include <filesystem>
#include <thread>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include "utils.hpp"
#include <stdexcept>

using namespace privmx::endpoint;
using namespace utils;

void publishLocalStream(std::shared_ptr<stream::StreamApi> streamApi, const std::string& streamRoomId);
std::shared_ptr<core::Connection> connection;
std::shared_ptr<event::EventApi> eventApi;
std::shared_ptr<stream::StreamApi> streamApi;

int main(int argc, char *argv[]) {
	std::cerr << __LINE__ << std::endl;

	std::string envPath {argc > 1 ? argv[1] : "conf/.env"};
	auto settings {loadSettings(envPath)};
	std::cerr << __LINE__ << std::endl;

	auto solutionId {getSetting(settings, "SOLUTION_ID")};
	auto contextId {getSetting(settings, "CONTEXT_ID")};
	auto userId {getSetting(settings, "USER_ID")};
	auto userPassword {getSetting(settings, "USER_PASSWORD")};
	auto platformUrl {getSetting(settings, "BRIDGE_URL")};
	auto streamRoomId {getSetting(settings, "STREAM_ROOM_ID")};
	auto isPublisher {getSetting(settings, "PUBLISHER") == "true"};
	auto isListener {getSetting(settings, "LISTENER") == "true"};
	std::cerr << __LINE__ << std::endl;

	TSQueue<ConsoleItem> appQueue;

	// handling events
	core::EventQueue eventQueue {core::EventQueue::getInstance()};
	std::cerr << __LINE__ << std::endl;

    // generate KeyPair
    auto cryptoApi {crypto::CryptoApi::create()};
    auto privKey {cryptoApi.derivePrivateKey2(userPassword, userId)};
    auto pubKey {cryptoApi.derivePublicKey(privKey)};
    std::cerr << "pub for pass: "<< userPassword << " and userId: "<< userId << " is: " << pubKey << std::endl;
	std::cerr << __LINE__ << std::endl;

	std::thread t([&](){
		while(true) {
			core::EventHolder holder = eventQueue.waitEvent();
			auto event {holder.get()};
			std::cout << "[EVENT]:" << std::endl << event->toJSON() << std::endl;
			// if (thread::Events::isThreadNewMessageEvent(event)) {
			// 	auto msgEvent = thread::Events::extractThreadNewMessageEvent(event);
			// 	ConsoleItem item = {.type = 1, .stringValue = renderMsg(msgEvent.data), .keyValue = -1};
			// 	appQueue.push(item);
			// }
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
    });
	std::cerr << __LINE__ << std::endl;
	std::cout << "Trying to connect to:\nPriv: " << privKey << "\nSolution: " << solutionId << "\nBridge: " << platformUrl << std::endl;  
	// // initialize Endpoint connection and Threads API
	// auto connection {core::Connection::connect(privKey, solutionId, platformUrl)};
	// log("connected");
	// auto eventApi {event::EventApi::create(connection)};
	// auto streamApi {stream::StreamApi::create(connection, eventApi)};

	connection = std::make_shared<core::Connection>(core::Connection::connect(privKey, solutionId, platformUrl));
	log("connected");
	eventApi = std::make_shared<event::EventApi>(event::EventApi::create(*connection));
	streamApi = std::make_shared<stream::StreamApi>(stream::StreamApi::create(*connection, *eventApi));

	log("APIs created");
	std::cerr << __LINE__ << std::endl;;

	// streamApi->subscribeForStreamEvents();
	std::cerr << __LINE__ << std::endl;

	if (isPublisher) {
		std::cerr << __LINE__ << std::endl;
		publishLocalStream(streamApi, streamRoomId);
	}
	// while(true) {
	// 	while(appQueue.size() > 0) {
	// 		auto item {appQueue.pop()};
	// 		if (item.type == 1) {
	// 			std::cout << "something in queue.." << std::endl;
	// 		}
	// 	}
	// 	std::this_thread::sleep_for(std::chrono::milliseconds(5));
	// }

	return 0;
}

void publishLocalStream(std::shared_ptr<stream::StreamApi> streamApi, const std::string& streamRoomId) {
	std::cout << "Check for local audio soruce..." << std::endl;
	auto audioDevices {streamApi->listAudioRecordingDevices()};
	std::cerr << __LINE__ << std::endl;
	if (audioDevices.size() < 1) {
		auto err {"No audio sources found"};
		throw std::runtime_error(err);
	}
	for (auto device: audioDevices) {
		auto [id, name] = device;
		std::cout << "Audio device: " << id << " / " << name << std::endl;
	}

	std::cout << "Check for local video soruce..." << std::endl;
	auto videoDevices {streamApi->listVideoRecordingDevices()};
	std::cerr << __LINE__ << std::endl;
	if (videoDevices.size() < 1) {
		auto err {"No video sources found"};
		throw std::runtime_error(err);
	}
	for (auto device: videoDevices) {
		auto [id, name] = device;
		std::cout << "Video device: " << id << " / " << name << std::endl;
	}

	std::cout << "Creating stream..." << std::endl;
	auto streamId {streamApi->createStream(streamRoomId)};
	std::cerr << __LINE__ << std::endl;

	std::cout << "Adding local audio as track..." << std::endl;
	streamApi->trackAdd(streamId,  stream::TrackParam{{.id=0, .type=stream::DeviceType::Audio}, .params_JSON="{}"});

	std::cout << "Adding local video as track..." << std::endl;
	streamApi->trackAdd(streamId,  stream::TrackParam{{.id=0, .type=stream::DeviceType::Video}, .params_JSON="{}"});
	std::cerr << __LINE__ << std::endl;

	streamApi->publishStream(streamId);
}

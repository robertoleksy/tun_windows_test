#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <thread>
#include <vector>

using namespace boost::asio;

int main() {
		boost::asio::io_service io_service;
		ip::udp::socket s(io_service,  ip::udp::endpoint(ip::address_v6(), 9000));
		ip::udp::socket s2(io_service,  ip::udp::endpoint(ip::address_v6(), 9001));
		std::array<unsigned char, 65000> buff;
		buff.fill(0);
		
	auto thread_lambda = [&] {
		while(1) {
			s.send_to(boost::asio::buffer(buff), ip::udp::endpoint(ip::address_v6::from_string("fc9d:e6d3:bd5b:2bc4:1374:d1a:cebc:224a"), 9000));
		}
	}; // lambda
	auto thread_lambda2 = [&] {
		while(1) {
			s2.send_to(boost::asio::buffer(buff), ip::udp::endpoint(ip::address_v6::from_string("fc9d:e6d3:bd5b:2bc4:1374:d1a:cebc:224a"), 9000));
		}
	}; // lambda
	std::vector<std::thread> threads;
	threads.emplace_back(thread_lambda);
	threads.emplace_back(thread_lambda2);
	
	for (auto &thread : threads)
		thread.join();
}
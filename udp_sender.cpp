#include <boost/asio.hpp>
#include <iostream>
#include <chrono>
#include <thread>

using namespace boost::asio;

int main() {
  try
  {
    boost::asio::io_service io_service;
    ip::udp::socket s(io_service,  ip::udp::endpoint(ip::address_v6(), 9000));
	std::array<unsigned char, 1000> buff;
	buff.fill(0);
	while(1) {
		s.send_to(boost::asio::buffer(buff), ip::udp::endpoint(ip::address_v6::from_string("fc9d:e6d3:bd5b:2bc4:1374:d1a:cebc:224a"), 9000));
	}
  }
  catch (std::exception& e)
  {
    std::cerr << "Exception: " << e.what() << "\n";
  }

}
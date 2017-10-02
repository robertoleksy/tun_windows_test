#include "c_tuntap_windows.hpp"
#include <atomic>
#include <thread>
#include <array>
#include <iostream>

////////////////////////////////////////////////

class c_counter final {
	public:
		c_counter();
		~c_counter();
		void add_readed_data_size(size_t size){m_received_bytes += size;}
		void add_raceived_packet(){++m_received_number_of_packet;}
	private:
		std::thread m_print_thread;
		std::atomic<size_t> m_received_bytes;
		std::atomic<size_t> m_received_number_of_packet;
};

c_counter::c_counter() :
	m_received_bytes(0),
	m_received_number_of_packet(0)
{
	
	m_print_thread = std::thread([this]() {
		const size_t wait_seconds = 10;
		while (1) {
			std::this_thread::sleep_for(std::chrono::seconds(wait_seconds));
			size_t bytes = m_received_bytes.exchange(0);
			size_t packets = m_received_number_of_packet.exchange(0);
			std::cout << bytes/wait_seconds/1024/1024 << " MB/s " << '\n';
			std::cout << packets/wait_seconds << " Pkg/s " << "\n\n" << std::endl;
		}
	});
}


c_counter::~c_counter() {
	m_print_thread.join();
}

////////////////////////////////////////////////






c_counter counter;
c_tuntap_windows_obj tuntap;
std::array<unsigned char, 65000> buff;

void handler_read(const unsigned char *, std::size_t size, const boost::system::error_code &) {
	counter.add_readed_data_size(size);
	counter.add_raceived_packet();
	tuntap.async_receive_from_tun(buff.data(), buff.size(), handler_read);
}



int main() {
	// sync
/*	while (1) {
		//size_t size = tuntap.get_asio_handle().read_some(boost::asio::buffer(buff));
		size_t size = tuntap.read_from_tun(buff.data(), buff.size());
		counter.add_readed_data_size(size);
		counter.add_raceived_packet();
	}*/

	
	// async
	tuntap.async_receive_from_tun(buff.data(), buff.size(), [&](const unsigned char *data, std::size_t size, const boost::system::error_code &error) {
		handler_read(data, size, error);
	});
	std::vector<std::thread> thread_vec;
	for (int i = 0; i < 2; i++)
		thread_vec.emplace_back(
			[&]{
				tuntap.get_asio_handle().get_io_service().run();		
			});
	for (auto &thread : thread_vec)
		thread.join();
}
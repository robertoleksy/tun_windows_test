#ifndef C_LINUX_TUNTAP_OBJ_HPP
#define C_LINUX_TUNTAP_OBJ_HPP

#include <boost/asio.hpp>
#include <iostream>
#include "../strings_utils.hpp"
#include "../cjdns-code/NetPlatform.h"

using namespace std;

#define print_debug(X) { ::std::ostringstream _dbg_oss; _dbg_oss<<__LINE__<<": "<<X<<::std::endl;  ::std::cerr<<_dbg_oss.str(); }


#define _dbg4(X) {if(0) { print_debug(X); } }
#define _dbg1(X) {if(0)_dbg4(X);}
#define _note(X) {if(0)_dbg4(X);}
#define _mark(X) {if(0)_dbg4(X);}
#define _fact(X) {if(0)_dbg4(X);}
#define _warn(X) {if(0)_dbg4(X);}
#define _info(X) {if(0)_dbg4(X);}


#define _erro(X) { print_debug("\n\n@@@@@@ ERRROR: " << X << "\n\n" ); }
#define _goal(X) { print_debug( "------ " << X ); }
constexpr int g_haship_addr_size = 16;

template <typename T>
class as_zerofill : public T {
	public:
		as_zerofill() {
			assert( sizeof(*this) == sizeof(T) ); // TODO move to static assert. sanity check. quote isostd
			void* baseptr = static_cast<void*>( dynamic_cast<T*>(this) );
			assert(baseptr == this); // TODO quote isostd
			memset( baseptr , 0 , sizeof(T) );
		}
		T& get() { return *this; }
};

using t_ipv4dot = std::string;
using t_ipv6dot = std::string;
using t_ipv6bin = std::string;

/***
@class virtual hash-ip, e.g. ipv6, usable for ipv6-cjdns (fc00/8), and of course also for our ipv6-galaxy (fd42/16)
*/
struct c_haship_addr : public std::array<unsigned char, g_haship_addr_size> {
	struct tag_constr_by_hash_of_pubkey{}; // address is calculated from hash of given public key
	struct tag_constr_by_addr_dot{}; // address is in form of t_ipv6dot
	struct tag_constr_by_addr_bin{}; // address is in form of t_ipv6bin
	struct tag_constr_by_array_uchar{}; // address is in form of std::array of unsigned char of proper size

	c_haship_addr(); ///< address is zero filled

	/// create the IP address from a string (as dot/colon IP notation)
	c_haship_addr(tag_constr_by_addr_dot x, const t_ipv6dot & addr_string);
	/// create the IP address from binary serialization of the IP address
	c_haship_addr(tag_constr_by_addr_bin x, const t_ipv6bin & data );
	/// create the IP address from std::array of unsigned char
	c_haship_addr(tag_constr_by_array_uchar x, const std::array<unsigned char, g_haship_addr_size> & data);

	void print(std::ostream &ostr) const;
	std::string get_hip_as_string(bool with_dots) const;
	bool is_empty() const;
	static c_haship_addr make_empty(); ///< named constructor
};

ostream& operator<<(ostream &ostr, const c_haship_addr & v);

class c_tuntap_system_functions final {
	public:
		int ioctl(int fd, unsigned long request,  void *ifreq);
		t_syserr NetPlatform_addAddress(const char* interfaceName,
		                                const uint8_t* address,
		                                int prefixLen,
		                                int addrFam);
		t_syserr NetPlatform_setMTU(const char* interfaceName,
		                            uint32_t mtu);
};

constexpr size_t IPV6_LEN = 16;
using read_handler = std::function<void(const unsigned char *, std::size_t, const boost::system::error_code &)>;

class c_tuntap_linux_obj final {
	public:
		c_tuntap_linux_obj(); ///< construct this object, throws if error

		size_t send_to_tun(const unsigned char *data, size_t size);
		size_t send_to_tun_separated_addresses(const unsigned char * const data, size_t size,
			const std::array<unsigned char, IPV6_LEN> &src_binary_address,
			const std::array<unsigned char, IPV6_LEN> &dst_binary_address);
		size_t read_from_tun(unsigned char * const data, size_t size);
		size_t read_from_tun_separated_addresses(unsigned char * const data, size_t size,
			std::array<unsigned char, IPV6_LEN> &src_binary_address,
			std::array<unsigned char, IPV6_LEN> &dst_binary_address);
		void async_receive_from_tun(unsigned char * const data, size_t size, const read_handler & handler);
		void set_tun_parameters
			(const std::array<unsigned char, IPV6_LEN> &binary_address, int prefix_len, uint32_t mtu);
		boost::asio::posix::stream_descriptor &get_asio_handle();
	private:
		const int m_tun_fd; ///< the unix file descriptor. -1 is closed (this should not happen in correct object)
		boost::asio::io_service m_io_service;
#ifdef USE_MOCK
		using stream_type = mock::mock_posix_stream_descriptor;
		using sys_functions_wrapper = testing::NiceMock<mock::mock_tuntap_system_functions>;
#else
		using stream_type = boost::asio::posix::stream_descriptor;
		using sys_functions_wrapper = c_tuntap_system_functions;
#endif
		stream_type m_tun_stream;
		sys_functions_wrapper sys_fun;
};

#endif // C_LINUX_TUNTAP_OBJ_HPP

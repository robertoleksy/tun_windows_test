#include "c_tuntap_linux_obj.hpp"

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifndef USE_MOCK
int c_tuntap_system_functions::ioctl(int fd, unsigned long request, void *ifreq) {
	return ::ioctl(fd, request, ifreq);
}

t_syserr c_tuntap_system_functions::NetPlatform_addAddress(const char *interfaceName,
                                                           const uint8_t *address,
                                                           int prefixLen,
                                                           int addrFam) {
	return ::NetPlatform_addAddress(interfaceName, address, prefixLen, addrFam);
}

t_syserr c_tuntap_system_functions::NetPlatform_setMTU(const char *interfaceName, uint32_t mtu) {
	return ::NetPlatform_setMTU(interfaceName, mtu);
}
#endif








// c_haship_addr :
c_haship_addr::c_haship_addr()
	 : std::array<unsigned char, g_haship_addr_size>({{}})
{
	fill(0);
}


c_haship_addr::c_haship_addr(tag_constr_by_addr_dot, const t_ipv6dot & addr_string) {
//	_dbg3("parsing ip addr_string=" << addr_string);
	// use boost asio for parsing
	boost::asio::ip::address_v6 asio_addr_v6;
	try {
		asio_addr_v6 = boost::asio::ip::address_v6::from_string(addr_string);
		boost::asio::ip::address_v6::bytes_type asio_addr_bytes = asio_addr_v6.to_bytes();

		assert (asio_addr_bytes.size() == 16); // 16 = 128/8
		for (int i = 0; i < 128 / 8; ++i) {
			this->at(i) = asio_addr_bytes.at(i);
		}
	} catch (boost::exception &err) {
		throw std::invalid_argument("The IP address looks invalid ["+addr_string+"]");
	}
	_dbg4("Parsed string addr=" << asio_addr_v6.to_string());
	_dbg4("Parsed bytes addr=" << *this);
}

c_haship_addr::c_haship_addr(tag_constr_by_addr_bin, const t_ipv6bin & data ) {
	if (! ( this->size() == data.size() ) ) {
		ostringstream oss; oss << "Trying to set hip address from binary data " << to_debug_b(data);
		throw  std::runtime_error(oss.str());
	}
	for (size_t i=0; i<this->size(); ++i) this->at(i) = data.at(i);
}

c_haship_addr::c_haship_addr(tag_constr_by_array_uchar, const std::array<unsigned char, g_haship_addr_size> & data) {
	assert(data.size() == this->size());
	std::copy(data.begin(), data.end(), this->begin());
}

void c_haship_addr::print(ostream &ostr) const {
	ostr << "hip=" << get_hip_as_string(true);
}

string c_haship_addr::get_hip_as_string(bool with_dots) const{
    string_as_hex dbg( string_as_bin(*this) );
    string hip(dbg.get());
    ostringstream out;
    for(auto it = hip.begin(); it < hip.end(); it++)
    {
        if(with_dots && it != hip.begin() && (it - hip.begin()) % 4 == 0)
            out << ':';
        out << *it;
    }
    return out.str();
}

bool c_haship_addr::is_empty() const {
	for (auto & byte : *this)
		if (byte != 0) return false;
	return true;
}

c_haship_addr c_haship_addr::make_empty() {
	c_haship_addr ret;
	ret.fill(0);
	return ret;
}
ostream& operator<<(ostream &ostr, const c_haship_addr & v) {	v.print(ostr);	return ostr; }



















/////////////////////////////////////////////////////////////////////

c_tuntap_linux_obj::c_tuntap_linux_obj() :
	m_tun_fd(open("/dev/net/tun", O_RDWR)),
	m_io_service(),
	m_tun_stream(m_io_service, m_tun_fd)
{
	_fact("tuntap opened with m_tun_fd=" << m_tun_fd);
	assert(m_tun_fd != -1);
	assert(m_tun_stream.is_open());
	try {
		//set_sockopt_timeout( m_tun_stream.native_handle() , sockopt_timeout_get_default() );
	} catch(const std::exception &ex) { _warn("Can not set timtout for tuntap: " << ex.what()); }
	_goal("tuntap is opened correctly");
}

size_t c_tuntap_linux_obj::send_to_tun(const unsigned char *data, size_t size) {
	try {
		return m_tun_stream.write_some(boost::asio::buffer(data, size));
	} catch (const std::exception &) {
		return 0; // error
	}
}

size_t c_tuntap_linux_obj::send_to_tun_separated_addresses(const unsigned char *const data, size_t size,
	const std::array<unsigned char, IPV6_LEN> &src_binary_address,
	const std::array<unsigned char, IPV6_LEN> &dst_binary_address) {
	assert(size >= 8);
	std::array<boost::asio::const_buffer, 4> buffers;
	buffers.at(0) = boost::asio::buffer(data, 8); // version, traffic, flow label, payload length, next header, hop limit
	buffers.at(1) = boost::asio::buffer(src_binary_address.data(), src_binary_address.size());
	buffers.at(2) = boost::asio::buffer(dst_binary_address.data(), dst_binary_address.size());
	buffers.at(3) = boost::asio::buffer(data + 8, size - 8); // 8 bytes are filled in buffers.at(0)
	boost::system::error_code ec;
	return m_tun_stream.write_some(buffers, ec);
}

size_t c_tuntap_linux_obj::read_from_tun(unsigned char *const data, size_t size) {
	try {
		return m_tun_stream.read_some(boost::asio::buffer(data, size));
	} catch (const std::exception &) {
		return 0; // error
	}
}

size_t c_tuntap_linux_obj::read_from_tun_separated_addresses(unsigned char *const data, size_t size,
	std::array<unsigned char, IPV6_LEN> &src_binary_address,
	std::array<unsigned char, IPV6_LEN> &dst_binary_address) {
	assert(size >= 8);
	// field sizes based on rfc2460
	// https://tools.ietf.org/html/rfc2460
	std::array<boost::asio::mutable_buffer, 4> buffers;
	buffers.at(0) = boost::asio::buffer(data, 8); // version, traffic, flow label, payload length, next header, hop limit
	buffers.at(1) = boost::asio::buffer(src_binary_address.data(), src_binary_address.size());
	buffers.at(2) = boost::asio::buffer(dst_binary_address.data(), dst_binary_address.size());
	buffers.at(3) = boost::asio::buffer(data + 8, size - 8); // 8 bytes are filled in buffers.at(0)
	try {
		return m_tun_stream.read_some(buffers) - src_binary_address.size() - dst_binary_address.size();
	} catch (const std::exception &) {
		return 0;
	}
}

void c_tuntap_linux_obj::async_receive_from_tun(unsigned char *const data,
                                                size_t size,
                                                const read_handler & handler) {

	auto asio_handler = [data, handler](const boost::system::error_code& error, std::size_t bytes_transferred) {
		handler(data, bytes_transferred, error);
	};
	return m_tun_stream.async_read_some(boost::asio::buffer(data, size), asio_handler);
}

void c_tuntap_linux_obj::set_tun_parameters(const std::array<unsigned char, IPV6_LEN> &binary_address,
                                            int prefix_len,
                                            uint32_t mtu) {

	c_haship_addr address(c_haship_addr::tag_constr_by_array_uchar(), binary_address);
	_goal("Configuring tuntap options: IP address: " << address << "/" << prefix_len << " MTU=" << mtu);
	as_zerofill< ifreq > ifr; // the if request
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, "galaxy%d", IFNAMSIZ);
	int errcode_ioctl = sys_fun.ioctl(m_tun_fd, TUNSETIFF, static_cast<void *>(&ifr));
	assert(errcode_ioctl != -1);
//	_check_input(binary_address[0] == 0xFD);
//	_check_input(binary_address[1] == 0x42);
	t_syserr err;
	err = sys_fun.NetPlatform_addAddress(ifr.ifr_name, binary_address.data(), prefix_len, Sockaddr_AF_INET6);
	if (err.my_code != 0) throw std::runtime_error("NetPlatform_addAddress error");
	err = sys_fun.NetPlatform_setMTU(ifr.ifr_name, mtu);
	if (err.my_code != 0) throw std::runtime_error("NetPlatform_setMTU error");
	m_tun_stream.release();
	m_tun_stream.assign(m_tun_fd);
	_goal("Configuring tuntap options - done");
}

boost::asio::posix::stream_descriptor &c_tuntap_linux_obj::get_asio_handle() {
	return m_tun_stream;
}

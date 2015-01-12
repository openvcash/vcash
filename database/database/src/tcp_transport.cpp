/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/random.hpp>
#include <database/protocol.hpp>
#include <database/tcp_transport.hpp>

using namespace database;

tcp_transport::tcp_transport(boost::asio::io_service & ios)
    : m_state(state_disconnected)
    , m_socket(ios)
    , m_close_after_writes(false)
    , m_read_timeout(0)
    , m_write_timeout(0)
    , io_service_(ios)
    , strand_(ios)
    , connect_timeout_timer_(ios)
    , read_timeout_timer_(ios)
    , write_timeout_timer_(ios)
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    , readStreamRef_(0)
    , writeStreamRef_(0)
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
{
    // ...
}

tcp_transport::~tcp_transport()
{   
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    if (readStreamRef_)
    {
        CFReadStreamClose(readStreamRef_);
        CFRelease(readStreamRef_), readStreamRef_ = 0;
    }
    
    if (writeStreamRef_)
    {
        CFWriteStreamClose(writeStreamRef_);
            
        CFRelease(writeStreamRef_), writeStreamRef_ = 0;
    }
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
}
        
void tcp_transport::start(
    const std::string & hostname, const std::uint16_t & port,
    const std::function<void (boost::system::error_code,
    std::shared_ptr<tcp_transport>)> & f
    )
{
    /**
     * Set the completion handler.
     */
    m_on_complete = f;

    auto self(shared_from_this());
    
    connect_timeout_timer_.expires_from_now(std::chrono::seconds(3));
    connect_timeout_timer_.async_wait(strand_.wrap(
        [this, self](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            m_socket.lowest_layer().close();
            
            m_state = state_disconnected;
        }
    }));
    
    try
    {
        boost::asio::ip::tcp::resolver resolver(io_service_);
        boost::asio::ip::tcp::resolver::query query(
            hostname, std::to_string(port)
        );
        do_connect(resolver.resolve(query));
    }
    catch (std::exception & e)
    {
        log_debug("Tcp transport resolve failed, what = " << e.what());
    }
}

void tcp_transport::start()
{
    auto self(shared_from_this());
    
    io_service_.post(strand_.wrap(
        [this, self]()
    {    
        m_state = state_connected;
        
        do_read();
    }));
}
        
void tcp_transport::stop()
{
    auto self(shared_from_this());
    
    io_service_.post(strand_.wrap(
        [this, self]()
    {
        connect_timeout_timer_.cancel();
        read_timeout_timer_.cancel();
        write_timeout_timer_.cancel();
        m_socket.lowest_layer().close();
        m_state = state_disconnected;
    }));
}

void tcp_transport::set_on_read(
    const std::function<void (std::shared_ptr<tcp_transport>, const char *,
    const std::size_t &)> & f
    )
{
    m_on_read = f;
}

void tcp_transport::write(const char * buf, const std::size_t & len)
{
    auto self(shared_from_this());
    
    std::vector<char> buffer(buf, buf + len);
    
    if (m_state == state_connected)
    {
        io_service_.post(strand_.wrap(
            [this, self, buffer]()
        {
            bool write_in_progress = !write_queue_.empty();
            
            write_queue_.push_back(buffer);
          
            if (!write_in_progress)
            {
                do_write(
                    &write_queue_.front()[0], write_queue_.front().size()
                );
            }
        }));
    }
    else
    {
        io_service_.post(strand_.wrap(
            [this, self, buffer]()
        {
            write_queue_.push_back(buffer);
        }));
    }
}

tcp_transport::state_t & tcp_transport::state()
{
    return m_state;
}

void tcp_transport::set_identifier(const std::string & val)
{
    m_identifier = val;
}

const std::string & tcp_transport::identifier() const
{
    return m_identifier;
}

boost::asio::ip::tcp::socket & tcp_transport::socket()
{
    return m_socket;
}

void tcp_transport::set_close_after_writes(const bool & flag)
{
    m_close_after_writes = flag;
}

void tcp_transport::set_read_timeout(const std::uint32_t & val)
{
    m_read_timeout = val;
}

void tcp_transport::set_write_timeout(const std::uint32_t & val)
{
    m_write_timeout = val;
}

void tcp_transport::do_connect(
    boost::asio::ip::tcp::resolver::iterator endpoint_iterator
    )
{
    using namespace boost;
    
    auto self(shared_from_this());
    
    m_state = state_connecting;
    
    asio::async_connect(m_socket.lowest_layer(), endpoint_iterator,
        [this, self](system::error_code ec, boost::asio::ip::tcp::resolver::iterator)
    {
        if (ec)
        {
            m_socket.lowest_layer().close();
            
            m_state = state_disconnected;
            
            if (m_on_complete)
            {
                m_on_complete(ec, self);
            }
        }
        else
        {
            connect_timeout_timer_.cancel();
            
            m_state = state_connected;
            
            if (m_on_complete)
            {
                m_on_complete(ec, self);
            }
    
            if (!write_queue_.empty())
            {
                do_write(
                    &write_queue_.front()[0], write_queue_.front().size()
                );
            }
            
            do_read();
        }
    });
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    set_voip();
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
}

void tcp_transport::do_read()
{
    if (m_state == state_connected)
    {
        auto self(shared_from_this());

        if (m_read_timeout > 0)
        {
            read_timeout_timer_.expires_from_now(
                std::chrono::seconds(m_read_timeout)
            );
            read_timeout_timer_.async_wait(strand_.wrap(
                [this, self](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    log_debug("TCP transport receive timed out, closing.");
                    
                    m_socket.lowest_layer().close();
                    
                    m_state = state_disconnected;
                }
            }));
        }
        
        m_socket.async_read_some(boost::asio::buffer(read_buffer_),
            [this, self](boost::system::error_code ec, std::size_t len)
        {
            if (ec)
            {
                m_socket.lowest_layer().close();
                
                m_state = state_disconnected;
            }
            else
            {
                read_timeout_timer_.cancel();
                
                /**
                 * Append to the read queue.
                 */
                read_queue_.insert(
                    read_queue_.end(), read_buffer_, read_buffer_ + len
                );
                
                while (
                    read_queue_.size() >= sizeof(protocol::header_tcp_t))
                {
                    /**
                     * Allocate a (possibly) full packet.
                     */
                    std::string partial_packet(
                        read_queue_.begin(),
                        read_queue_.begin() + sizeof(protocol::header_tcp_t)
                    );
                    
                    /**
                     * Allocate header.
                     */
                    protocol::header_tcp_t header_tcp;
                    
                    /**
                     * Copy the header.
                     */
                    std::memcpy(
                        &header_tcp, partial_packet.data(),
                        sizeof(protocol::header_tcp_t)
                    );
            
                    /**
                     * Swap the length byte order.
                     */
                    header_tcp.length = ntohl(header_tcp.length);
            
                    /**
                     * Check if we have received enough for a full message.
                     */
                    if (
                        read_queue_.size() < sizeof(protocol::header_tcp_t) +
                        header_tcp.length
                        )
                    {
                        break;
                    }
                    else
                    {
                        /**
                         * Allocate the full packet.
                         */
                        std::string full_packet(
                            read_queue_.begin(), read_queue_.begin() +
                            (sizeof(protocol::header_tcp_t) +
                            header_tcp.length)
                        );
                        
                        /**
                         * Erase the full packet.
                         */
                        read_queue_.erase(
                            read_queue_.begin(), read_queue_.begin() +
                            (sizeof(protocol::header_tcp_t) + header_tcp.length)
                        );
                        
                        /**
                         * Callback
                         */
                        if (m_on_read)
                        {
                            m_on_read(
                                self, full_packet.data(), full_packet.size()
                            );
                        }
                    }
                }
                
                do_read();
            }
        });
    }
}

void tcp_transport::do_write(const char * buf, const std::size_t & len)
{
    using namespace boost;
    
    auto self(shared_from_this());

    if (m_write_timeout > 0)
    {
        write_timeout_timer_.expires_from_now(
            std::chrono::seconds(m_write_timeout)
        );
        write_timeout_timer_.async_wait(strand_.wrap(
            [this, self](boost::system::error_code ec)
        {
            if (ec)
            {
                // ...
            }
            else
            {
                log_debug("TCP transport write timed out, closing.");
                
                m_socket.lowest_layer().close();
                
                m_state = state_disconnected;
            }
        }));
    }
    
    asio::async_write(m_socket, asio::buffer(buf, len),
        [this, self](system::error_code ec, std::size_t bytes_transferred)
    {
        if (ec)
        {
            m_socket.lowest_layer().close();
            
            m_state = state_disconnected;
        }
        else
        {
            write_timeout_timer_.cancel();
            
            write_queue_.pop_front();
            
            if (write_queue_.empty())
            {
                if (m_close_after_writes)
                {
                    log_debug("TCP transport write queue is empty, closing.");
                    
                    m_socket.lowest_layer().close();
                    
                    m_state = state_disconnected;
                }
            }
            else
            {
                do_write(
                    &write_queue_.front()[0], write_queue_.front().size()
                );
            }
        }
    });
}

void tcp_transport::set_voip()
{
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    /**
     * To configure a socket for VoIP usage, the only thing you have to do
     * beyond the normal configuration is add a special key that tags the 
     * interface as being associated with a VoIP service.
     */    
    CFStreamCreatePairWithSocket(
        0, (CFSocketNativeHandle)m_socket.native(), &readStreamRef_,
        &writeStreamRef_
    );

    if (
        !CFReadStreamSetProperty(readStreamRef_, kCFStreamNetworkServiceType,
        kCFStreamNetworkServiceTypeVoIP)
        )
    {
        log_error(
            "TCP transport failed to set service type to voip for read stream."
        );
    }
    else
    {
        log_info(
            "TCP transport set service type to "
            "kCFStreamNetworkServiceTypeVoIP for read stream."
        );
    }
    
    if (
        !CFWriteStreamSetProperty(writeStreamRef_,
        kCFStreamNetworkServiceType, kCFStreamNetworkServiceTypeVoIP)
        )
    {
        log_error(
            "TCP transport failed to set service type to voip for write stream."
        );
    }
    else
    {
        log_info(
            "TCP transport set service type to "
            "kCFStreamNetworkServiceTypeVoIP for write stream."
        );
    }
    
    if (!CFReadStreamOpen(readStreamRef_))
    {
        log_error("TCP transport unable open read stream.");
    }
    
    if (!CFWriteStreamOpen(writeStreamRef_))
    {
        log_error("TCP transport unable open write stream.");
    }
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
}

int tcp_transport::run_test()
{
    boost::asio::io_service ios;
    
    std::shared_ptr<tcp_transport> t =
        std::make_shared<tcp_transport>(ios)
    ;
    
    t->start("coinsy.net", 80,
        [](boost::system::error_code ec, std::shared_ptr<tcp_transport> t)
    {
        if (ec)
        {
            std::cerr <<
                "tcp_transport connect failed, message = " <<
                ec.message() <<
            std::endl;
        }
        else
        {
            std::cout <<
                "tcp_transport connect success" <<
            std::endl;
            
            std::stringstream ss;
            ss << "GET" << " "  << "/" << " HTTP/1.0\r\n";
            ss << "Host: " << "coinsy.net" << "\r\n";
            ss << "Accept: */*\r\n";
            ss << "Connection: close\r\n\r\n";
            t->write(ss.str().data(), ss.str().size());
        }
    });
    
    ios.run();

    return 0;
}

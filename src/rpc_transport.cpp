/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * vanillacoin is free software: you can redistribute it and/or modify
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

#include <coin/rpc_transport.hpp>

using namespace coin;

#include <sstream>

#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/rpc_transport.hpp>

using namespace coin;

rpc_transport::rpc_transport(
    boost::asio::io_service & ios, boost::asio::strand & s
    )
    : m_state(state_disconnected)
    , m_close_after_writes(false)
    , m_read_timeout(0)
    , m_write_timeout(0)
    , io_service_(ios)
    , strand_(s)
    , connect_timeout_timer_(ios)
    , read_timeout_timer_(ios)
    , write_timeout_timer_(ios)
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    , readStreamRef_(0)
    , writeStreamRef_(0)
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
{
    m_socket.reset(new boost::asio::ip::tcp::socket(ios));
}

rpc_transport::~rpc_transport()
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
        
void rpc_transport::start(
    const std::string & hostname, const std::uint16_t & port,
    const std::function<void (boost::system::error_code,
    std::shared_ptr<rpc_transport>)> & f
    )
{
    /**
     * Set the completion handler.
     */
    m_on_complete = f;

    auto self(shared_from_this());
    
    connect_timeout_timer_.expires_from_now(std::chrono::seconds(8));
    connect_timeout_timer_.async_wait(strand_.wrap(
        [this, self](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            log_none(
                "TCP transport connect operation timed out after 8 "
                "seconds, closing."
            );
            
            /**
             * Stop
             */
             stop();
        }
    }));
    
    try
    {
        try
        {
            do_connect(
                boost::asio::ip::tcp::endpoint(
                boost::asio::ip::address::from_string(hostname), port)
            );
        }
        catch (...)
        {
            boost::asio::ip::tcp::resolver resolver(io_service_);
            boost::asio::ip::tcp::resolver::query query(
                hostname, std::to_string(port)
            );
            do_connect(resolver.resolve(query));
        }
    }
    catch (std::exception & e)
    {
        log_debug("TCP transport start failed, what = " << e.what());
    }
}

void rpc_transport::start()
{
    m_state = state_connected;
        
    do_read();
}
        
void rpc_transport::stop()
{
    if (m_state != state_disconnected)
    {
        auto self(shared_from_this());

        /**
         * Set the state to state_disconnected.
         */
        m_state = state_disconnected;
        
        /**
         * Shutdown the socket.
         */
        if (m_socket && m_socket->lowest_layer().is_open())
        {
            boost::system::error_code ec;
            
            m_socket->lowest_layer().shutdown(
                boost::asio::ip::tcp::socket::shutdown_both, ec
            );
            
            if (ec)
            {
                log_debug(
                    "TLS socket shutdown error = " << ec.message() << "."
                );
            }
        }
        
        connect_timeout_timer_.cancel();
        read_timeout_timer_.cancel();
        write_timeout_timer_.cancel();
        
        /**
         * Close the socket.
         */
        if (m_socket)
        {
            m_socket->lowest_layer().close();
        }

        m_on_complete = std::function<
            void (boost::system::error_code, std::shared_ptr<rpc_transport>)
        > ();

        m_on_read = std::function<
            void (std::shared_ptr<rpc_transport>, const char *,
            const std::size_t &)
        > ();
    }
}

void rpc_transport::set_on_read(
    const std::function<void (std::shared_ptr<rpc_transport>, const char *,
    const std::size_t &)> & f
    )
{
    m_on_read = f;
}

void rpc_transport::write(const char * buf, const std::size_t & len)
{
    auto self(shared_from_this());
    
    std::vector<char> buffer(buf, buf + len);
    
    if (m_state == state_connected)
    {
        io_service_.post(strand_.wrap(
            [this, self, buffer]()
        {
            bool write_in_progress = write_queue_.size() > 0;
            
            write_queue_.push_back(buffer);
          
            if (write_in_progress == false)
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

rpc_transport::state_t & rpc_transport::state()
{
    return m_state;
}

void rpc_transport::set_identifier(const std::string & val)
{
    m_identifier = val;
}

const std::string & rpc_transport::identifier() const
{
    return m_identifier;
}

boost::asio::ip::tcp::socket & rpc_transport::socket()
{
    return *m_socket;
}

void rpc_transport::set_close_after_writes(const bool & flag)
{
    m_close_after_writes = flag;
}

void rpc_transport::set_read_timeout(const std::uint32_t & val)
{
    m_read_timeout = val;
}

void rpc_transport::set_write_timeout(const std::uint32_t & val)
{
    m_write_timeout = val;
}

void rpc_transport::do_connect(const boost::asio::ip::tcp::endpoint & ep)
{
    auto self(shared_from_this());
    
    m_state = state_connecting;

    m_socket->lowest_layer().async_connect(ep,
        [this, self](boost::system::error_code ec)
    {
        if (ec)
        {
            if (m_on_complete)
            {
                m_on_complete(ec, self);
            }
            
            /**
             * Stop
             */
            stop();
        }
        else
        {
            connect_timeout_timer_.cancel();
            
            m_state = state_connected;
            
            if (m_on_complete)
            {
                m_on_complete(ec, self);
            }
    
            if (write_queue_.size() > 0)
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

void rpc_transport::do_connect(
    boost::asio::ip::tcp::resolver::iterator endpoint_iterator
    )
{
    auto self(shared_from_this());
    
    m_state = state_connecting;
    
    boost::asio::async_connect(m_socket->lowest_layer(), endpoint_iterator,
        [this, self](boost::system::error_code ec,
        boost::asio::ip::tcp::resolver::iterator)
    {
        if (ec)
        {
            if (m_state != state_disconnected)
            {
                /**
                 * Stop
                 */
                 stop();
                
                if (m_on_complete)
                {
                    m_on_complete(ec, self);
                }
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
    
            if (write_queue_.size() > 0)
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

void rpc_transport::do_read()
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
                    
                    /**
                     * Stop
                     */
                     stop();
                }
            }));
        }
        
        m_socket->async_read_some(boost::asio::buffer(read_buffer_),
            [this, self](boost::system::error_code ec, std::size_t len)
        {
            if (ec)
            {
                log_debug(
                    "TCP transport read error, message = " <<
                    ec.message() << ", closing."
                );

                /**
                 * Stop.
                 */
                stop();
            }
            else
            {
                read_timeout_timer_.cancel();
                        
                /**
                 * Callback
                 */
                if (m_on_read)
                {
                    m_on_read(self, read_buffer_, len);
                }
                
                do_read();
            }
        });
    }
}

void rpc_transport::do_write(const char * buf, const std::size_t & len)
{
    if (m_state == state_connected)
    {
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
                    
                    /**
                     * Stop
                     */
                     stop();
                }
            }));
        }

        boost::asio::async_write(*m_socket, boost::asio::buffer(buf, len),
            [this, self](boost::system::error_code ec,
            std::size_t bytes_transferred)
        {
            if (ec)
            {
                /**
                 * Stop
                 */
                 stop();
            }
            else
            {
                write_timeout_timer_.cancel();
                
                write_queue_.pop_front();
                
                if (write_queue_.size() == 0)
                {
                    if (m_close_after_writes)
                    {
                        log_debug(
                            "TCP transport write queue is empty, closing."
                        );
                        
                        /**
                         * Stop
                         */
                         stop();
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
}

void rpc_transport::set_voip()
{
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    CFStreamCreatePairWithSocket(
        0, (CFSocketNativeHandle)m_socket->native(), &readStreamRef_,
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

int rpc_transport::run_test()
{
    boost::asio::io_service ios;
    
    boost::asio::strand s(ios);
    
    std::shared_ptr<rpc_transport> t =
        std::make_shared<rpc_transport>(ios, s)
    ;
    
    t->start("google.com", 80,
        [](boost::system::error_code ec, std::shared_ptr<rpc_transport> t)
    {
        if (ec)
        {
            std::cerr <<
                "rpc_transport connect failed, message = " <<
                ec.message() <<
            std::endl;
        }
        else
        {
            std::cout <<
                "rpc_transport connect success" <<
            std::endl;
            
            std::stringstream ss;
            ss << "GET" << " "  << "/" << " HTTP/1.0\r\n";
            ss << "Host: " << "google.com" << "\r\n";
            ss << "Accept: */*\r\n";
            ss << "Connection: close\r\n\r\n";
            t->write(ss.str().data(), ss.str().size());
        }
    });
    
    ios.run();

    return 0;
}

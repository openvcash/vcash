/*
 * Copyright (c) 2013-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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

#include <sstream>

#include <openssl/ssl.h>

#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/tcp_transport.hpp>

using namespace coin;

boost::system::error_code use_private_key(SSL_CTX * ctx, char * buf)
{
    boost::system::error_code ec;
    
    BIO * bio = ::BIO_new_mem_buf(buf, -1);
    
    if (bio == 0)
    {
        ec = boost::asio::error::invalid_argument;
        return ec;
    }

    EVP_PKEY * pkey = PEM_read_bio_PrivateKey(
        bio, 0, ctx->default_passwd_callback,
        ctx->default_passwd_callback_userdata
    );
    
    BIO_free(bio);
    
    if (pkey == 0)
    {
        ec = boost::asio::error::invalid_argument;
        return ec;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
    {
        ec = boost::asio::error::invalid_argument;
        return ec;
    }
    
    EVP_PKEY_free(pkey);

    ec = boost::system::error_code();
    
    return ec;
}

boost::system::error_code use_tmp_dh(SSL_CTX * ctx, char * buf)
{
    boost::system::error_code ret;
    
    BIO * bio = ::BIO_new_mem_buf(buf, -1);
                
    if (bio == 0)
    {
        ret = boost::asio::error::invalid_argument;
        
        return ret;
    }

    DH * dh = ::PEM_read_bio_DHparams(bio, 0, 0, 0);
            
    if (dh == 0)
    {
        BIO_free(bio);
        
        ret = boost::asio::error::invalid_argument;
        
        return ret;
    }

    BIO_free(bio);
            
    auto result = SSL_CTX_set_tmp_dh(ctx, dh);
                
    if (result != 1)
    {
        DH_free(dh);
        
        ret = boost::asio::error::invalid_argument;
        
        return ret;
    }
    
    DH_free(dh);
    
    ret = boost::system::error_code();
    
    return ret;
}

boost::system::error_code use_certificate_chain(SSL_CTX * ctx, char * buf)
{
    boost::system::error_code ec;
    
    BIO * bio = ::BIO_new_mem_buf(buf, -1);
    
    if (bio == 0)
    {
        ec = boost::asio::error::invalid_argument;
        
        return ec;
    }
    
	X509 * x = PEM_read_bio_X509(bio, 0, 0, 0);
    
    if (x == 0)
    {
        ec = boost::asio::error::invalid_argument;
        
        return ec;
    }

    if (SSL_CTX_use_certificate(ctx, x) != 1)
    {
        ec = boost::asio::error::invalid_argument;
        
        return ec;
    }
    
    X509_free(x);

    X509 * ca = 0;
		
    if (ctx->extra_certs != 0)
    {
        sk_X509_pop_free(ctx->extra_certs, X509_free);
        ctx->extra_certs = 0;
    }

    while (
        (ca = PEM_read_bio_X509( bio, 0, ctx->default_passwd_callback,
        ctx->default_passwd_callback_userdata)
        ) != 0)
    {
        if (SSL_CTX_add_extra_chain_cert(ctx, ca) != 1)
        {
            X509_free(ca);
            
            return boost::asio::error::invalid_argument;
        }
    }
 
    BIO_free(bio);

    ec = boost::system::error_code();
    
    return ec;
}

void print_cipher_list(const SSL * s)
{
    std::stringstream ss;
    
    auto i = 0;
    
    const char * ptr = 0;
    
    ss << "TCP transport cipher list: ";
    
    do
    {
        ptr = SSL_get_cipher_list(s, i);
        
        if (ptr != 0)
        {
            ss << ptr;
            ss << " ";
            
            i++;
        }
    }
    while (ptr != 0);
    
    log_debug(ss.str());
}

tcp_transport::tcp_transport(
    boost::asio::io_service & ios, boost::asio::strand & s
    )
    : m_state(state_disconnected)
    , m_close_after_writes(false)
    , m_read_timeout(0)
    , m_write_timeout(0)
    , m_time_last_read(0)
    , m_time_last_write(0)
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
    /**
     * The temporary Diffie–Hellman parameters.
     */
    static char tmp_dh_buf[] =
    {
        "-----BEGIN DH PARAMETERS-----\n"
        "MEYCQQCK3iSb85hymUqRKvE1aMFJtxuZCmERLX5A1RaUH+HajZC2crc8UCkbFIb6\n"
        "gN7dtgQusSzCschXrtSv/s10O+NzAgEC\n"
        "-----END DH PARAMETERS-----\n"
    };
    
    /**
     * Allocate the boost::asio::ssl::context.
     */
    m_ssl_context.reset(
        new boost::asio::ssl::context(boost::asio::ssl::context::tlsv1)
    );
    
    /** 
     * Set the options.
     */
    m_ssl_context->set_options(
        boost::asio::ssl::context::default_workarounds | 
        boost::asio::ssl::context::no_sslv2 | 
        boost::asio::ssl::context::single_dh_use
    );


    /**
     * Use temporary Diffie-Hellman paramaters.
     */
    use_tmp_dh(m_ssl_context->impl(), tmp_dh_buf);
    
    /**
     * Replace with SSL_CTX_set_ecdh_auto when supported.
     */
    EC_KEY * ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    
    /**
     * Set the temporary Elliptic Curve Diffie-Hellman.
     */
    if (ecdh)
    {
        if (SSL_CTX_set_tmp_ecdh(m_ssl_context->impl(), ecdh) != 1)
        {
            log_error("TCP transport failed to set SSL_CTX_set_tmp_ecdh.");
        }
        
        EC_KEY_free(ecdh);
    }

    /**
     * Allocate the cipher list.
     */
    std::string cipher_list;
    
    /**
     * Create the cipher list.
     * + TLS_ECDH_anon_WITH_RC4_128_SHA        AECDH-RC4-SHA
     * + TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA   AECDH-DES-CBC3-SHA
     * + TLS_ECDH_anon_WITH_AES_128_CBC_SHA    AECDH-AES128-SHA
     * + TLS_ECDH_anon_WITH_AES_256_CBC_SHA    AECDH-AES256-SHA
     */
    cipher_list += "AECDH-RC4-SHA";
    cipher_list += " ";
    cipher_list += "AECDH-DES-CBC3-SHA";
    cipher_list += " ";
    cipher_list += "AECDH-AES128-SHA";
    cipher_list += " ";
    cipher_list += "AECDH-AES256-SHA";
    cipher_list += " ";
    
    /**
     * Set the cipher list.
     */
    if (
        SSL_CTX_set_cipher_list(m_ssl_context->impl(), cipher_list.c_str()) != 1
        )
    {
        log_error("SSL_CTX_set_cipher_list failed.");
    }

    /**
     * Allocate the socket.
     */
    m_socket.reset(
        new boost::asio::ssl::stream<boost::asio::ip::tcp::socket> (
        ios, *m_ssl_context))
    ;
    
    /**
     * Set the verify mode.
     */
    m_socket->set_verify_mode(boost::asio::ssl::context::verify_none);

    if (globals::instance().debug() && false)
    {
        /**
         * Print the cipher list.
         */
        print_cipher_list(m_socket->native_handle());
    }
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

void tcp_transport::start()
{
    auto self(shared_from_this());
    
    if (m_socket)
    {
        m_socket->async_handshake(boost::asio::ssl::stream_base::server,
            [this, self](boost::system::error_code ec)
        {
            if (ec)
            {
                /**
                 * Stop.
                 */
                stop();
            }
            else
            {
                m_state = state_connected;
                
                do_read();
            }
        });
    }
}
        
void tcp_transport::stop()
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
            void (boost::system::error_code, std::shared_ptr<tcp_transport>)
        > ();

        m_on_read = std::function<
            void (std::shared_ptr<tcp_transport>, const char *,
            const std::size_t &)
        > ();
    }
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

boost::asio::ssl::stream<
    boost::asio::ip::tcp::socket
>::lowest_layer_type & tcp_transport::socket()
{
    return m_socket->lowest_layer();
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

const std::time_t & tcp_transport::time_last_read()
{
    return m_time_last_read;
}

const std::time_t & tcp_transport::time_last_write()
{
    return m_time_last_write;
}

void tcp_transport::do_connect(const boost::asio::ip::tcp::endpoint & ep)
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
            m_socket->async_handshake(boost::asio::ssl::stream_base::client,
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
                            &write_queue_.front()[0],
                            write_queue_.front().size()
                        );
                    }
                    
                    do_read();
                }
            });
        }
    });
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    set_voip();
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
}

void tcp_transport::do_connect(
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
            m_socket->async_handshake(boost::asio::ssl::stream_base::client,
                [this, self](boost::system::error_code ec)
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
                            &write_queue_.front()[0],
                            write_queue_.front().size()
                        );
                    }
                    
                    do_read();
                }
            });
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
                /**
                 * Set the time last read.
                 */
                m_time_last_read = std::time(0);
                
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

void tcp_transport::do_write(const char * buf, const std::size_t & len)
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
                /**
                 * Set the time last write.
                 */
                m_time_last_write = std::time(0);
                
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

void tcp_transport::set_voip()
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

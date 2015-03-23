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

#include <sstream>

#if (defined USE_TLS && USE_TLS)
#include <openssl/ssl.h>
#endif //USE_TLS

#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/tcp_transport.hpp>

using namespace coin;

#if (defined USE_TLS && USE_TLS)
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
#endif // USE_TLS

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
#if (defined USE_TLS && USE_TLS)

    /**
     * This key/pair is safe in public hands. It is for web browser
     * compatibility (testing) and serves no other purpose.
     */

    /**
     * The private key.
     */
    static char key_buf[] =
    {
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICXAIBAAKBgQDygv8O6KuUO2MhiL51oTHJC7ELRbg8i9NHAZv/etJjEMCEcSYN\n"
        "Ma017BqUnjsdyb8mTKaGbwITdHpcWpbPhAWZnD3l1u8Kf0Wl4PHkYipdwkx6r53J\n"
        "l+fKLjrQ1sekoqHkmpKdFGLimzdbQGPCd5RwWhVVE6W81tGNKANf+wN3XQIDAQAB\n"
        "AoGARxd3xdsXUWEHcnEvxDP48ELpJ7DMjZM/4HTsUjyjKD9k8G5rBTsm18PbFu47\n"
        "zkOyMXwO5SHtrd5bcG9t/m9pZEh/HqPqcaJemZYsuJgAMYAXoVbgb3FVFkMYYH0U\n"
        "JAlHiVkFberR4GK0wDe74wXn7vnCrEAw/DMj37WSxZ9gFoECQQD5T2IBsD008rLi\n"
        "LL/Zmi4JW/Iab3yoUa5qebNL6HpJVuOTEKNFa03nVOOxCed98J1RPcBeWY6MRHCU\n"
        "dFAFwxkFAkEA+QTpmHgGhhH6IIgTyaHPCEnKv3o43xwOizienZ/9c4W0pJljf8Qa\n"
        "iADqakC23f260FJ2xMqab28Q1MPXDutUeQJAMDqBFR6I2KNSo5pQisHewgS9cwu6\n"
        "K72RZhug6cBRV7qtT5faXeWCLownd+oYlC5l4H93pUjh4JSkyrMtf8/cGQJBAMmE\n"
        "/DVzDHR7H9wrwzetRooCjZ0fH98OKYbpLxOIYeeXEHUT3L2MyZu+gfWyoUpNB12H\n"
        "Hq5q90eurgRA6E0ejKECQG5Q4uC9uoomCS5IQeyF5d1+dXJp9YjyCF158CjxsjUZ\n"
        "Q0a0EqGGuTBCz8YcFhFYIOyRaOQjbJVTckztXDl2ABw=\n"
        "-----END RSA PRIVATE KEY-----\n"
    };
    
    /**
     * The chain file (public and private key).
     */
    static char chain_buf[] =
    {
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIICXAIBAAKBgQDygv8O6KuUO2MhiL51oTHJC7ELRbg8i9NHAZv/etJjEMCEcSYN\n"
        "Ma017BqUnjsdyb8mTKaGbwITdHpcWpbPhAWZnD3l1u8Kf0Wl4PHkYipdwkx6r53J\n"
        "l+fKLjrQ1sekoqHkmpKdFGLimzdbQGPCd5RwWhVVE6W81tGNKANf+wN3XQIDAQAB\n"
        "AoGARxd3xdsXUWEHcnEvxDP48ELpJ7DMjZM/4HTsUjyjKD9k8G5rBTsm18PbFu47\n"
        "zkOyMXwO5SHtrd5bcG9t/m9pZEh/HqPqcaJemZYsuJgAMYAXoVbgb3FVFkMYYH0U\n"
        "JAlHiVkFberR4GK0wDe74wXn7vnCrEAw/DMj37WSxZ9gFoECQQD5T2IBsD008rLi\n"
        "LL/Zmi4JW/Iab3yoUa5qebNL6HpJVuOTEKNFa03nVOOxCed98J1RPcBeWY6MRHCU\n"
        "dFAFwxkFAkEA+QTpmHgGhhH6IIgTyaHPCEnKv3o43xwOizienZ/9c4W0pJljf8Qa\n"
        "iADqakC23f260FJ2xMqab28Q1MPXDutUeQJAMDqBFR6I2KNSo5pQisHewgS9cwu6\n"
        "K72RZhug6cBRV7qtT5faXeWCLownd+oYlC5l4H93pUjh4JSkyrMtf8/cGQJBAMmE\n"
        "/DVzDHR7H9wrwzetRooCjZ0fH98OKYbpLxOIYeeXEHUT3L2MyZu+gfWyoUpNB12H\n"
        "Hq5q90eurgRA6E0ejKECQG5Q4uC9uoomCS5IQeyF5d1+dXJp9YjyCF158CjxsjUZ\n"
        "Q0a0EqGGuTBCz8YcFhFYIOyRaOQjbJVTckztXDl2ABw=\n"
        "-----END RSA PRIVATE KEY-----\n"
        "-----BEGIN CERTIFICATE-----\n"
        "MIICATCCAWoCCQCr5V+G3Ch9MDANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJB\n"
        "VTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0\n"
        "cyBQdHkgTHRkMB4XDTE0MTIwODAwMzk1MFoXDTI0MTIwNTAwMzk1MFowRTELMAkG\n"
        "A1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0\n"
        "IFdpZGdpdHMgUHR5IEx0ZDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA8oL/\n"
        "DuirlDtjIYi+daExyQuxC0W4PIvTRwGb/3rSYxDAhHEmDTGtNewalJ47Hcm/Jkym\n"
        "hm8CE3R6XFqWz4QFmZw95dbvCn9FpeDx5GIqXcJMeq+dyZfnyi460NbHpKKh5JqS\n"
        "nRRi4ps3W0BjwneUcFoVVROlvNbRjSgDX/sDd10CAwEAATANBgkqhkiG9w0BAQUF\n"
        "AAOBgQDLQ55GLq7gubsV1CdGK4g3jPPc+nPSpiEToepqkIdjz98O5TIVGGvjKoDU\n"
        "K/rBXEg5tHPrDtvi/M8gQ/7Xn5oF8RB3h0CJ9gc2zA9VdDpOWvPc/Ha/xuOrzHBR\n"
        "EoiESyrxBQinuRqjAfUCbGN1kCbrr5R4g7ocljNnbx4HUQzjFQ==\n"
        "-----END CERTIFICATE-----\n"
    };
    
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
     * Use a certificate chain.
     */
    use_certificate_chain(m_ssl_context->impl(), chain_buf);

    /** 
     * Use a private key.
     */
    use_private_key(m_ssl_context->impl(), key_buf);

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
     * + TLS_ECDH_RSA_WITH_AES_256_SHA         ECDHE-RSA-AES256-SHA
     * + TLS_ECDH_anon_WITH_RC4_128_SHA        AECDH-RC4-SHA
     * + TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA   AECDH-DES-CBC3-SHA
     * + TLS_ECDH_anon_WITH_AES_128_CBC_SHA    AECDH-AES128-SHA
     * + TLS_ECDH_anon_WITH_AES_256_CBC_SHA    AECDH-AES256-SHA
     */
    cipher_list += "ECDHE-RSA-AES256-SHA";
    cipher_list += " ";
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
#else
    m_socket.reset(new boost::asio::ip::tcp::socket(ios));
#endif // USE_TLS
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

void tcp_transport::start()
{
    auto self(shared_from_this());
    
#if (defined USE_TLS && USE_TLS)
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
#else
    m_state = state_connected;
        
    do_read();
#endif // USE_TLS
}
        
void tcp_transport::stop()
{
    if (m_state != state_disconnected)
    {
        auto self(shared_from_this());

#if (defined USE_TLS && USE_TLS)
        /**
         * This can cause a deadlock in OpenSSL under specific conditions
         * related to it's asio integration and blocking behaviour. We will
         * keep it disabled for some time before complete removal because it
         * is not required in "ungraceful" autonomous environments.
         */
#if 0
        if (m_socket)
        {
            try
            {
                m_socket->shutdown();
            }
            catch (std::exception & e)
            {
                log_debug(
                    "TCP transport failed to shutdown SSL, what = " <<
                    e.what() << "."
                );
            }
        }
#endif // #if 0
#endif // USE_TLS

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

#if (defined USE_TLS && USE_TLS)
boost::asio::ssl::stream<
    boost::asio::ip::tcp::socket
>::lowest_layer_type & tcp_transport::socket()
#else
boost::asio::ip::tcp::socket & tcp_transport::socket()
#endif // USE_TLS
{
#if (defined USE_TLS && USE_TLS)
    return m_socket->lowest_layer();
#else
    return *m_socket;
#endif // USE_TLS
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
#if (defined USE_TLS && USE_TLS)
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
#else
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
#endif // USE_TLS
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
#if (defined USE_TLS && USE_TLS)
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
#else
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
#endif // USE_TLS
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
        0, (CFSocketNativeHandle)m_socket->lowest_layer().native(),
        &readStreamRef_, &writeStreamRef_
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
    
    boost::asio::strand s(ios);
    
    std::shared_ptr<tcp_transport> t =
        std::make_shared<tcp_transport>(ios, s)
    ;
    
    t->start("google.com", 80,
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
            ss << "Host: " << "google.com" << "\r\n";
            ss << "Accept: */*\r\n";
            ss << "Connection: close\r\n\r\n";
            t->write(ss.str().data(), ss.str().size());
        }
    });
    
    ios.run();

    return 0;
}

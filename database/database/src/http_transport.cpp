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

#include <cassert>

#include <boost/algorithm/string.hpp>

#include <database/http_transport.hpp>
#include <database/logger.hpp>

using namespace database;

http_transport::http_transport(
    boost::asio::io_service & ios, const std::string & url
    )
    : m_url(boost::algorithm::to_lower_copy(url))
    , m_secure(false)
    , m_method("GET")
    , m_status_code(-1)
    , io_service_(ios)
    , strand_(ios)
    , timeout_timer_(ios)
    , response_(new boost::asio::streambuf())
    , redirects_(0)
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    , readStreamRef_(0)
    , writeStreamRef_(0)
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
{
    assert(!url.empty());
}

http_transport::~http_transport()
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
  

void http_transport::start(
    const std::function<void (boost::system::error_code,
    std::shared_ptr<http_transport>)> & f
    )
{
    /**
     * Set if the transport is secure.
     */
    m_secure = m_url.substr(0, 5) == "https";
    
    /**
     * Parse the url.
     */
    parse_url();
    
    /**
     * Set the completion handler.
     */
    m_on_complete = f;
#if (defined USE_OPENSSL && USE_OPENSSL)
    /**
     * Allocate the boost::asio::ssl::context.
     */
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv1_client);
    
    /**
     * Allocate the socket.
     */
    ssl_socket_.reset(
        new boost::asio::ssl::stream<boost::asio::ip::tcp::socket> (
        io_service_, ctx)
    );
    
    if (m_secure)
    {
        ssl_socket_->set_verify_mode(boost::asio::ssl::verify_none);

        ssl_socket_->set_verify_callback(
            [this](bool preverified, boost::asio::ssl::verify_context & ctx)
            {
#if 0
                char subject_name[256];
                X509 * cert = X509_STORE_CTX_get_current_cert(
                    ctx.native_handle()
                );
                X509_NAME_oneline(
                    X509_get_subject_name(cert), subject_name, 256
                );
                std::cout << "Verifying " << subject_name << "\n";
#endif
                return preverified;
            }
        );
    }
#else
    /**
     * Allocate the socket.
     */
    socket_.reset(new boost::asio::ip::tcp::socket(io_service_));
#endif // USE_OPENSSL
    auto self(shared_from_this());
    
    timeout_timer_.expires_from_now(std::chrono::seconds(60));
    timeout_timer_.async_wait(
        strand_.wrap(
            [this, self](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
#if (defined USE_OPENSSL && USE_OPENSSL)
                    if (ssl_socket_)
                    {
                        ssl_socket_->lowest_layer().close();
                    }
#else
                    if (socket_)
                    {
                        socket_->close();
                    }
#endif // USE_OPENSSL
                }
            }
        )
    );
    
    try
    {
        boost::asio::ip::tcp::resolver resolver(io_service_);
        boost::asio::ip::tcp::resolver::query query(
            m_hostname, m_secure ? "443" : "80"
        );
        do_connect(resolver.resolve(query));
    }
    catch (std::exception & e)
    {
        std::cerr <<
            "Http transport resolve failed, what = " << e.what() <<
        std::endl;
    }
}
        
void http_transport::stop()
{
#if (defined USE_OPENSSL && USE_OPENSSL)
    if (ssl_socket_)
    {
        io_service_.post([this]() { ssl_socket_->lowest_layer().close(); });
    }
#else
    if (socket_)
    {
        io_service_.post([this]() { socket_->close(); });
    }
#endif // USE_OPENSSL
}

const bool & http_transport::secure() const
{
    return m_secure;
}

const std::string & http_transport::url() const
{
    return m_url;
}

const std::string & http_transport::hostname() const
{
    return m_hostname;
}

const std::string & http_transport::path() const
{
    return m_path;
}

const std::int32_t & http_transport::status_code() const
{
    return m_status_code;
}

std::map<std::string, std::string> & http_transport::headers()
{
    return m_headers;
}

void http_transport::set_request(const std::string & val)
{
    request_.reset(new boost::asio::streambuf());
    std::ostream request_stream(request_.get());
    request_stream << val;
}

void http_transport::set_request_body(const std::string & val)
{
    m_request_body = val;
    m_method = m_request_body.size() > 0 ? "POST" : "GET";
}

const std::string & http_transport::request_body() const
{
    return m_request_body;
}

const std::string http_transport::response_body() const
{
    return m_response_body.str();
}

void http_transport::do_connect(
    boost::asio::ip::tcp::resolver::iterator endpoint_iterator
    )
{
    using namespace boost;
    
    auto self(shared_from_this());
#if (defined USE_OPENSSL && USE_OPENSSL)
    asio::async_connect(ssl_socket_->lowest_layer(), endpoint_iterator,
#else
    asio::async_connect(*socket_, endpoint_iterator,
#endif // USE_OPENSSL
        [this, self](system::error_code ec, asio::ip::tcp::resolver::iterator)
        {
            if (ec)
            {
                if (m_on_complete)
                {
                    m_on_complete(ec, self);
                }
            }
            else
            {
#if (defined USE_OPENSSL && USE_OPENSSL)
                if (m_secure)
                {
                    ssl_socket_->async_handshake(asio::ssl::stream_base::client,
                        [this, self](boost::system::error_code ec)
                        {
                            if (ec)
                            {
                                if (m_on_complete)
                                {
                                    m_on_complete(ec, self);
                                }
                            }
                            else
                            {
                                timeout_timer_.cancel();
                                
                                if (request_)
                                {
                                    // ....
                                }
                                else
                                {
                                    generate_request();
                                }
                                
                                /**
                                 * Write the http request.
                                 */
                                do_write(*request_);
                            }
                        }
                    );
                }
                else
#endif // USE_OPENSSL
                {
                    timeout_timer_.cancel();
                    
                    if (request_)
                    {
                        // ....
                    }
                    else
                    {
                        generate_request();
                    }
                    
                    /**
                     * Write the http request.
                     */
                    do_write(*request_);
                }
            }
        }
    );
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    set_voip();
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
}

void http_transport::do_write(boost::asio::streambuf & buf)
{
    using namespace boost;
    
    auto self(shared_from_this());
    
    if (m_secure)
    {
#if (defined USE_OPENSSL && USE_OPENSSL)
        asio::async_write(*ssl_socket_, buf,
#else
        asio::async_write(*socket_, buf,
#endif // USE_OPENSSL
            [this, self](system::error_code ec, std::size_t)
            {
                if (ec)
                {
                    if (m_on_complete)
                    {
                        m_on_complete(ec, self);
                    }
                }
                else
                {
                    /**
                     * Read the status line.
                     */
#if (defined USE_OPENSSL && USE_OPENSSL)
                    asio::async_read_until(*ssl_socket_, *response_.get(), "\r\n",
#else
                    asio::async_read_until(*socket_, *response_.get(), "\r\n",
#endif // USE_OPENSSL
                        [this, self](system::error_code ec, std::size_t)
                        {
                            if (ec)
                            {
                                if (m_on_complete)
                                {
                                    m_on_complete(ec, self);
                                }
                            }
                            else
                            {
                                handle_status_line();
                            }
                        }
                    );
                }
            }
        );
    }
    else
    {
#if (defined USE_OPENSSL && USE_OPENSSL)
        asio::async_write(ssl_socket_->next_layer(), buf,
#else
        asio::async_write(*socket_, buf,
#endif // USE_OPENSSL
            [this, self](system::error_code ec, std::size_t)
            {
                if (ec)
                {
                    if (m_on_complete)
                    {
                        m_on_complete(ec, self);
                    }
                }
                else
                {
                    /**
                     * Read the status line.
                     */
                    asio::async_read_until(
#if (defined USE_OPENSSL && USE_OPENSSL)
                        ssl_socket_->next_layer(), *response_.get(), "\r\n",
#else
                        *socket_, *response_.get(), "\r\n",
#endif // USE_OPENSSL
                        [this, self](system::error_code ec, std::size_t)
                        {
                            if (ec)
                            {
                                if (m_on_complete)
                                {
                                    m_on_complete(ec, self);
                                }
                            }
                            else
                            {
                                handle_status_line();
                            }
                        }
                    );
                }
            }
        );
    }
}

void http_transport::handle_status_line()
{
    std::istream response_stream(response_.get());
    std::string http_version;
    response_stream >> http_version;
    response_stream >> m_status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    
    auto self(shared_from_this());
    
    if (!response_stream || http_version.substr(0, 5) != "HTTP/")
    {
        boost::system::error_code ec(-1, boost::system::system_category());
        
        if (m_on_complete)
        {
            m_on_complete(ec, self);
        }
    }
    else
    {
#if (defined USE_OPENSSL && USE_OPENSSL)
        if (m_secure)
        {
            boost::asio::async_read_until(*ssl_socket_, *response_.get(), "\r\n\r\n",
                [this, self](boost::system::error_code ec, std::size_t)
                {
                    if (ec)
                    {
                        if (m_on_complete)
                        {
                            m_on_complete(ec, self);
                        }
                    }
                    else
                    {
                        handle_headers();
                    }
                }
            );
        }
        else
#endif
        {
            boost::asio::async_read_until(
#if (defined USE_OPENSSL && USE_OPENSSL)
                ssl_socket_->next_layer(), *response_.get(), "\r\n\r\n",
#else
                *socket_, *response_.get(), "\r\n\r\n",
#endif // USE_OPENSSL
                [this, self](boost::system::error_code ec, std::size_t)
                {
                    if (ec)
                    {
                        if (m_on_complete)
                        {
                            m_on_complete(ec, self);
                        }
                    }
                    else
                    {
                        handle_headers();
                    }
                }
            );
        }
    }
}

void http_transport::handle_headers()
{
    std::istream response_stream(response_.get());
    std::string header;
    
    while (std::getline(response_stream, header) && header != "\r")
    {
        std::string t;
        
        std::string::size_type i;

        while ((i = header.find("\r")) != std::string::npos)
        {
            t = header.substr(0, i);
            
            header.erase(0, i + 1);
            
            if (t == "")
            {
                break;
            }
            
            i = t.find(": ");
            
            if (i == std::string::npos)
            {
                // ...
            }
            else
            {
                /**
                 * Find the key.
                 */
                std::string key = t.substr(0, i);
                
                /**
                 * Find the value.
                 */
                std::string value = t.substr(i + 2);
                
                /**
                 * Trim whitespace.
                 */
                boost::algorithm::trim(key);
                
                /**
                 * Trim whitespace.
                 */
                boost::algorithm::trim(value);
                    
                /**
                 * Insert the header field.
                 */
                m_headers.insert(std::make_pair(key, value));
            }
        }
    }
#if 0
    for (auto & i : m_headers)
    {
        std::cout << i.first << ":" << i.second << std::endl;
    }
#endif
    if (response_->size() > 0)
    {
        m_response_body << response_.get();
    }

    handle_body();
}

void http_transport::handle_body()
{
    using namespace boost;
    
    auto self(shared_from_this());
#if (defined USE_OPENSSL && USE_OPENSSL)
    if (m_secure)
    {
        asio::async_read(*ssl_socket_, *response_.get(), asio::transfer_at_least(1),
            [this, self](system::error_code ec, std::size_t)
            {
                if (
                    ec == boost::asio::error::eof ||
                    ec.message() == "short read"
                    )
                {
                    if (m_on_complete)
                    {
                        m_on_complete(boost::system::error_code(), self);
                    }
                }
                else if (ec)
                {
                    if (m_on_complete)
                    {
                        m_on_complete(ec, self);
                    }
                }
                else
                {
                    m_response_body << response_.get();

                    handle_body();
                }
            }
        );
    }
    else
#endif // USE_OPENSSL
    {
#if (defined USE_OPENSSL && USE_OPENSSL)
        asio::async_read(ssl_socket_->next_layer(), *response_.get(),
#else
        asio::async_read(*socket_, *response_.get(),
#endif // USE_OPENSSL
            asio::transfer_at_least(1),
            [this, self](system::error_code ec, std::size_t)
            {
                if (ec == boost::asio::error::eof)
                {
                    if (m_on_complete)
                    {
                        m_on_complete(boost::system::error_code(), self);
                    }
                }
                else if (ec)
                {
                    if (m_on_complete)
                    {
                        m_on_complete(ec, self);
                    }
                }
                else
                {
                    m_response_body << response_.get();
                    
                    handle_body();
                }
            }
        );
    }
}

void http_transport::parse_url()
{
    std::string tmp_url = m_url;
    
    /**
     * Remove all occurances of http://.
     */
    boost::algorithm::erase_all(tmp_url, "http://");

    /**
     * Remove all occurances of https://.
     */
    boost::algorithm::erase_all(tmp_url, "https://");
    
    auto i = tmp_url.find_first_of("/");
    
    /**
     * Get the hostname.
     */
    m_hostname = tmp_url.substr(0, i);

    /**
     * Remove all occurances of the domain.
     */
    boost::algorithm::erase_all(tmp_url, m_hostname);
    
    i = tmp_url.find_first_of("?");
    
    std::string path = tmp_url.substr(0, i);
    
    std::string url_params = path;
    
    /**
     * Remove all occurances of the domain.
     */
    boost::algorithm::erase_all(tmp_url, url_params);
    
    url_params = tmp_url;
    
    /**
     * Get the path.
     */
    m_path = path + urlencode(url_params);
#if 1
    std::cout << "m_hostname = " << m_hostname << std::endl;
    std::cout << "m_path  = " << m_path << std::endl;
#endif
}

void http_transport::generate_request()
{
    request_.reset(new boost::asio::streambuf());
    
    std::ostream request_stream(request_.get());
    request_stream << m_method << " "  << m_path << " HTTP/1.0\r\n";
    request_stream << "Host: " << m_hostname << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n";
    request_stream << "Content-Length: " << m_request_body.size() << "\r\n";
    
    for (auto & i : m_headers)
    {
        request_stream << i.first << ": " << i.second << "\r\n";
    }
    
    request_stream << "\r\n";
    request_stream << m_request_body;
}

void http_transport::set_voip()
{
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    /**
     * To configure a socket for VoIP usage, the only thing you have to do
     * beyond the normal configuration is add a special key that tags the 
     * interface as being associated with a VoIP service.
     */    
    CFStreamCreatePairWithSocket(
#if (defined USE_OPENSSL && USE_OPENSSL)
        0, (CFSocketNativeHandle)ssl_socket_->lowest_layer().native(),
#else
        0, (CFSocketNativeHandle)socket_->native(),
#endif // USE_OPENSSL
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

std::string http_transport::char2hex(char dec)
{
    std::string ret;
    
    char dig1 = (dec & 0xF0) >> 4;
    char dig2 = (dec & 0x0F);
    
    if (0 <= dig1 && dig1 <= 9)
    {
        dig1 += 48; //0,48inascii
    }
    
    if (10 <= dig1 && dig1 <= 15)
    {
        dig1 += 97 - 10; //a,97inascii
    }
    
    if (0 <= dig2 && dig2 <= 9)
    {
        dig2 += 48;
    }
    
    if (10 <= dig2 && dig2 <=15)
    {
        dig2 += 97 - 10;
    }

    ret.append(&dig1, 1);
    ret.append(&dig2, 1);
    
    return ret;
}

std::string http_transport::urlencode(const std::string & c)
{
    std::string ret;

    for (unsigned i = 0; i < c.length(); i++)
    {
        if ((48 <= c[i] && c[i] <= 57) || // 0-9
             (65 <= c[i] && c[i] <= 90) || // abc...xyz
             (97 <= c[i] && c[i] <= 122) || // ABC...XYZ
             (c[i]=='~' || c[i]=='!' || c[i]=='*' || c[i]=='(' || c[i]==')' ||
             c[i]=='\'' || c[i]=='?' || c[i]=='&' || c[i]=='=')
            )
        {
            ret.append(&c[i], 1);
        }
        else if (c[i] == ' ')
        {
            ret.append("+", 1);
        }
        else
        {
            ret.append("%");
            ret.append(char2hex(c[i]));//converts char 255 to string "ff"
        }
    }
    return ret;
}

int http_transport::run_test()
{
    boost::asio::io_service ios;
    
    std::shared_ptr<http_transport> t =
        std::make_shared<http_transport>(ios,
        "https://www.grapevine.am/foo?test1=1&test2=foo bar")
    ;
    
    t->set_request_body("Hello World!");
    
    t->headers()["Content-Type"] = "text/plain";
    
    t->start(
        [](boost::system::error_code ec, std::shared_ptr<http_transport> t)
        {
            if (ec)
            {
                std::cerr <<
                    "http_transport request failed, message = " <<
                    ec.message() <<
                std::endl;
            }
            else
            {
                if (t->status_code() == 200)
                {
                    std::cout <<
                        "http_transport success, body = " <<
                        t->response_body() <<
                    std::endl;
                }
                else
                {
                    std::cerr <<
                        "http_transport request failed, status code = " <<
                        t->status_code() <<
                    std::endl;
                }
            }
        }
    );
    
    ios.run();

    return 0;
}

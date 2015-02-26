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

#include <thread>

#include <coin/gateway.hpp>
#include <coin/logger.hpp>
#include <coin/nat_pmp_client.hpp>

using namespace coin;

nat_pmp_client::nat_pmp_client(boost::asio::io_service & ios)
    : m_public_ip_address(boost::asio::ip::address())
    , io_service_(ios)
    , strand_(ios)
    , timeout_timer_(ios)
    , retry_timer_(ios)
    , refresh_timer_(ios)
{
    // ...
}
            
void nat_pmp_client::start()
{
    if (socket_)
    {
        throw std::runtime_error("socket is in use");
    }
    else
    {
        /**
         * Allocate the socket.
         */
        socket_.reset(new boost::asio::ip::udp::socket(io_service_));

        boost::system::error_code ec;
        
        /**
         * Obtain the default gateway.
         */
        m_gateway_address = gateway::default_route(io_service_, ec);
        
        if (ec)
        {
            throw std::runtime_error(ec.message()); 
        }
        else
        {
			log_info(
                "NAT-PMP client started, default route to gateway is " <<
                m_gateway_address << "."
 			);   
        }
        
        endpoint_ = boost::asio::ip::udp::endpoint(
            m_gateway_address, nat_pmp::port
        );
        
        /**
         * Connect the socket so that we receive ICMP errors.
         */
        socket_->async_connect(
            endpoint_, strand_.wrap(std::bind(
                &nat_pmp_client::handle_connect, this, std::placeholders::_1))
        );

    	timeout_timer_.expires_from_now(boost::posix_time::seconds(10));
    	timeout_timer_.async_wait(std::bind(
			&nat_pmp_client::handle_timeout, this, std::placeholders::_1)
    	);
    }
}
            
void nat_pmp_client::stop(const bool & unmap)
{
    if (socket_ && socket_->is_open())
    {
	    /**
	     * Clear the request queue.
	     */
	    request_queue_.clear();
        
		/**
		 * Cancel the timeout timer.
		 */
		timeout_timer_.cancel();
		
		/**
		 * Cancel the refresh timer.
		 */
		refresh_timer_.cancel();

		/**
		 * Cancel the retry timer.
		 */
		retry_timer_.cancel();

		if (unmap)
		{
            auto it = mappings_.begin();
     
			for (; it != mappings_.end(); ++it)
			{
        		nat_pmp::mapping_request_t & req = (*it).first;
    	
    			std::uint16_t private_port = ntohs(*((std::uint16_t *)
    				(req.buffer + 4))
    			);
    			std::uint16_t public_port = ntohs(*((std::uint16_t *)
    				(req.buffer + 6))
    			);

				log_debug(
                    "NAT-PMP client is removing mapping: " <<
					(unsigned int)(*it).first.buffer[1] << ":" <<  
					private_port << ":" << public_port
				);
            
				/**
				 * Send the mapping request with a lifetime of 0.
				 */
				send_mapping_request(
					(*it).first.buffer[1], private_port, public_port, 0
				);
			}
		}

		/**
		 * Close the socket.
		 */
		socket_->close();
	    
	    /**
	     * Clear the mappings.
	     */
	    mappings_.clear();
    }
    else
    {
        // ...
    }
}

void nat_pmp_client::add_mapping(
    const nat_pmp::protocol_t & protocol, const std::uint16_t & port
    )
{
    send_mapping_request(protocol, port, port, 3610);
}

void nat_pmp_client::remove_mapping(
    const nat_pmp::protocol_t & protocol, const std::uint16_t & port
    )
{
    send_mapping_request(protocol, port, port, 0);
}

void nat_pmp_client::handle_timeout(const boost::system::error_code & ec)
{
	if (ec)
	{
		// ...
	}
	else
	{
		log_debug("NAT-PMP client connection timeout, stopping.");
		
		stop(false);
	}	
}

void nat_pmp_client::send_mapping_request(
    std::uint16_t protocol, std::uint16_t private_port, 
    std::uint16_t public_port, std::uint32_t lifetime
    )
{
    if (socket_ && socket_->is_open())
    {
        log_debug(
            "NAT-PMP client is queueing mapping request for protocol = " <<
            protocol << ", private_port = " << private_port <<
            ", public_port = " << public_port << ", lifetime = " << lifetime
            << "."
       	);
        
        nat_pmp::mapping_request_t r;
        
        r.buffer[0] = 0;
    	r.buffer[1] = protocol;
    	r.buffer[2] = 0;
    	r.buffer[3] = 0;
    	
        *((std::uint16_t *)(r.buffer + 4)) = htons(private_port);
    	*((std::uint16_t *)(r.buffer + 6)) = htons(public_port);
    	*((std::uint32_t *)(r.buffer + 8)) = htonl(lifetime);
    
        r.length = 12;
        r.retry_count = 0;
        
        auto it = mappings_.begin();
     	
     	bool found = false;
     	
        for (; it != mappings_.end(); ++it)
        {
        	nat_pmp::mapping_request_t & req = (*it).first;
    		
    		if (
    			ntohs(private_port) == *((std::uint16_t *)(req.buffer + 4)) &&
    			ntohs(public_port) == *((std::uint16_t *)(req.buffer + 6)) &&
    			protocol == req.buffer[1]
    			)
    		{
		        found = true;
		        
		        break;
    		}
        }
      	
      	if (found == false)
      	{
	        nat_pmp::mapping_response_t res;
	        
	        mappings_.push_back(std::make_pair(r, res));
      	}
      	
        /**
         * If we have not yet discovered our public ip address queue the
         * request.
         */
        if (m_public_ip_address == boost::asio::ip::address())
        {
        	request_queue_.push_back(r);
        }
        else
        {
        	send_request(r);
        }
    }
}

void nat_pmp_client::send_public_address_request()
{
	log_debug(
        "NAT-PMP client sending public address request to gateway device."
    );
    
    public_ip_request_.buffer[0] = 0;
    public_ip_request_.buffer[1] = 0;
    public_ip_request_.length = 2;
    public_ip_request_.retry_count = 1;
    
    retry_timer_.expires_from_now(boost::posix_time::milliseconds(
        250 * public_ip_request_.retry_count)
    );
    retry_timer_.async_wait(std::bind(
        &nat_pmp_client::retransmit_public_adddress_request, this,
        std::placeholders::_1)
    );
    
    send_request(public_ip_request_);
}

void nat_pmp_client::retransmit_public_adddress_request(
    const boost::system::error_code & ec
    )
{
    if (ec)
    {
		// ...
    }
    else if (public_ip_request_.retry_count >= 9)
    {
		log_debug(
            "NAT-PMP client, no gateway device found, retries = " <<
			public_ip_request_.retry_count << ", calling stop."
        );
        
        stop(false);   
    }
    else if (m_public_ip_address == boost::asio::ip::address_v4::any())
    {
        if (socket_->is_open())
        {
            /**
             * Increment retry count.
             */
            ++public_ip_request_.retry_count;
            
            /**
             * Retransmit the request.
             */
            send_request(public_ip_request_);
            
            log_debug(
                "NAT-PMP client is retransmitting public address request, "
                "retry = " << static_cast<std::uint32_t> (
                public_ip_request_.retry_count) << "."
            );
            
            retry_timer_.expires_from_now(boost::posix_time::milliseconds(
                250 * public_ip_request_.retry_count)
            );
            
            retry_timer_.async_wait(std::bind(
                &nat_pmp_client::retransmit_public_adddress_request, this,
                std::placeholders::_1)
            );
        }
    }
}

void nat_pmp_client::send_request(nat_pmp::mapping_request_t & req)
{
    if (socket_ && socket_->is_open())
    {
        send(reinterpret_cast<const char *>(req.buffer), req.length);
    }
    else
    {
        log_debug(
            "NAT-PMP cannot send NAT-PMP request while not started"
        );
    }
}

void nat_pmp_client::send_queued_requests()
{
    if (socket_ && socket_->is_open())
    {        
        if (request_queue_.size() > 0)
        {
            log_debug(
                "NAT-PMP client is sending queued NAT-PMP requests, " <<
                request_queue_.size() << " remaining."
            );
            
            nat_pmp::mapping_request_t & r = request_queue_.front();
            
            send_request(r);
        }
    }
}

void nat_pmp_client::send(const char * buf, std::size_t len)
{
    socket_->async_send(
        boost::asio::buffer(buf, len), strand_.wrap(std::bind(
            &nat_pmp_client::handle_send, this, 
            std::placeholders::_1, std::placeholders::_2))
    );
}

void nat_pmp_client::handle_send(
    const boost::system::error_code & ec, std::size_t bytes
    )
{
    if (ec == boost::asio::error::operation_aborted)
    {
        // ...
    }
    else if (ec)
    {
		log_debug(
            "NAT-PMP client send failed, error = " <<
            nat_pmp::opcode_to_string(nat_pmp::error_code_send) <<
            " : " << ec.message() << "."
        );
    }
    else
    {
		// ...
    }
}

void nat_pmp_client::handle_connect(const boost::system::error_code & ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        // ...
    }
    else if (ec)
    {
		log_debug(
            "NAT-PMP client failed to discover compatible gateway, "
            "error = " << ec.message() << ", calling stop."
        );
        
        /**
         * Call stop.
         */
        stop(false);
    }
    else
    {
		log_debug(
			"NAT-PMP client connected to gateway, sending public address "
            "request."
		);
	
		/**
		 * Cancel the timeout timer.
		 */
		timeout_timer_.cancel();
		
        /**
         * Send a request for the NAT-PMP gateway's public ip address.
         */
        send_public_address_request();

        socket_->async_receive_from(
            boost::asio::buffer(data_, receive_buffer_length), endpoint_,
            strand_.wrap(std::bind(&nat_pmp_client::handle_receive_from, this,
            std::placeholders::_1, std::placeholders::_2))
        );
        
        /**
         * Start the mapping refresh timer.
         */
    	refresh_timer_.expires_from_now(boost::posix_time::minutes(20));
    	refresh_timer_.async_wait(
    		strand_.wrap(std::bind(&nat_pmp_client::tick, this,
            std::placeholders::_1))
   		);
    }  
}

void nat_pmp_client::handle_receive_from(
    const boost::system::error_code & ec, std::size_t bytes
    )
{
    if (ec == boost::asio::error::operation_aborted)
    {
        // ...
    }
    else if (ec)
    {
        if (ec == boost::asio::error::connection_refused)
        {
            log_debug("NAT-PMP client connection to gateway refused, stopping.");
            
            stop(false);
        }
        else
        {        
            log_debug(
                "NAT-PMP client receive failed, error = " <<
                nat_pmp::opcode_to_string(nat_pmp::error_code_receive_from) <<
                " : " << ec.message() << "."
            );
            
            stop();
        }
    }
    else
    {
        /**
         * Handle the response.
         */
        handle_response(data_, bytes);
        
        socket_->async_receive_from(
            boost::asio::buffer(data_, receive_buffer_length), endpoint_,
            strand_.wrap(std::bind(&nat_pmp_client::handle_receive_from, this,
            std::placeholders::_1, std::placeholders::_2))
        );
    }
}

void nat_pmp_client::handle_response(const char * buf, std::size_t len)
{
    unsigned int opcode = 0;
    
    nat_pmp::mapping_response_t response;

    if (endpoint_.address() == m_gateway_address)
    {
    	response.result_code = ntohs(*((std::uint16_t *)(buf + 2)));
        
    	response.epoch = ntohl(*((std::uint32_t *)(buf + 4)));
        
    	if (buf[0] != 0)
        {
    		opcode = nat_pmp::result_opcode_unsupported_version;
        }
    	else if (
    	   static_cast<std::uint8_t> (buf[1]) < 128 || 
    	   static_cast<std::uint8_t> (buf[1]) > 130
    	   )
        {
    		opcode = nat_pmp::result_opcode_unsupported_opcode;
        }
    	else if (response.result_code != 0)
        {
    		switch (response.result_code)
            {
                case 1:
                {
                    opcode = nat_pmp::result_opcode_unsupported_version;
    			}
                break;
                case 2:
                {
                    opcode = nat_pmp::result_opcode_not_authorized_refused;
    			}
                break;
                case 3:
                {
                    opcode = nat_pmp::result_opcode_network_failure;
    			}
                break;
                case 4:
                {
                    opcode = nat_pmp::result_opcode_out_of_resources;
    			}
                break;
                case 5:
                {
                    opcode = nat_pmp::result_opcode_unsupported_opcode;
    			}
                break;
                default:
                {
                    opcode = nat_pmp::result_opcode_undefined;
                }
                break;
            }
    	}
        else
        {
    		response.type = static_cast<std::uint8_t>(buf[1]) & 0x7f;
            
    		if (static_cast<std::uint8_t> (buf[1]) == 128)
            {
                std::uint32_t ip = ntohl(*((std::uint32_t *)(buf + 8)));
    
                response.public_address = boost::asio::ip::address_v4(ip);
                
                m_public_ip_address = response.public_address;
                
                retry_timer_.cancel();
                
                log_debug( 
                    "Obtained public ip address " << response.public_address << 
                    " from NAT-PMP gateway, sending " <<
                    request_queue_.size() << " queued requests."
                );
                
                /**
                 * A NAT-PMP compatible gateway has been found, send queued 
                 * requests.
                 */
                send_queued_requests();
    		}
            else
            {
    			response.private_port = ntohs(*((std::uint16_t *)(buf + 8)));
                
    			response.public_port = ntohs(*((std::uint16_t *)(buf + 10)));
                
    			response.lifetime = ntohl(*((std::uint32_t *)(buf + 12)));

               	log_debug(
             		"NAT-PMP mapping success, port =  " <<
             		response.public_port << "."
             	);

                if (request_queue_.size() > 0)
                {
                	request_queue_.pop_front();
                }
                
                /**
                 * Send queued requests.
                 */
                send_queued_requests();
    		}
            
    		opcode = 0;
    	}
    }
    else
    {
        opcode = nat_pmp::error_code_source_conflict;
    }
    
    if (opcode)
    {
		log_debug(
			"NAT-PMP client got response opcode =  " <<
			nat_pmp::opcode_to_string(opcode) << "."
        );
    }
}

void nat_pmp_client::tick(const boost::system::error_code & ec)
{
	if (ec)
	{
		// ...
	}
	else
	{
        for (auto & i : mappings_)
        {
        	nat_pmp::mapping_request_t & req = i.first;

    		std::uint16_t private_port = *((std::uint16_t *)
    			(req.buffer + 4)
    		);
    		std::uint16_t public_port = *((std::uint16_t *)
    			(req.buffer + 6)
    		);
    		std::uint32_t lifetime = *((std::uint32_t *)(req.buffer + 8));
    		
			log_debug("NAT-PMP client is refreshing NAT-PMP mapping: " <<
                (unsigned int)i.first.buffer[1] << ":" <<
                ntohs(private_port) << ":" << ntohs(public_port) <<
                ", lifetime = " << ntohl(lifetime)
            );
            
            /**
             * Send the mapping request.
             */
            send_mapping_request(
                i.first.buffer[1], ntohs(private_port),
                ntohs(public_port), ntohl(lifetime)
            );
        }
	        
        /**
         * Start the mapping refresh timer.
         */
    	refresh_timer_.expires_from_now(boost::posix_time::minutes(20));
    	refresh_timer_.async_wait(
    		std::bind(&nat_pmp_client::tick, this, std::placeholders::_1)
   		);
	}
}

int nat_pmp_client::run_test()
{
    static boost::asio::io_service g_ios;
	
	nat_pmp_client c(g_ios);

	c.start();
	
    std::thread t([]()
    {
        g_ios.run();
    });

	c.add_mapping(nat_pmp::protocol_tcp, 32768);
	c.add_mapping(nat_pmp::protocol_udp, 32768);

	std::cin.get();
	
	c.stop();
	
	t.join();
	
	return 0;
}

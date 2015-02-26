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

#ifndef COIN_RPC_JSON_PARSER_HPP
#define COIN_RPC_JSON_PARSER_HPP

#include <string>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/detail/json_parser_read.hpp>
#include <boost/property_tree/detail/json_parser_write.hpp>
#include <boost/property_tree/detail/json_parser_error.hpp>

namespace coin {

    /** 
     * Implements a JSON-RPC parser.
     */
    class rpc_json_parser
    {
        public:
        
            template <typename T>
            struct translator
            {
                typedef T internal_type;
                typedef T external_type;

                boost::optional<T> get_value(const T & v)
                {
                    return v.substr(1, v.size() - 2) ;
                }
                
                boost::optional<T> put_value(const T & v)
                {
                    return '"' + v + '"';
                }
            };

            template<class Ptree>
            static void write_json(
                std::basic_ostream<typename Ptree::key_type::value_type> &
                stream, const Ptree & pt, bool pretty = true
                )
            {
                write_json_internal(
                    stream, pt, std::string(), pretty
                );
            }
    
        private:
        
            // ...
        
        protected:
        
            template<class Ch>
            static std::basic_string<Ch> create_escapes(
                const std::basic_string<Ch> & s
                )
            {
                std::basic_string<Ch> result;
                
                auto b = s.begin();
                auto e = s.end();
                
                while (b != e)
                {
                    if (
                        *b == 0x20 || *b == 0x21 ||
                        (*b >= 0x23 && *b <= 0x2E) ||
                        (*b >= 0x30 && *b <= 0x5B) ||
                        (*b >= 0x5D && *b <= 0xFF)
                        )
                    {
                        result += *b;
                    }
                    else if (*b == Ch('\b'))
                    {
                        result += Ch('\\'), result += Ch('b');
                    }
                    else if (*b == Ch('\f'))
                    {
                        result += Ch('\\'), result += Ch('f');
                    }
                    else if (*b == Ch('\n'))
                    {
                        result += Ch('\\'), result += Ch('n');
                    }
                    else if (*b == Ch('\r'))
                    {
                        result += Ch('\\'), result += Ch('r');
                    }
                    else if (*b == Ch('/'))
                    {
                        result += Ch('\\'), result += Ch('/');
                    }
                    else if (*b == Ch('"'))
                    {
                        result+= Ch('"');
                    }
                    else if (*b == Ch('\\'))
                    {
                        result += Ch('\\'), result += Ch('\\');
                    }
                    else
                    {
                        const char * hexdigits = "0123456789ABCDEF";
                        
                        typedef typename boost::make_unsigned<Ch>::type UCh;
                        
                        unsigned long u =
                            (std::min)(static_cast<unsigned long>(
                            static_cast<UCh>(*b)), 0xFFFFul
                        );
                        
                        auto d1 = u / 4096; u -= d1 * 4096;
                        auto d2 = u / 256; u -= d2 * 256;
                        auto d3 = u / 16; u -= d3 * 16;
                        auto d4 = u;
                        
                        result += Ch('\\'); result += Ch('u');
                        result += Ch(hexdigits[d1]); result += Ch(hexdigits[d2]);
                        result += Ch(hexdigits[d3]); result += Ch(hexdigits[d4]);
                    }
                    ++b;
                }
                return result;
            }

            template<class Ptree>
            static void write_json_helper(
                std::basic_ostream<typename Ptree::key_type::value_type> &
                stream, const Ptree & pt, int indent, bool pretty
                )
            {
                typedef typename Ptree::key_type::value_type Ch;
                typedef typename std::basic_string<Ch> Str;

                if (pt.empty())
                {
                    auto data = create_escapes(pt.template get_value<Str>());

                    stream << data;

                }
                else if (pt.count(Str()) == pt.size())
                {
                    stream << Ch('[');
                    
                    if (pretty)
                    {
                        stream << Ch('\n');
                    }
                    
                    auto it = pt.begin();
                    
                    for (; it != pt.end(); ++it)
                    {
                        if (pretty)
                        {
                            stream << Str(4 * (indent + 1), Ch(' '));
                        }
                        
                        write_json_helper(
                            stream, it->second, indent + 1, pretty
                        );
                        
                        if (boost::next(it) != pt.end())
                        {
                            stream << Ch(',');
                        }
                        
                        if (pretty)
                        {
                            stream << Ch('\n');
                        }
                    }
                    stream << Str(4 * indent, Ch(' ')) << Ch(']');

                }
                else
                {
                    stream << Ch('{');
                    
                    if (pretty)
                    {
                        stream << Ch('\n');
                    }
                    
                    typename Ptree::const_iterator it = pt.begin();
                    
                    for (; it != pt.end(); ++it)
                    {
                        if (pretty)
                        {
                            stream << Str(4 * (indent + 1), Ch(' '));
                        }
                        
                        stream << Ch('"') <<
                            create_escapes(it->first) << Ch('"') << Ch(':')
                        ;
                        
                        if (pretty)
                        {
                            if (it->second.empty())
                            {
                                stream << Ch(' ');
                            }
                            else
                            {
                                stream <<
                                    Ch('\n') << Str(4 * (indent + 1), Ch(' '))
                                ;
                            }
                        }
                        
                        write_json_helper(
                            stream, it->second, indent + 1, pretty
                        );
                        
                        if (boost::next(it) != pt.end())
                        {
                            stream << Ch(',');
                        }
                        
                        if (pretty)
                        {
                            stream << Ch('\n');
                        }
                    }
                    
                    if (pretty) stream << Str(4 * indent, Ch(' '));
                    {
                        stream << Ch('}');
                    }
                }

            }

            template<class Ptree>
            static bool verify_json(const Ptree & pt, int depth)
            {
                typedef typename Ptree::key_type::value_type Ch;
                typedef typename std::basic_string<Ch> Str;

                if (depth == 0 && !pt.template get_value<Str>().empty())
                {
                    return false;
                }
                
                if (!pt.template get_value<Str>().empty() && !pt.empty())
                {
                    return false;
                }
                
                typename Ptree::const_iterator it = pt.begin();
                
                for (; it != pt.end(); ++it)
                {
                    if (!verify_json(it->second, depth + 1))
                    {
                        return false;
                    }
                }
                
                return true;

            }

            template<class Ptree>
            static void write_json_internal(
                std::basic_ostream<typename Ptree::key_type::value_type> & stream,
                const Ptree & pt, const std::string & filename, bool pretty
                )
            {
                if (verify_json(pt, 0) == false)
                {
                    BOOST_PROPERTY_TREE_THROW(
                        boost::property_tree::json_parser::json_parser_error(
                        "ptree contains data that cannot be represented "
                        "in JSON format", filename, 0)
                    );
                }
                
                write_json_helper(stream, pt, 0, pretty);
                stream << std::endl;
                
                if (stream.good() == false)
                {
                    BOOST_PROPERTY_TREE_THROW(
                        boost::property_tree::json_parser::json_parser_error(
                        "write error", filename, 0)
                    );
                }
            }
    };
    
} // namespace coin

#endif // COIN_RPC_JSON_PARSER_HPP

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

#ifndef COIN_COIN_CONTROL_HPP
#define COIN_COIN_CONTROL_HPP

#include <cstdint>
#include <set>

#include <coin/destination.hpp>
#include <coin/point_out.hpp>

namespace coin {

    /**
     * Implements coin control features.
     */
    class coin_control
    {
        public:
        
            /**
             * Constructor
             */
            coin_control()
                : m_destination_change(destination::none())
            {
                // ...
            }
        
            /**
             * Sets null.
             */
            void set_null()
            {
                m_destination_change = destination::none();
                
                m_selected.clear();
            }
        
            /**
             * If true it has selected.
             */
            bool has_selected() const
            {
                return m_selected.size() > 0;
            }
        
            /**
             * Checks if the point_out is selected.
             * @param h The sha256.
             * @param n The n.
             */
            bool is_selected(const sha256 & h, const std::uint32_t & n) const
            {
                return m_selected.count(point_out(h, n)) > 0;
            }
        
            /**
             * Selects
             * @param output The point_out.
             */
            void select(point_out & output)
            {
                m_selected.insert(output);
            }
        
            /**
             * Unselects
             * @param output The point_out.
             */
            void unselect(point_out & output)
            {
                m_selected.erase(output);
            }
        
            /**
             * Unselects all.
             */
            void unselect_all()
            {
                m_selected.clear();
            }

            /**
             * Gets the selected list.
             * out_points The point_out's.
             */
            void list_selected(std::vector<point_out> & out_points)
            {
                out_points.assign(m_selected.begin(), m_selected.end());
            }
        
            /**
             * The destination change.
             */
            const destination::tx_t & destination_change() const
            {
                return m_destination_change;
            }
    
        private:
        
            /**
             * The destination change.
             */
            destination::tx_t m_destination_change;
        
            /**
             * The selected.
             */
            std::set<point_out> m_selected;
        
        protected:
    
            // ..
    };
    
} // namespace coin

#endif // COIN_COIN_CONTROL_HPP

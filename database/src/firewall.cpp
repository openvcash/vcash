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

#if (defined _MSC_VER)
#include <comdef.h>
#include <netfw.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#endif // _MSC_VER

#include <database/firewall.hpp>
#include <database/logger.hpp>

using namespace database;

#if (defined _MSC_VER)
class win_impl : public firewall::impl
{
    public:
    
        win_impl()
            : mgr_(0)
            , policy_(0)
            , profile_(0)
        {
            // ...
        }
    
        virtual bool start()
        {
            if (mgr_)
            {
                // ...
            }
            else
            {
                HRESULT hr = CoCreateInstance(
                    __uuidof(NetFwMgr),0, CLSCTX_INPROC_SERVER, 
                    __uuidof(INetFwMgr), reinterpret_cast<void **>(&mgr_)
                );
              
                if (SUCCEEDED(hr) && mgr_)
                {
                    hr = mgr_->get_LocalPolicy(&policy_);
                }

                if (SUCCEEDED(hr) && policy_)
                {
                    hr = policy_->get_CurrentProfile(&profile_);
                }
                
                return SUCCEEDED(hr) && profile_;
            }
            
            return false;
        }
    
        virtual bool stop()
        {
            if (profile_)
            {
                profile_->Release(), profile_ = 0;
            }
            
            if (policy_)
            {
                policy_->Release(), policy_ = 0;
            }
            
            if (mgr_)
            {
                mgr_->Release(), mgr_ = 0;
            }
            
            return true;
        }
    
        virtual bool is_enabled()
        {
            VARIANT_BOOL ret = VARIANT_FALSE;
            
            if (profile_)
            {
                profile_->get_FirewallEnabled(&ret);
            }

            return ret != VARIANT_FALSE;
        }
    
        bool is_authorized(const char * path, bool * known)
        {
            VARIANT_BOOL ret = VARIANT_FALSE;
            
            if (known) 
            {
                *known = false;
            }
            
            if (profile_)
            {
                _bstr_t bpath = path;

                INetFwAuthorizedApplications * apps = 0;
                
                HRESULT hr = profile_->get_AuthorizedApplications(&apps);
                
                if (SUCCEEDED(hr) && apps != 0)
                {
                    INetFwAuthorizedApplication * app = 0;
                    
                    hr = apps->Item(bpath, &app);
                    
                    if (SUCCEEDED(hr) && app != 0)
                    {
                        hr = app->get_Enabled(&ret);
                        
                        app->Release();
                        
                        if (known)
                        {
                            *known = true;
                        }
                    }
                    else if (hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
                    {
                        // unexpected error
                    }
                    
                    apps->Release();
                }
            }
            
            return ret != VARIANT_FALSE;
        }
    
        bool add(
            const char * path, const char * name, const bool & authorized
            )
        {
            INetFwAuthorizedApplications * apps = 0;
            
            HRESULT hr = profile_->get_AuthorizedApplications(&apps);
            
            if (SUCCEEDED(hr) && apps != 0)
            {
                INetFwAuthorizedApplication * app = 0;
                
                hr = CoCreateInstance(
                    __uuidof(NetFwAuthorizedApplication), 0,
                    CLSCTX_INPROC_SERVER,
                    __uuidof(INetFwAuthorizedApplication),
                    reinterpret_cast<void **>(&app)
                );
         
                if (SUCCEEDED(hr) && app != 0)
                {
                    hr = app->put_ProcessImageFileName(_bstr_t(path));
                    
                    if (SUCCEEDED(hr))
                    {
                        hr = app->put_Name(_bstr_t(name));
                    }
                    else
                    {
                        log_error(
                            "Firewall put_Name failed, result = " << hr << "."
                        );
                    }

                    if (SUCCEEDED(hr))
                    {
						hr = app->put_Scope(NET_FW_SCOPE_ALL);
					}
					else
					{
                        log_error(
                            "Firewall put_Scope failed, result = " << hr << "."
                        );
					}
                    
                    if (SUCCEEDED(hr))
                    {
                        hr = app->put_Enabled(
                            authorized ? VARIANT_TRUE : VARIANT_FALSE
                        );
                    }
                    else
                    {
                        log_error(
                            "Firewall put_Enabled failed, result = " << hr <<
                            "."
                        );
                    }
                    
                    if (SUCCEEDED(hr))
                    {
                        hr = apps->Add(app);
                    }
                    else
                    {
                        log_error(
                            "Firewall Add failed, result = " << hr <<
                            "."
                        );
                    }
                
                    app->Release();
                }
                
                apps->Release();
            }
            
            return SUCCEEDED(hr);
        }
    
    private:
    
        // ...
        
    protected:
    
        INetFwMgr * mgr_;
        INetFwPolicy * policy_;
        INetFwProfile * profile_;
};
#endif // _MSC_VER

firewall::firewall()
    : impl_(0)
{
    // ...
}

void firewall::start()
{
    if (impl_)
    {
        // ...
    }
    else
    {
#if (defined _MSC_VER)
        impl_ = new win_impl();
        
        if (impl_->start())
        {
			if (impl_->is_enabled())
			{
				log_info("Firewall is enabled.");

				wchar_t pBuf[MAX_PATH];
            
				DWORD bytes = GetModuleFileName(0, pBuf, sizeof(pBuf));

				std::string path = std::string(pBuf, pBuf + bytes);

				wchar_t * name = PathFindFileName(pBuf);
				PathRemoveExtension(name); 

				log_info("Firewall is adding path " << path << ".");

				if (((win_impl *)impl_)->add(path.c_str(), "stack.exe", true))
				{
					bool known = false;

					if (((win_impl *)impl_)->is_authorized(path.c_str(), &known))
					{
						log_info("Firewall authorized path.");
					}
					else
					{
						log_error("Firewall failed to authorize path, known = " << known << ".");
					}
				}
				else
				{
					log_info("Firewall failed to authorize path.");
				}
			}
        }
        else
        {
            log_error("Firewall failed to start.");
        }
#else
        log_debug("Firewall is not implemented on this platform.");
#endif // _MSC_VER
    }
}

void firewall::stop()
{
    if (impl_)
    {
        impl_->stop(), impl_ = 0;
    }
    else
    {
        // ...
    }
}

/*
    Blackboard Webservices OAuth
    Copyright (C) 2011-2013 Andrew Martin, Newcastle University

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package bbws.util.security;

//bbws
import bbws.util.security.oauth.OAuth;
import bbws.util.security.oauth.Server;

//java
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public abstract class DefaultProvider implements Provider
{
    protected long requestTimeout;
    protected Server server;
    protected Map<String,String> oauthParams;

    public static Map<String,String> getOAuthParams(String oAuthParams)
    {
        //System.out.println(oAuthParams);
        Map<String,String> params = new HashMap<String,String>();
        try
        {
            Iterator<String> i = Arrays.asList(oAuthParams.replaceAll("OAuth ", "").trim().split(",")).iterator();
            String[] param;
            while(i.hasNext())
            {
                param = i.next().trim().split("=\"");
                if(param[0].equals("realm")){params.put(OAuth.realm_url_key,getHeaderValue(param[1]));}
                else if(param[0].equals(OAuth.consumer_key_url_key)){params.put(OAuth.consumer_key_url_key,getHeaderValue(param[1]));}
                else if(param[0].equals(OAuth.nonce_url_key)){params.put(OAuth.nonce_url_key,getHeaderValue(param[1]));}
                else if(param[0].equals(OAuth.signature_url_key)){params.put(OAuth.signature_url_key,getHeaderValue(param[1]));}
                else if(param[0].equals(OAuth.signature_method_url_key)){params.put(OAuth.signature_method_url_key,getHeaderValue(param[1]));}
                else if(param[0].equals(OAuth.timestamp_url_key)){params.put(OAuth.timestamp_url_key,getHeaderValue(param[1]));}
                else if(param[0].equals(OAuth.version_url_key)){params.put(OAuth.version_url_key,getHeaderValue(param[1]));}
                else{System.out.println("Invalid oauth parameter! "+param[0]);}
            }
        }catch(java.lang.NullPointerException npe){//No OAuth Header supplied
        }catch(Exception e){System.out.println("Error parsing oauth params: "+e.getMessage());}
        return params;
    }

    public boolean validateOAuth(String requestMethod,String resource) //throws Exception
    {
        try
        {
            //System.out.println("DEF PROVIDER: "+this.requestTimeout+" "+requestMethod+" "+resource+" "+oauthParams.get(OAuth.nonce_url_key)+" "+oauthParams.get(OAuth.signature_url_key)+" "+Long.parseLong(oauthParams.get(OAuth.timestamp_url_key)));
            return server.isRequestValid(this.requestTimeout,requestMethod,resource,oauthParams.get(OAuth.nonce_url_key),oauthParams.get(OAuth.signature_url_key),Long.parseLong(oauthParams.get(OAuth.timestamp_url_key)));
        }
        catch(Exception e)
        {
            return false;
        }
    }

    protected static String getHeaderValue(String rawHeaderValue)
    {
        return rawHeaderValue.substring(0,rawHeaderValue.length()-1);
    }
}

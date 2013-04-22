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
package bbws.util.security.oauth;

public interface OAuth
{
    public static final String realm_url_key = "realm";
    public static final String consumer_key_url_key = "oauth_consumer_key";
    public static final String nonce_url_key = "oauth_nonce";
    public static final String signature_url_key = "oauth_signature";
    public static final String signature_method_url_key = "oauth_signature_method";
    public static final String timestamp_url_key = "oauth_timestamp";
    public static final String version_url_key = "oauth_version";
}

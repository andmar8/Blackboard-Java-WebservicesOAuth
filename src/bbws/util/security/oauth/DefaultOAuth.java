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

//java.io
import java.io.UnsupportedEncodingException;

//java.net
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;

//javav - security
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

//javax
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

//sun
import sun.misc.BASE64Encoder;

public abstract class DefaultOAuth implements OAuth
{
    //I haven't experimented with these yet...
    protected final String signature_method = "HMAC-SHA1";
    protected final String version = "1.0";
    protected String baseuri;
    protected String consumer_key;
    protected String consumer_secret;

    protected String encode(String string) throws UnsupportedEncodingException
    {
        return URLEncoder.encode(string, "UTF-8");
    }

    protected String encodeParams(String consumer_key,String nonce,String timestamp) throws UnsupportedEncodingException
    {
        return encode(consumer_key_url_key+"="+consumer_key+
                        "&"+nonce_url_key+"="+nonce+
                        "&"+signature_method_url_key+"="+signature_method+
                        "&"+timestamp_url_key+"="+timestamp+
                        "&"+version_url_key+"="+version);
    }

    protected String getOAuthHeadersWithSignature(String method,String baseresturl,String resource,String consumer_key,String consumer_secret,String nonce,String timestamp) throws UnsupportedEncodingException, InvalidKeyException, MalformedURLException, NoSuchAlgorithmException
    {
        return consumer_key_url_key+"=\""+encode(consumer_key)+"\","
                +nonce_url_key+"=\""+encode(nonce)+"\","
                +signature_url_key+"=\""+getEncodedSignedRequest(method, baseresturl+resource, consumer_key, consumer_secret, nonce, timestamp)+"\","
                +signature_method_url_key+"=\""+encode(signature_method)+"\","
                +timestamp_url_key+"=\""+encode(timestamp)+"\","
                +version_url_key+"=\""+encode(version)+"\",";
    }

    protected String normaliseAndEncodeURL(String baseresturlandresource) throws MalformedURLException, UnsupportedEncodingException
    {
        URL url = new URL(baseresturlandresource);
        String protocol = url.getProtocol().toLowerCase();
        int port = url.getPort();

        StringBuilder returnURL = new StringBuilder();
        returnURL.append(protocol+"://"+url.getHost().toLowerCase());
        if(port > 0 && (protocol.equals("http") && port!=80) || (protocol.equals("https") && port!=443))
        {
            returnURL.append(":"+port);
        }
        returnURL.append(url.getPath());
        return encode(returnURL.toString());
    }

    protected String getPath(String url) throws MalformedURLException
    {
        return new URL(url).getPath();
    }

    protected byte[] hashHmac(String algorithm,String data,String key) throws InvalidKeyException, NoSuchAlgorithmException
    {
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key.getBytes(),algorithm));
        return mac.doFinal(data.getBytes());
    }

    protected Boolean isSignatureValid(String requestMethod,String baseresturlandresource,String consumer_key,String consumer_secret,String nonce,String timestamp,String signature)
    {
        try
        {
            //System.out.println(baseresturlandresource+" "+nonce+" "+timestamp+" "+version+" "+requestMethod+" "+consumer_key+" "+consumer_secret);
            String validSignature = signRequest(encode(requestMethod),normaliseAndEncodeURL(baseresturlandresource),encodeParams(consumer_key, nonce, timestamp),encode(consumer_secret));
            //System.out.println(validSignature);
            //If the signature to compare has come from a header it will be encoded
            if(signature.endsWith("%3D")){validSignature=encode(validSignature);}
            if(signature.equals(validSignature))
            {
                return true;
            }
        }
        catch(Exception e)
        {
            System.out.println("Error whilst checking signature: "+e.getMessage());
        }
        return false;
    }

    protected String getEncodedSignedRequest(String requestMethod,String baseresturlandresource,String consumer_key,String consumer_secret,String nonce,String timestamp) throws InvalidKeyException, MalformedURLException, NoSuchAlgorithmException, UnsupportedEncodingException
    {
        return encode(signRequest(encode(requestMethod),normaliseAndEncodeURL(baseresturlandresource),encodeParams(consumer_key,nonce,timestamp),encode(consumer_secret)));
    }

    protected String signRequest(String encodedRequestMethod,String normalisedAndEncodedURL, String encodedParams, String encodedC_Secret) throws InvalidKeyException, MalformedURLException, NoSuchAlgorithmException, UnsupportedEncodingException
    {
        return new BASE64Encoder().encode(hashHmac("HMACSHA1",encodedRequestMethod+"&"+normalisedAndEncodedURL+"&"+encodedParams,encodedC_Secret+"&"/*,true*/));
    }
}

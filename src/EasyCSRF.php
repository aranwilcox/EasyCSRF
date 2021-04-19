<?php

namespace EasyCSRF;

use EasyCSRF\Exceptions\InvalidCsrfTokenException;
use EasyCSRF\Interfaces\SessionProvider;

class EasyCSRF
{
    /**
     * @var SessionProvider
     */
    protected $session;

    /**
     * @var string
     */
    protected $session_prefix = 'easycsrf_';

    /**
     * @param SessionProvider $sessionProvider
     */
    public function __construct(SessionProvider $sessionProvider)
    {
        $this->session = $sessionProvider;
    }

    /**
     * Generate a CSRF token.
     *
     * @param  string $key Key for this token
     * @return string
     */
    public function generate($key)
    {
        $key = $this->sanitizeKey($key);

        $token = $this->createToken();

        $this->session->set($this->session_prefix . $key, $token);

        return $token;
    }

    /**
     * Check the CSRF token is valid.
     *
     * @param  string  $key            Key for this token
     * @param  string  $token          The token string (usually found in $_POST)
     * @param  int     $timespan       Makes the token expire after $timespan seconds (null = never)
     * @param  boolean $multiple       Makes the token reusable and not one-time (Useful for ajax-heavy requests)
     */
    public function check($key, $token, $timespan = null, $multiple = false)
    {
        $key = $this->sanitizeKey($key);

        if (!$token) {
            throw new InvalidCsrfTokenException('Invalid CSRF token');
        }

        $sessionToken = $this->session->get($this->session_prefix . $key);
        if (!$sessionToken) {
            throw new InvalidCsrfTokenException('Invalid CSRF session token');
        }

        if (!$multiple) {
            $this->session->set($this->session_prefix . $key, null);
        }

        if ($this->referralHash() !== substr(base64_decode($sessionToken), 10, 40)) {
            throw new InvalidCsrfTokenException('Invalid CSRF token');
        }

        if ($token != $sessionToken) {
            throw new InvalidCsrfTokenException('Invalid CSRF token');
        }

        // Check for token expiration
        if (is_int($timespan) && (intval(substr(base64_decode($sessionToken), 0, 10)) + $timespan) < time()) {
            throw new InvalidCsrfTokenException('CSRF token has expired');
        }
    }

    /**
     * Sanitize the session key.
     *
     * @param string $key
     * @return string
     */
    protected function sanitizeKey($key)
    {
        return preg_replace('/[^a-zA-Z0-9]+/', '', $key);
    }

    /**
     * Create a new token.
     *
     * @return string
     */
    protected function createToken()
    {
        // time() is used for token expiration
        return base64_encode(time() . $this->referralHash() . $this->randomString(32));
    }

    /**
     * Return a unique referral hash.
     *
     * @return string
     */
    protected function referralHash()
    {
    	$user_ipaddress=0;
    	
	    //get correct Remote IP Address with Cloudfront
	    if (!empty($_SERVER["HTTP_CLIENT_IP"])) {
		    //check for ip from share internet
		    $ip = $_SERVER["HTTP_CLIENT_IP"];
	    } elseif (!empty($_SERVER["HTTP_X_FORWARDED_FOR"])) {
		    // Check for the Proxy User
		    $ip = $_SERVER["HTTP_X_FORWARDED_FOR"];
	    } else {
		    $ip = $_SERVER["REMOTE_ADDR"];
	    }

	    // This will print user's real IP Address it doesn't matter if the user is using proxy or not. Remove Cloudfront IP
	    $pos = strpos($ip, ',');
	    if ($pos > 0){
		    $user_ipaddress = substr($ip, 0, $pos);
	    }else{
		    $user_ipaddress = $ip;
	    }

	    return sha1($user_ipaddress . $_SERVER['HTTP_USER_AGENT']);
    }

    /**
     * Generate a random string.
     *
     * @param int $length
     * @return string
     */
    protected function randomString($length)
    {
        $seed = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijqlmnopqrtsuvwxyz0123456789';
        $max = strlen($seed) - 1;
        $string = '';
        for ($i = 0; $i < $length; ++$i) {
            $string .= $seed[intval(mt_rand(0.0, $max))];
        }

        return $string;
    }
}

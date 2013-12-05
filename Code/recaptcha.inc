<?php
// recaptcha.inc -- HotCRP wrapper class for reCAPTCHA form protection
// Distributed under an MIT-like license; see LICENSE

require_once("recaptcha/recaptchalib.php");

class reCAPTCHA {
    const PRIVATE_OPTNAME = "recaptchaPrivate";
    const PUBLIC_OPTNAME = "recaptchaPublic";
    const POST_CHALLENGE_FIELD = "recaptcha_challenge_field";
    const POST_RESPONSE_FIELD = "recaptcha_response_field";

    var $enabled;       // protection status
    var $private;       // recaptcha private key
    var $public;        // recaptcha public key
    var $last_error;    // error message produced by failed recaptcha validation
    var $ssl;           // use of ssl

    function __construct($opts, $ssl="auto") {
        $this->last_error = 0;
        $this->enabled = array_key_exists(self::PRIVATE_OPTNAME, $opts) && array_key_exists(self::PUBLIC_OPTNAME, $opts);
        if ($this->enabled) {
            $this->private = $opts[self::PRIVATE_OPTNAME];
            $this->public = $opts[self::PUBLIC_OPTNAME];

            if ($ssl == "auto") 
                $this->ssl = $_SERVER["HTTPS"];
            else 
                $this->ssl = (bool)$ssl;
        }
    }

    function protect($wrapper_element=null, $wrapper_id="recaptcha_wrapper", $wrapper_style="display: none;") {
        if ($this->enabled) {
            if ($wrapper_element) {
                $wrapper_id_s = $wrapper_id ? sprintf(' id="%s"', $wrapper_id) : "";
                $wrapper_style_s = $wrapper_style ? sprintf(' style="%s"', $wrapper_style) : "";
                printf('<%s%s%s>', $wrapper_element, $wrapper_id_s, $wrapper_style_s);
            }

            if ($this->last_error)
                echo recaptcha_get_html($this->public, $this->last_error, $this->ssl);
            else
                echo recaptcha_get_html($this->public, null, $this->ssl);

            if ($wrapper_element) {
                printf('</%s>', $wrapper_element);
            }
        }
    }

    function check() {
        if ($this->enabled) {
            // don't bother verifying empty captcha responses
            if ( !array_key_exists(self::POST_CHALLENGE_FIELD, $_POST) ||
                 !array_key_exists(self::POST_RESPONSE_FIELD, $_POST) ||
                 $_POST[self::POST_CHALLENGE_FIELD] == "" ||
                 $_POST[self::POST_RESPONSE_FIELD] == ""
            ) return False;

            $resp = recaptcha_check_answer ($this->private,
                $_SERVER["REMOTE_ADDR"],
                $_POST["recaptcha_challenge_field"],
                $_POST["recaptcha_response_field"]
            );
            if (!$resp->is_valid) {
                $this->last_error = $resp->error;
                return False;
            }
            else {
                return True;
            }
        }
        else {
            // recaptcha protection not enabled.
            return True;
        }
    }
}


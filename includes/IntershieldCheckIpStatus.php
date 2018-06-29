<?php
defined('ABSPATH') or exit;
if (!class_exists('IntershieldCheckIpStatus')) {
    class IntershieldCheckIpStatus
    {
        public $client_ip_address;
        public $is_bad_ip = false;

        public function __construct($badIpListDb)
        {
            $this->client_ip_address = $this->get_client_ip();
            if ($this->client_ip_address != 'UNKNOWN') {
                $this->check_status($this->client_ip_address, $badIpListDb);
            }
        }

        private function get_client_ip()
        {
            if (getenv('HTTP_CLIENT_IP'))
                $client_ip_address = getenv('HTTP_CLIENT_IP');
            else if (getenv('HTTP_X_FORWARDED_FOR'))
                $client_ip_address = getenv('HTTP_X_FORWARDED_FOR');
            else if (getenv('HTTP_X_FORWARDED'))
                $client_ip_address = getenv('HTTP_X_FORWARDED');
            else if (getenv('HTTP_FORWARDED_FOR'))
                $client_ip_address = getenv('HTTP_FORWARDED_FOR');
            else if (getenv('HTTP_FORWARDED'))
                $client_ip_address = getenv('HTTP_FORWARDED');
            else if (getenv('REMOTE_ADDR'))
                $client_ip_address = getenv('REMOTE_ADDR');
            else
                $client_ip_address = 'UNKNOWN';
            return $client_ip_address;
        }

        private function check_status($client_ip_address, $badIpListDb)
        {
            /**Remove Comments**/
            $bad_ips_str_without_comments = preg_replace("@\/\/.*[\n]+@", '', json_decode($badIpListDb));

            preg_match_all("@" . $client_ip_address . "[^\d||\.]+@", $bad_ips_str_without_comments, $matches);
            if (!empty($matches[0])) {
                $this->is_bad_ip = true;
            }
        }
    }
}
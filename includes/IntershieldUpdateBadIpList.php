<?php
defined('ABSPATH') or exit;
if (!class_exists('IntershieldUpdateBadIpList')) {
    class IntershieldUpdateBadIpList
    {
        public function __construct()
        {
            // Hook into that action that'll fire every 15 minutes
            add_action('add_every_fifteen_min', array($this, 'updateIpListTxt'));

            // Add a new interval for cron
            add_filter('cron_schedules', array($this, 'add_cron_interval'));

            // Schedule an action if it's not already scheduled
            if (!wp_next_scheduled('add_every_fifteen_min')) {
                wp_schedule_event(time(), 'custom_min', 'add_every_fifteen_min');
            }
        }


        public function updateIpListTxt()
        {
            /***Get bad ips new list***/
//            $url = "http://sigs.interserver.net/ip.txt";
            $url = "https://scanner.interserver.net/ip.txt";

            $response = wp_remote_get( $url, array('timeout'=> 120) );
            if (is_array( $response ) ) {
                $newIpList = $response['body']; // use the content
            }else{
               return false;
            }

            /***Set Bad IP's New List***/
            $path = dirname(__FILE__) . '/bad-ip-list.txt';
            $fp = fopen($path, 'wa+');

            if (!$fp) {
                echo 'file is not opend';
            }

            fwrite($fp, $newIpList);
            fclose($fp);
            return true;
        }

        public function add_cron_interval($schedules)
        {
            $schedules['custom_min'] = array(
                'interval' => 900,
            );
            return $schedules;
        }
    }
}
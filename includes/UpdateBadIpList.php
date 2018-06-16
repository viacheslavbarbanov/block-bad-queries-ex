<?php
defined('ABSPATH') or exit;
if (!class_exists('UpdateBadIpList')) {
    class UpdateBadIpList
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
            if (function_exists('curl_version')) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                $newIpList = curl_exec($ch);

                if (curl_errno($ch)) {
                    wp_die(curl_error($ch));
                } else {
                    curl_close($ch);
                }
            } else if ($response = @file_get_contents($url)) {
                $newIpList = $response;
            } else {
                wp_die(__('cURL and file_get_contents are disabled.', 'intershield'));
            }

            if (!is_string($newIpList) || !strlen($newIpList)) {
                echo "Failed to get contents.";
                $newIpList = '';
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
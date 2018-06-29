<?php
defined('ABSPATH') or exit;
if (!class_exists('IntershieldUpdateBadIpList')) {
    class IntershieldUpdateBadIpList
    {
        private $IntershieldAdminOptionsObj = false;

        public function __construct($IntershieldAdminOptions)
        {
            $this->IntershieldAdminOptionsObj = $IntershieldAdminOptions;
            // Hook into that action that'll fire every 15 minutes
            add_action('add_every_fifteen_min', array($this, 'updateIpListDB'));

            // Add a new interval for cron
            add_filter('cron_schedules', array($this, 'add_cron_interval'));

            // Schedule an action if it's not already scheduled
            if (!wp_next_scheduled('add_every_fifteen_min')) {
                wp_schedule_event(time(), 'custom_min', 'add_every_fifteen_min');
            }
        }

        public function updateIpListDB()
        {
            /***Get bad ips new list***/
            $url = "https://scanner.interserver.net/ip.txt";
            $response = wp_remote_get( $url, array('timeout'=> 120) );

            if (is_array( $response ) ) {
                $newIpList = $response['body']; // use the content
            }else{
               return false;
            }

            if($this->IntershieldAdminOptionsObj){
                $this->IntershieldAdminOptionsObj->updateBadIpListDb($newIpList);
            }
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
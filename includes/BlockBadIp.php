<?php
defined('ABSPATH') or exit;
if (!class_exists('BlockBadIp')) {
    class BlockBadIp
    {
        public function block_ip($block_bad_ip_switch)
        {
            /***When Firewall Is Off***/
            if ($block_bad_ip_switch === 'off') {
                return false;
            }

            $settingsDb = $this->getSettingsDb();
            $forbidden_link = $settingsDb['forbidden_link'];

            if ($settingsDb['show_403_forbidden'] === 'on') {
                header('HTTP/1.0 403 Forbidden');
                exit;
            } elseif (!$forbidden_link) {
//                header("Location: " . 'https://sigs.interserver.net/blocked?ref=' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] . '&port=' . $_SERVER['SERVER_PORT'], true, 301);
                header("Location: " . 'https://sigs.interserver.net/blocked', true, 301);
                exit;
            } else {
                $current_url = $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
                /***When Current Page Is Not Forbidden Page***/
                if ($forbidden_link !== 'http://' . $current_url && $forbidden_link !== 'https://' . $current_url) {
                    header('refresh:0;url=' . $forbidden_link);
                }
            }
        }

        public function getSettingsDb()
        {
            return json_decode(get_option('intershield_settings'), true);
        }
    }
}
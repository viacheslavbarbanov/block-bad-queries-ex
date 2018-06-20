<?php
/*
Plugin Name: InterShield
Plugin URI: https://scanner.interserver.net
Description: Malware scanner and firewall
Author: InterServer
Author URI: https://interserver.net
Version: 0.2
Text Domain: wp-intershield
*/

defined('ABSPATH') or exit;
define("INTERSHIELD_DIR", plugin_dir_path(__FILE__));
define("INTERSHIELD_URL", plugin_dir_url(__FILE__));
define("INTERSHIELD_REL_PATH", dirname(plugin_basename(__FILE__)));

ini_set('max_execution_time', 30000);
ini_set('mysql.connect_timeout', 30000);
ini_set('default_socket_timeout', 30000);

/***Admin Options***/
add_action('init', function () {
    include INTERSHIELD_DIR . 'includes/IntershieldAdminOptions.php';
    $IntershieldAdminOptions = new IntershieldAdminOptions();

    /****WHEN ENABLED AUTOMATICALLY UPDATE IP LIST IN SETTINGS***/
    if ($IntershieldAdminOptions->intershield_settings['auto_update_bad_ip_switch'] === 'on') {
        /***Scheduler update bad ips list***/
        include INTERSHIELD_DIR . 'includes/IntershieldUpdateBadIpList.php';
        $IntershieldUpdateBadIpList = new IntershieldUpdateBadIpList();
    } else {
        wp_clear_scheduled_hook('add_every_fifteen_min');
    }

    /*****WHEN CLICKED UPDATE BAD IP LIST*****/
    if ($IntershieldAdminOptions->startIntershieldUpdateBadIpList) {
        $updateIpListTxt = $IntershieldUpdateBadIpList->updateIpListTxt();
        if ($updateIpListTxt) {
            $IntershieldAdminOptions->msgAfterIntershieldUpdateBadIpList = __('Bad IP List Successfully Updated. Downloading bad IP list update from sigs.interserver.net ', 'intershield');
        }else{
            $IntershieldAdminOptions->msgAfterIntershieldUpdateBadIpList = __('Bad IP List Didn\'t Update', 'intershield');
        }
    }

    include INTERSHIELD_DIR . 'includes/IntershieldCheckIpStatus.php';
    $IntershieldCheckIpStatus = new IntershieldCheckIpStatus();

    /*****If Current Ip Is Bad*****/
    if ($IntershieldCheckIpStatus->is_bad_ip) {
        /*****Block Current Ip*****/
        include INTERSHIELD_DIR . 'includes/IntershieldBlockBadIp.php';
        $IntershieldBlockBadIp = new IntershieldBlockBadIp();
        $IntershieldBlockBadIp->block_ip($IntershieldAdminOptions->intershield_settings['intershield_update_bad_ip_list_menu']);
    }

    /****Files Controller****/
    include INTERSHIELD_DIR . 'includes/files-controller/IntershieldCheckFilesCorrect.php';
    $IntershieldCheckFilesCorrect = new IntershieldCheckFilesCorrect();
    /***When is clicked <<Start Scan>> button***/
    if ($IntershieldAdminOptions->scanState == 'start') {
        /***Update intershield_malware_files_list in wp-option***/
        $IntershieldAdminOptions->updateMalwareFilesDb($IntershieldCheckFilesCorrect->malware_files_list);

        /***Update intershield_unknown_files_list in wp-option***/
        $IntershieldAdminOptions->updateUnknownFilesList($IntershieldCheckFilesCorrect->unknownFilesList);

        /***Update intershield_good_files_list in wp-option***/
        $IntershieldAdminOptions->updateGoodFilesList($IntershieldCheckFilesCorrect->goodFilesList);

        header("Location: " . home_url() . '/wp-admin/admin.php?page=intershield&end-scan=true');
    } elseif ($IntershieldAdminOptions->scanState == 'configCheck') {
        /***Configuration Check Menu***/
        /***Get configCheckResult Of IntershieldCheckFilesCorrect() And Insert To msgAfterConfigCheck In IntershieldAdminOptions()***/
        $IntershieldAdminOptions->msgAfterConfigCheck = $IntershieldCheckFilesCorrect->configCheckResult;
    }

    /***Get Percent And Count Scanned Files From db***/
    add_action('wp_ajax_get_scan_percent', function () {
        wp_die(get_option('intershield_scanned_files_progress_percent'));
    });

    /***Get Percent And Count Sent Files By CURL From db***/
    add_action('wp_ajax_get_curl_percent', function () {
        wp_die(get_option('intershield_curl_progress_percent'));
    });
});

/***For Multi Language***/
add_action('plugins_loaded', function () {
    load_plugin_textdomain('intershield', false, INTERSHIELD_REL_PATH . '/languages');
});

/***Clear Scheduler hook***/
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('add_every_fifteen_min');
});

/***After Uninstall Plugin***/
register_uninstall_hook(__FILE__, 'intershield_uninstall');

function intershield_uninstall()
{
    delete_option('intershield_malware_files_list');
    delete_option('intershield_good_files_list');
    delete_option('intershield_unknown_files_list');
    delete_option('intershield_curl_progress_percent');
    delete_option('intershield_files_info_after_curl');
    delete_option('intershield_settings');
    delete_option('intershield_scanned_files_progress_percent');
}
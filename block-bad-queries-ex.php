<?php
/*
Plugin Name: Block Bad Queries Example
Plugin URI: #
Description:
Version: 0.1
Text Domain: admin
*/

defined('ABSPATH') or exit;
define("BLOCK_DIR", plugin_dir_path(__FILE__));
define("BLOCK_URL", plugin_dir_url(__FILE__));
define("BLOCK_REL_PATH", dirname(plugin_basename(__FILE__)));

ini_set('max_execution_time', 30000);
ini_set('mysql.connect_timeout', 30000);
ini_set('default_socket_timeout', 30000);

/***Scheduler update bad ips list***/
include BLOCK_DIR . 'includes/update_ip_list.php';

/***Clear Scheduler hook***/
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('add_every_custom_min');
});


/***Admin Options***/
add_action('init', function () {
    include BLOCK_DIR . 'includes/BlockAdminOptions.php';
    $blockAdminOptions = new BlockAdminOptions();

    include BLOCK_DIR . 'includes/CheckIpStatus.php';
    $CheckIpStatus = new CheckIpStatus();

    /*****If Current Ip Is Bad*****/
    if ($CheckIpStatus->is_bad_ip) {
        /*****Block Current Ip*****/
        include BLOCK_DIR . 'includes/BlockBadIp.php';
        $blockBadIp = new BlockBadIp();
        $blockBadIp->block_ip($blockAdminOptions->bl_settings['block_bad_ip_switch']);
    }

    /****Files Controller****/
    include BLOCK_DIR . 'includes/files-controller/CheckFilesCorrect.php';
    $checkFilesCorrect = new CheckFilesCorrect();
    /***When is clicked <<Start Scan>> button***/
    if ($blockAdminOptions->scanState == 'start') {
        /***Update bl_malware_files_list in wp-option***/
        $blockAdminOptions->updateMalwareFilesDb($checkFilesCorrect->malware_files_list);

        /***Update bl_unknown_files_list in wp-option***/
        $blockAdminOptions->updateUnknownFilesList($checkFilesCorrect->unknownFilesList);

        /***Update bl_good_files_list in wp-option***/
        $blockAdminOptions->updateGoodFilesList($checkFilesCorrect->goodFilesList);

        header("Location: " . home_url() . '/wp-admin/admin.php?page=scan-files&end-scan=true');
    } elseif ($blockAdminOptions->scanState == 'configCheck') {
        /***Configuration Check Menu***/
        /***Get configCheckResualt Of CheckFilesCorrect() And Insert To msgAfterConfigCheck In BlockAdminOptions()***/
        $blockAdminOptions->msgAfterConfigCheck = $checkFilesCorrect->configCheckResualt;
    }

    /***Get Percent And Count Scanned Files From db***/
    add_action('wp_ajax_get_scan_percent', function () {
        wp_die(get_option('bl_scanned_files_progress_percent'));
    });

    /***Get Percent And Count Sent Files By CURL From db***/
    add_action('wp_ajax_get_curl_percent', function () {
        wp_die(get_option('bl_curl_progress_percent'));
    });
});


/***After Uninstall Plugin***/
register_uninstall_hook(__FILE__, 'block_uninstall');

function block_uninstall()
{
    delete_option('bl_malware_files_list');
    delete_option('bl_good_files_list');
    delete_option('bl_unknown_files_list');
    delete_option('bl_curl_progress_percent');
    delete_option('bl_files_info_after_curl');
    delete_option('bl_settings');
    delete_option('bl_scanned_files_progress_percent');
}
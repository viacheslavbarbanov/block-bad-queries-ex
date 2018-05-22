<?php
defined('ABSPATH') or exit;
if (!class_exists('BlockAdminOptions')) {
    class BlockAdminOptions
    {
        public $intershield_settings;
        public $scanState;
        public $malwareFilesDb;
        public $goodFilesDb;
        public $unknownFilesDb;
        public $lastScannedInfo;
        public $msgAfterConfigCheck;
        public $startUpdateBadIpList;
        public $msgAfterUpdateBadIpList;
        public $filesInfoAfterCurl;
        public $curlProgressPercentDb;
        public $goodResponseCodeAfterCurl = '1 clamscan: OK';
        public $badResponseCodeAfterCurl = '0 clamscan: VIRUSNAME';
        public $responseAfterCurlArr = array();

        public function __construct()
        {
            $this->malwareFilesDb = $this->getMalwareFilesDb();
            $this->intershield_settings = $this->getSettingsDb();
            $this->goodFilesDb = $this->getGoodFilesDb();
            $this->unknownFilesDb = json_decode($this->getUnknownFilesDb(), true);
            $this->filesInfoAfterCurlDb = $this->getFilesInfoAfterCurlDb();
            $this->lastScannedInfo = json_decode($this->scannedFilesProgressPercent(), true);
            $this->curlProgressPercentDb = json_decode($this->getCurlProgressPercentDb(), true);
            $this->addMenuBlock();
            $this->checkRequests();

            /***Get Styles And Scripts Only For Admin Panel***/
            add_action('admin_enqueue_scripts', array($this, 'registerScripts'));
        }

        private function addMenuBlock()
        {
            /***Add Scan Files Menu In Dashboard***/
            add_action('admin_menu', function () {
                add_menu_page('intershield', 'intershield', 'manage_options', 'intershield', array($this, 'main_menu'), 'dashicons-portfolio');
                add_submenu_page('intershield', 'Settings', 'Settings', 'manage_options', 'intershield-settings', array($this, 'intershieldSettingsMenu'));
                add_submenu_page('intershield', 'Configuration Check', 'Configuration Check', 'manage_options', 'intershield-configuration-check', array($this, 'configurationCheckMenu'));

                if ($this->intershield_settings['show_check_unknown_files_menu_switch'] === 'on') {
                    add_submenu_page('intershield', 'Check Unknown Files', 'Check Unknown Files', 'manage_options', 'intershield-check-unknown-files', array($this, 'checkUnknownFilesMenu'));
                }

                /***When Blocking Bad Ip's Enabled In Settings***/
                if ($this->intershield_settings['block_bad_ip_switch'] === 'on') {
                    add_submenu_page('intershield', "Update Bad IP List", 'Update Bad IP List', 'manage_options', 'intershield-update-bad-ip-list', array($this, 'updateBadIpListMenu'));
                }
            });
        }

        public function main_menu()
        {
            ?>
            <div class="wrap">
                <h1><?php echo get_admin_page_title(); ?></h1>
                <div id="scan_page_parent">
                    <div id="scan_section">
                        <form name="scan_info" action="#" method="post">
                            <input type="radio" name="scan_type" class="full_scan" id="full_scan" value="full_scan"
                                   checked>
                            <label for="full_scan">Full Scan:</label><br>
                            <input type="radio" name="scan_type" class="part_scan" id="part_scan" value="part_scan">
                            <label for="part_scan">Part Scan:</label><br>
                            <input type="text" name="folder_name_for_scan" id="folder_name_for_scan" class="hidden"
                                   placeholder="Enter folder name..."><br>
                            <input type="hidden" name="wp_nonce_start_scan"
                                   value="<?php echo wp_create_nonce('start-scan'); ?>">

                            <input type="submit" name="start_scan" id="start_scan" value="Start Scan">
                            <a href="?page=intershield&end-scan=true" id="stop_scan">Stop Scan</a>
                        </form>
                    </div>
                    <div id="progressbar_section">
                        <div class="scanned_files_info"></div>
                        <div id="progressbar"></div>
                    </div>
                    <div id="information_section">

                        <?php if (!empty($this->lastScannedInfo['scannedFiles'])) { ?>
                            <div class="last_scanned_files_info">
                                <h1 class="title">
                                    Malware Files Information After Last Scan
                                    <span class="show_date">
                                       <?php echo trim($this->lastScannedInfo['date'], '""'); ?>
                                    </span>
                                </h1>
                                <h2 class="last_scanned_count">
                                    <?php echo 'Scanned ' . $this->lastScannedInfo['scannedFiles'] . ' files'; ?>
                                </h2>
                            </div>
                        <?php } ?>
                        <div class="malware_files_list">
                            <!--/***show <<Load More>> Button When <<Malware Files List>> Is More Then <<Count Files Shown During Start>>***/-->
                            <?php if ($this->malwareFilesDb && count(json_decode($this->malwareFilesDb, true)) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                <button type="button" id="loadMoreMalwareFiles" class="loadMore">
                                    Load More
                                </button>
                            <?php } ?>
                        </div>

                        <?php if (!empty($this->goodFilesDb) && $this->goodFilesDb !== '[]') {
                            $goodFilesListArr = json_decode($this->goodFilesDb, true); ?>

                            <div>
                                <button type="button" id="show_good_files">Show clean files</button>

                            </div>

                            <div class="good_files_list">
                                <h2 class="infoMsg">Clean files</h2>
                                <?php foreach ($goodFilesListArr as $value) {
                                    foreach ($value as $hashCode => $dir) { ?>
                                        <div class="current_file_info">
                                            <strong><?php echo $hashCode == '127.0.10.100' ? 'Good sha256match from previous scan' : 'Good sha256match known wordpress files'; ?></strong>
                                            <p><?php echo $dir; ?></p>
                                        </div>
                                    <?php }
                                } ?>

                                <!--/***show <<Load More>> Button When <<Good Files List>> Is More Then <<Count Files Shown During Start>>***/-->
                                <?php if (count($goodFilesListArr) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                    <button type="button" id="loadMoreGoodFiles" class="loadMore">Load More</button>
                                <?php } ?>
                            </div>
                        <?php } ?>
                    </div>
                </div>
            </div>
            <?php
        }

        public function intershieldSettingsMenu()
        { ?>
            <!--/***Update Settings Form***/-->
            <div class="wrap">
            <h1><?php echo get_admin_page_title(); ?></h1>
            <div id="settings_section">
                <form action="?page=intershield-settings&update-settings" method="post">
                    <table>
                        <tr>
                            <td class="interrogative_badge_parent">
                                <h3>
                                    <label for="forbidden_link"> Forbidden Link:</label>
                                </h3>
                                <img src="<?php echo BLOCK_URL . 'assets/images/interrogative-badge.png' ?>"
                                     class="interrogative_badge"
                                     title="Need fill url, for example ... https://website.com/forbidden/">
                            </td>
                            <td>
                                <input type="text" name="forbidden_link" id="forbidden_link"
                                       placeholder="Enter forbidden page url..."
                                       value="<?php echo $this->intershield_settings['forbidden_link'] ?>">
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <h3>
                                    <label for="count_files_shown_during_start">Count Files Shown During Start:</label>
                                </h3>
                            </td>
                            <td>
                                <input type="number" min="1" name="count_files_shown_during_start"
                                       id="count_files_shown_during_start"
                                       value="<?php echo $this->intershield_settings['count_files_shown_during_start'] ?>">
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <h3>
                                    <label for="load_more_files_range">Count Showing Files After Click Load
                                        More:</label>
                                </h3>
                            </td>
                            <td>
                                <input type="number" min="1" name="load_more_files_range" id="load_more_files_range"
                                       value="<?php echo $this->intershield_settings['load_more_files_range'] ?>">
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <h3>
                                    <label>Blocking Bad Ips:</label>
                                </h3>
                            </td>
                            <td>
                                On <input type="radio" name="block_bad_ip_switch" value="on"
                                    <?php echo $this->intershield_settings['block_bad_ip_switch'] == 'on' ? 'checked' : '' ?> >
                                Off <input type="radio" name="block_bad_ip_switch" value="off"
                                    <?php echo $this->intershield_settings['block_bad_ip_switch'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>

                        <tr>
                            <td>
                                <h3>
                                    <label>Show Check Unknown Files Menu:</label>
                                </h3>
                            </td>
                            <td>
                                On <input type="radio" name="show_check_unknown_files_menu_switch" value="on"
                                    <?php echo $this->intershield_settings['show_check_unknown_files_menu_switch'] == 'on' ? 'checked' : '' ?> >
                                Off <input type="radio" name="show_check_unknown_files_menu_switch" value="off"
                                    <?php echo $this->intershield_settings['show_check_unknown_files_menu_switch'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <input type="hidden" name="wp_nonce_update_settings"
                                       value="<?php echo wp_create_nonce('update-settings'); ?>">
                            </td>
                            <td class="textright"><input type="submit" value="Save"></td>
                        </tr>
                    </table>
                </form>
            </div>

            <!--/***Show Settings***/-->
            <?php if (!empty($this->intershield_settings['forbidden_link'])) { ?>
            <h2>Forbidden Page Link</h2>
            <div id="forbidden_link_page_section">
                <div class="forbidden_link">
                    <?php echo $this->intershield_settings['forbidden_link'] ?>
                </div>
                <div class="delete_forbidden_link">
                    <a href="?page=intershield-settings&del_forbidden_link&_wpnonce=<?php echo wp_create_nonce('del-link'); ?>"
                       data-method="delete"><img src="<?php echo BLOCK_URL . 'assets/images/delete.png' ?>"> </a>
                </div>
            </div>
            </div>
        <?php }
        }

        public function configurationCheckMenu()
        { ?>
            <div class="wrap">
                <h1><?php echo get_admin_page_title(); ?></h1>
                <div id="configuration_check_section">
                    <div class="config_check_button_parent">
                        <h3>
                            <a href="?page=intershield-configuration-check&scan_type=configCheck">Check</a>
                        </h3>
                    </div>
<!--                    /***When Clicked <<Configuration Check>> Button***/-->
                    <?php if (!empty($this->msgAfterConfigCheck)) { ?>
                        <div class="config_check_result">
                            <h3 class="infoMsg"><?php echo $this->msgAfterConfigCheck ?></h3>
                        </div>
                    <?php } ?>
                </div>
            </div>

            <?php
        }

        public function checkUnknownFilesMenu()
        { ?>
            <div class="wrap">
                <h1><?php echo get_admin_page_title(); ?></h1>
                <div id="check_unknown_files_section">
                    <?php
                    $unknownFilesListArr = $this->unknownFilesDb;
                    $filesInfoAfterCurlDb = json_decode($this->filesInfoAfterCurlDb, true);
                    if (is_null($unknownFilesListArr)) { ?>
                        <?php wp_die('<h2 class="successMsg">You have not done any scan yet!</h2>') ?>
                    <?php }

                    if (is_array($unknownFilesListArr) && !empty($unknownFilesListArr)) { ?>
                        <div class="unknown_files_list">
                            <h2 class="description">
                                The list of the unknown files after last scan in
                                <span class="show_date">
                                    <?php echo trim($this->lastScannedInfo['date'], '""'); ?>
                                </span>
                            </h2>
                            <?php
                            foreach ($unknownFilesListArr as $value) {
                                foreach ($value as $hashCode => $dir) {
                                    /***Show All Unknown Files***/
                                    echo('<p class="infoMsg current_file_info">' . $dir . '</p>');
                                }
                            }
                            ?>
                            <!--/***show <<Load More>> Button When <<Unknown Files List>> Is More Then <<Count Files Shown During Start>>***/-->
                            <?php if (count($unknownFilesListArr) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                <button type="button" id="loadMoreUnknownFiles" class="loadMore">Load More</button>
                            <?php } ?>
                        </div>

                        <form name="send_unknown_files" action="#" method="post">
                            <input type="submit" name="send_unknown_files" id="send_unknown_files"
                                   value="Send Unknown Files">
                            <input type="hidden" name="wp_nonce_unknown_files_nonce"
                                   value="<?php echo wp_create_nonce('unknown-files-nonce'); ?>">
                            <a href="?page=intershield&stop-sending-unknown-files=true" id="stop_sending_unknown_files">
                                Stop Sending
                            </a>
                        </form>

                        <div id="progressbar_section">
                            <div class="curl_sent_files_info"></div>
                            <div id="progressbar"></div>
                        </div>
                        <?php
                    } else { ?>
                        <h2 class="successMsg">You have no unknown files!</h2>
                    <?php }

                    /***Show Section <<The list of the files after last check>>***/
                    if (!empty($filesInfoAfterCurlDb)) { ?>
                        <div class="files_list_after_curl">
                            <h2 class="description">
                                The list of the files after last check in
                                <span class="show_date">
                                       <?php echo trim($this->curlProgressPercentDb['date'], '""'); ?>
                                    </span>
                            </h2>
                            <?php foreach ($filesInfoAfterCurlDb as $info) { ?>
                                <div class="current_file_info">
                                    <?php
                                    $currentFileDir = array_keys($info)[0];
                                    if (in_array($this->badResponseCodeAfterCurl, $info)) {
                                        /***Show Current Bad File Dir***/
                                        echo('<h3 class="errorMsg file_desc">Bad Code:</h3><p class="">' . $currentFileDir . '</p>');
                                    } elseif (in_array($this->goodResponseCodeAfterCurl, $info)) {
                                        /***Show Current Good File Dir***/
                                        echo('<h3 class="successMsg file_desc">Good Code:</h3><p class="">' . $currentFileDir . '</p>');
                                    }
                                    ?>
                                </div>
                            <?php } ?>

                            <!--/***show <<Load More>> Button When <<Files Info After Curl>> Is More Then <<Count Files Shown During Start>>***/-->
                            <?php if (count($filesInfoAfterCurlDb) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                <button type="button" id="loadMoreFilesListAfterCurl" class="loadMore">
                                    Load More
                                </button>
                            <?php } ?>
                        </div>
                    <?php } ?>
                </div>
            </div>
        <?php }

        public function updateBadIpListMenu()
        { ?>
            <div class="wrap">
                <h1><?php echo get_admin_page_title(); ?></h1>
                <div id="update_bad_ip_list_section">
                    <div class="update_bad_ip_list_button_parent">
                        <h3>
                            <a href="?page=intershield-update-bad-ip-list&update_bad_ip_list=true&_wpnonce=<?php echo wp_create_nonce('update-ip-list'); ?>">Update</a>
                        </h3>
                    </div>
<!--                    /***When Clicked <<Update>> Button***/-->
                    <?php if (!empty($this->msgAfterUpdateBadIpList)) { ?>
                        <div class="update_bad_ip_list_result">
                            <h3 class="successMsg"><?php echo $this->msgAfterUpdateBadIpList ?></h3>
                        </div>
                    <?php } ?>
                </div>
            </div>
            <?php
        }


        public function registerScripts()
        {
            /***CSS***/
            wp_register_style('jquery_ui_style', BLOCK_URL . "assets/styles/jquery-ui.css");
            wp_enqueue_style('jquery_ui_style');

            wp_register_style('block_style', BLOCK_URL . "assets/styles/block-style.css");
            wp_enqueue_style('block_style');

            /***JS***/
            wp_register_script('jquery_ui_script', BLOCK_URL . "assets/js/jquery-ui.js", array('jquery'));
            wp_enqueue_script('jquery_ui_script');

            wp_register_script('block_script', BLOCK_URL . "assets/js/block-script.js", array('jquery'));
            wp_enqueue_script('block_script');

            wp_localize_script('block_script', 'data_block', array(
                'scanState' => $this->scanState,
                'malwareFilesDb' => $this->malwareFilesDb,
                'goodFilesDb' => $this->goodFilesDb,
                'intershield_settings' => $this->intershield_settings,
                'ajaxUrl' => admin_url('admin-ajax.php'),
            ));
        }

        public function checkRequests()
        {
            if (!empty($_POST['start_scan']) && wp_verify_nonce($_POST['wp_nonce_start_scan'], 'start-scan')) {
                $this->scanState = 'start';
            } elseif (isset($_GET['end-scan'])) {
                $this->scanState = 'stop';
            } elseif (!empty($_GET['scan_type']) && $_GET['scan_type'] == 'configCheck') {
                $this->scanState = 'configCheck';
            }

            /***Save <<intershield_settings>> In DB***/
            if (!empty($_POST['wp_nonce_update_settings']) && wp_verify_nonce($_POST['wp_nonce_update_settings'], 'update-settings')) {
                $intershield_settings_arr = array(
                    'forbidden_link' => $_POST['forbidden_link'],
                    'count_files_shown_during_start' => $_POST['count_files_shown_during_start'],
                    'load_more_files_range' => $_POST['load_more_files_range'],
                    'block_bad_ip_switch' => $_POST['block_bad_ip_switch'],
                    'show_check_unknown_files_menu_switch' => $_POST['show_check_unknown_files_menu_switch'],
                );

                $this->updateSettingsDb($intershield_settings_arr);
                header("Location: " . home_url() . '/wp-admin/admin.php?page=intershield-settings', true, 301);
            }

            /***Delete forbidden_link In DB***/
            if (isset($_GET['del_forbidden_link']) && wp_verify_nonce($_GET['_wpnonce'], 'del-link')) {
                $intershield_settings = $this->intershield_settings;
                $intershield_settings['forbidden_link'] = '';
                update_option('intershield_settings', json_encode($intershield_settings));
                header("Location: " . home_url() . '/wp-admin/admin.php?page=intershield-settings', true, 301);
            }

            /***Unknown Files***/
            if (!empty($_POST['send_unknown_files']) && wp_verify_nonce($_POST['wp_nonce_unknown_files_nonce'], 'unknown-files-nonce')) {
                $this->unknownFilesController();
            }

            /***UPDATE BAD IP LIST***/
            if (isset($_GET['update_bad_ip_list']) && wp_verify_nonce($_GET['_wpnonce'], 'update-ip-list')) {
                $this->startUpdateBadIpList = true;

//echo '<pre>'; var_dump($_GET); exit;


            }

        }

        public function unknownFilesController()
        {
            $unknownFilesListArr = $this->unknownFilesDb;

            if (!empty($unknownFilesListArr)) {
                $totalFilesCountForCurl = count($unknownFilesListArr);
                $increment = 0;
                foreach ($unknownFilesListArr as $hashCode => $value) {
                    foreach ($unknownFilesListArr[$hashCode] as $dir) {
                        /***Send All Unknown Files For Repeated Check***/
                        if (file_exists($dir)) {
                            $increment++;
                            /***Get Percent For Send Unknown Files By Curl***/
                            $percent = round(($increment / $totalFilesCountForCurl) * 100, 0);
                            /***Send Current File For Check By Curl***/
                            if ($this->sendUnknownFilesByCurl($dir)) {
                                /***Save Percent For Every 5%***/
                                if ($percent % 5 === 0) {
                                    $this->updateCurlProgressPercent($increment, $percent, $totalFilesCountForCurl);
                                }
                            }
                        } else {
                            /***For Correct Reckon  Total Files Count Which Sent By CURL***/
                            $totalFilesCountForCurl--;
                        }
                    }
                }

                /***After Curl Remove All Good Files Off intershield_unknown_files_list In wp-option***/
                $this->removeGoodFilesOffUnknownFilesList();

                /***Update intershield_files_info_after_curl In wp-option***/
                $this->updateFilesInfoAfterCurl($this->responseAfterCurlArr);
                header("Refresh:0");
            }
        }

        public function removeGoodFilesOffUnknownFilesList()
        {
            $newUknownFilesListArr = array();
            foreach ($this->responseAfterCurlArr as $key => $currentFileArr) {
                foreach ($currentFileArr as $fileDir => $responseCode) {
                    if ($responseCode !== '1 clamscan: OK') {
                        array_push($newUknownFilesListArr, $fileDir);
                    }
                }
            }
            $this->updateUnknownFilesList($newUknownFilesListArr);
        }

        public function scannedFilesProgressPercent()
        {
            return get_option('intershield_scanned_files_progress_percent');
        }

        public function sendUnknownFilesByCurl($dir)
        {
//            // initialise the curl request
            $fileToUpload = new CURLFile(realpath($dir));
            $request = curl_init('http://scanner.interserver.net/wpscan');
            // send a file
            curl_setopt($request, CURLOPT_POST, true);
            curl_setopt($request, CURLOPT_SAFE_UPLOAD, true);
            curl_setopt(
                $request,
                CURLOPT_POSTFIELDS,
                array(
                    'submit' => 'apache',
                    'fileToUpload' => $fileToUpload,
                ));
            // output the response
            curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
            array_push($this->responseAfterCurlArr, array($dir => curl_exec($request)));
            // close the session
            curl_close($request);
            return true;
        }

        public function updateSettingsDb($intershield_settings_arr)
        {
            update_option('intershield_settings', json_encode($intershield_settings_arr));
        }

        public function updateMalwareFilesDb($malware_files_list)
        {
            update_option('intershield_malware_files_list', json_encode($malware_files_list));
        }

        public function updateGoodFilesList($goodFilesList)
        {
            update_option('intershield_good_files_list', json_encode($goodFilesList));
        }

        public function updateUnknownFilesList($unknownFilesListArr)
        {
            update_option('intershield_unknown_files_list', json_encode($unknownFilesListArr));
        }

        public function updateFilesInfoAfterCurl($responseAfterCurl)
        {
            update_option('intershield_files_info_after_curl', json_encode($responseAfterCurl));
        }

        public function updateCurlProgressPercent($increment, $percent, $totalFilesCountForCurl)
        {
            update_option('intershield_curl_progress_percent', json_encode(array('sentFiles' => $increment, 'percent' => $percent, 'total' => $totalFilesCountForCurl, 'date' => date('"d-m-Y H:i:s"'))));
        }

        public function getSettingsDb()
        {
            $default_intershield_settings = array(
                'forbidden_link' => '',
                'count_files_shown_during_start' => 5,
                'load_more_files_range' => 5,
                'block_bad_ip_switch' => 'on',
                'show_check_unknown_files_menu_switch' => 'off'
            );
            return get_option('intershield_settings') ? json_decode(get_option('intershield_settings'), true) : $default_intershield_settings;
        }

        public function getMalwareFilesDb()
        {
            return get_option('intershield_malware_files_list');
        }

        public function getGoodFilesDb()
        {
            return get_option('intershield_good_files_list');
        }

        public function getUnknownFilesDb()
        {
            return get_option('intershield_unknown_files_list');
        }

        public function getFilesInfoAfterCurlDb()
        {
            return get_option('intershield_files_info_after_curl');
        }

        public function getCurlProgressPercentDb()
        {
            return get_option('intershield_curl_progress_percent');
        }
    }
}
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
            $this->malwareFilesDb = json_decode($this->getMalwareFilesDb(), true);
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
                add_menu_page(__('Intershield', 'intershield'), __('Intershield', 'intershield'), 'manage_options', 'intershield', array($this, 'main_menu'), 'dashicons-shield');
                add_submenu_page('intershield', __('Settings', 'intershield'), __('Settings', 'intershield'), 'manage_options', 'intershield-settings', array($this, 'intershieldSettingsMenu'));
                add_submenu_page('intershield', __('Configuration Check', 'intershield'), __('Configuration Check', 'intershield'), 'manage_options', 'intershield-configuration-check', array($this, 'configurationCheckMenu'));

                if ($this->intershield_settings['show_check_unknown_files_menu_switch'] === 'on') {
                    add_submenu_page('intershield', __('Check Unknown Files', 'intershield'), __('Check Unknown Files', 'intershield'), 'manage_options', 'intershield-check-unknown-files', array($this, 'checkUnknownFilesMenu'));
                }

                /***When Blocking Bad Ip's Enabled In Settings***/
                if ($this->intershield_settings['block_bad_ip_switch'] === 'on') {
                    add_submenu_page('intershield', __('Update Bad IP List', 'intershield'), __('Update Bad IP List', 'intershield'), 'manage_options', 'intershield-update-bad-ip-list', array($this, 'updateBadIpListMenu'));
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
                            <label for="full_scan"> <?php _e('Full Site Scan:', 'intershield') ?> </label><br>
                            <input type="radio" name="scan_type" class="part_scan" id="part_scan" value="part_scan">
                            <label for="part_scan"> <?php _e('Partial Folder Scan:', 'intershield') ?> </label><br>
                            <input type="text" name="folder_name_for_scan" id="folder_name_for_scan" class="hidden"
                                   placeholder="Enter folder name..."><br>
                            <input type="hidden" name="wp_nonce_start_scan"
                                   value="<?php echo wp_create_nonce('start-scan'); ?>">

                            <input type="submit" name="start_scan" id="start_scan"
                                   value=" <?php _e('Start Scan', 'intershield') ?> ">
                            <a href="?page=intershield&end-scan=true" id="stop_scan" class="stop_button">
                                <?php _e('Stop Scan', 'intershield') ?>
                            </a>
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
                                    <?php _e('Malware Files Information After Last Scan in', 'intershield') ?>
                                    <span class="show_date">
                                       <?php echo trim($this->lastScannedInfo['date'], '""'); ?>
                                    </span>
                                </h1>
                                <h2 class="last_scanned_count">
                                    <?php echo __('Scanned', 'intershield') . ' ' . $this->lastScannedInfo['scannedFiles'] . ' ' . __('files', 'intershield'); ?>
                                </h2>
                            </div>
                        <?php } ?>
                        <div class="malware_files_list">
                            <?php if (!is_null($this->malwareFilesDb)) { ?>
                                <?php if (!empty($this->malwareFilesDb)) {
                                    /***Show Malware Files And Error Msg***/
                                    $malwareMsg = '';
                                    foreach ($this->malwareFilesDb as $currentFileInfo) {
                                        foreach ($currentFileInfo as $responseCode => $fileDir) {
                                            switch ($responseCode) {
                                                case '127.0.0.100':
                                                    $malwareMsg = __('Malware sha256 match from previous scan', 'intershield');
                                                    break;
                                                case '127.0.0.10':
                                                    $malwareMsg = __('Malware sha256 match from known malware', 'intershield');
                                                    break;
                                                case '127.0.0.20':
                                                    $malwareMsg = __('Malware hexmatch from known malware', 'intershield');
                                                    break;
                                                case '127.0.0.40':
                                                    $malwareMsg = __('Malware logical virus match', 'intershield');
                                                    break;
                                                case '127.0.0.50':
                                                    $malwareMsg = __('Malware SEO match', 'intershield');
                                                    break;
                                                case '127.0.0.2':
                                                    $malwareMsg = __('Malware test strings', 'intershield');
                                                    break;
                                            } ?>
                                            <div class="current_file_info">
                                                <strong><?php echo $malwareMsg; ?></strong>
                                                <p class="errorMsg"> <?php echo $fileDir; ?></p>
                                            </div>
                                        <?php }
                                    }

                                    /***show  <<View Debugging Information>> Button When <<Malware Files List>> Is More Then <<Count Files Shown During Start>>***/
                                    if (count($this->malwareFilesDb) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                        <button type="button" id="loadMoreMalwareFiles" class="loadMore">
                                            <?php _e('View Debugging Information', 'intershield') ?>
                                        </button>
                                    <?php }
                                } else {
                                    echo "<h2 class='successMsg'>" . __('No malware files were detected after the previous scan', 'intershield') . "</h2>";
                                } ?>
                            <?php } else {
                                echo "<h2 class='successMsg'>" . __('No previous scan was detected', 'intershield') . "</h2>";
                            } ?>


                        </div>

                        <?php if (!empty($this->goodFilesDb) && $this->goodFilesDb !== '[]') {
                            $goodFilesListArr = json_decode($this->goodFilesDb, true); ?>

                            <div>
                                <button type="button" id="show_good_files">
                                    <?php _e('Show clean files', 'intershield') ?>
                                </button>
                            </div>

                            <div class="good_files_list">
                                <h2 class="infoMsg">Clean files</h2>
                                <?php foreach ($goodFilesListArr as $value) {
                                    foreach ($value as $hashCode => $dir) { ?>
                                        <div class="current_file_info">
                                            <strong>
                                                <?php echo $hashCode == '127.0.10.100' ? __('Good sha256 match from previous scan', 'intershield') : __('Good sha256 match known wordpress files', 'intershield'); ?>
                                            </strong>
                                            <p><?php echo $dir; ?></p>
                                        </div>
                                    <?php }
                                } ?>

                                <!--/***show <<View Debugging Information>> Button When <<Good Files List>> Is More Then <<Count Files Shown During Start>>***/-->
                                <?php if (count($goodFilesListArr) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                    <button type="button" id="loadMoreGoodFiles"
                                            class="loadMore"><?php _e('View Debugging Information', 'intershield') ?> </button>
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
                                    <label for="forbidden_link"> <?php _e('Forbidden Link:', 'intershield') ?> </label>
                                </h3>
                                <img src="<?php echo BLOCK_URL . 'assets/images/interrogative-badge.png' ?>"
                                     class="interrogative_badge"
                                     title=" <?php _e('Need fill url, for example ... https://website.com/forbidden/', 'intershield') ?>">
                            </td>
                            <td>
                                <input type="text" name="forbidden_link" id="forbidden_link"
                                       placeholder="<?php _e('Enter forbidden page url...', 'intershield') ?> "
                                       value="<?php echo $this->intershield_settings['forbidden_link'] ?>">
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <h3>
                                    <label for="count_files_shown_during_start"> <?php _e('Files quantity on start:', 'intershield') ?> </label>
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
                                    <label for="load_more_files_range">
                                        <?php _e('Loading files quantity on "View Debugging Information" button click:', 'intershield') ?>
                                    </label>
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
                                    <label><?php _e('Blocking Bad IP:', 'intershield') ?> </label>
                                </h3>
                            </td>
                            <td>
                                <?php _e('On', 'intershield') ?>
                                <input type="radio" name="block_bad_ip_switch" value="on"
                                    <?php echo $this->intershield_settings['block_bad_ip_switch'] == 'on' ? 'checked' : '' ?> >
                                <?php _e('Off', 'intershield') ?>
                                <input type="radio" name="block_bad_ip_switch" value="off"
                                    <?php echo $this->intershield_settings['block_bad_ip_switch'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>

                        <tr>
                            <td>
                                <h3>
                                    <label> <?php _e('Show "Check Unknown Files" menu:', 'intershield') ?> </label>
                                </h3>
                            </td>
                            <td>
                                <?php _e('On', 'intershield') ?>
                                <input type="radio" name="show_check_unknown_files_menu_switch" value="on"
                                    <?php echo $this->intershield_settings['show_check_unknown_files_menu_switch'] == 'on' ? 'checked' : '' ?> >
                                <?php _e('Off', 'intershield') ?>
                                <input type="radio" name="show_check_unknown_files_menu_switch" value="off"
                                    <?php echo $this->intershield_settings['show_check_unknown_files_menu_switch'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <input type="hidden" name="wp_nonce_update_settings"
                                       value="<?php echo wp_create_nonce('update-settings'); ?>">
                            </td>
                            <td class="textright"><input type="submit" value="<?php _e('Save', 'intershield') ?>"></td>
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
                    <!--/***When Clicked <<Configuration Check>> Button***/-->
                    <?php if (!empty($this->msgAfterConfigCheck)) { ?>
                        <h3 class="infoMsg"><?php echo $this->msgAfterConfigCheck ?></h3>
                    <?php } ?>
                </div>
            </div>
        <?php }

        public function checkUnknownFilesMenu()
        { ?>
            <div class="wrap">
                <h1><?php echo get_admin_page_title(); ?></h1>
                <div id="check_unknown_files_section">
                    <?php
                    $unknownFilesListArr = $this->unknownFilesDb;
                    $filesInfoAfterCurlDb = json_decode($this->filesInfoAfterCurlDb, true);
                    if (is_null($unknownFilesListArr)) { ?>
                        <?php wp_die("<h2 class='successMsg'>" . __('You have not done any scan yet!', 'intershield') . "</h2>") ?>
                    <?php }

                    if (is_array($unknownFilesListArr) && !empty($unknownFilesListArr)) { ?>
                        <div class="unknown_files_list">
                            <h2 class="description">
                                <?php _e('The list of the unknown files after last scan in', 'intershield') ?>
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
                            <!--/***show <<View Debugging Information>> Button When <<Unknown Files List>> Is More Then <<Count Files Shown During Start>>***/-->
                            <?php if (count($unknownFilesListArr) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                <button type="button" id="loadMoreUnknownFiles" class="loadMore">
                                    <?php _e('View Debugging Information', 'intershield') ?>
                                </button>
                            <?php } ?>
                        </div>

                        <form name="send_unknown_files" action="#" method="post">
                            <input type="submit" name="send_unknown_files" id="send_unknown_files"
                                   value=" <?php _e('Send Unknown Files', 'intershield') ?> ">
                            <input type="hidden" name="wp_nonce_unknown_files_nonce"
                                   value="<?php echo wp_create_nonce('unknown-files-nonce'); ?>">

                            <a href="?page=intershield&stop-sending-unknown-files=true" id="stop_sending_unknown_files"
                               class="stop_button">
                                <?php _e('Stop Sending', 'intershield') ?>
                            </a>
                        </form>

                        <div id="progressbar_section">
                            <div class="curl_sent_files_info"></div>
                            <div id="progressbar"></div>
                        </div>
                        <?php
                    } else { ?>
                        <h2 class="successMsg"><?php _e('You have no unknown files!', 'intershield') ?></h2>
                    <?php }

                    /***Show Section <<The list of the files after last check>>***/
                    if (!empty($filesInfoAfterCurlDb)) { ?>
                        <div class="files_list_after_curl">
                            <h2 class="description">
                                <?php _e('The list of the files after last check in', 'intershield') ?>
                                <span class="show_date">
                                       <?php echo trim($this->curlProgressPercentDb['date'], '""'); ?>
                                </span>
                            </h2>
                            <?php foreach ($filesInfoAfterCurlDb as $info) { ?>
                                <div class="current_file_info">
                                    <?php
                                    $currentFileDir = array_keys($info)[0];
                                    if (in_array($this->badResponseCodeAfterCurl, $info)) { ?>
                                        <!--                                        /***Show Current Bad File Dir***/-->
                                        <h3 class="errorMsg file_desc"> <?php _e('Bad Code:', 'intershield') ?> </h3>
                                        <p> <?php echo $currentFileDir ?> </p>
                                    <?php } elseif (in_array($this->goodResponseCodeAfterCurl, $info)) { ?>
                                        <!--                                        /***Show Current Good File Dir***/-->
                                        <h3 class="successMsg file_desc"> <?php _e('good code:', 'intershield') ?> </h3>
                                        <p> <?php echo $currentFileDir ?> </p>
                                    <?php } ?>

                                </div>
                            <?php } ?>

                            <!--/***show <<View Debugging Information>> Button When <<Files Info After Curl>> Is More Then <<Count Files Shown During Start>>***/-->
                            <?php if (count($filesInfoAfterCurlDb) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                <button type="button" id="loadMoreFilesListAfterCurl" class="loadMore">
                                    <?php _e('View Debugging Information', 'intershield') ?>
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

                    <div class="update_bad_ip_list_info">
                        <h3>
                            <?php _e('The bad ip list will automatically update daily through wp-cron. Use the below to manually force an update.', 'intershield') ?>

                        </h3>
                    </div>

                    <div class="update_bad_ip_list_button_parent">
                        <h3>
                            <a href="?page=intershield-update-bad-ip-list&update_bad_ip_list=true&_wpnonce=<?php echo wp_create_nonce('update-ip-list'); ?>">
                                <?php _e('Update', 'intershield') ?>
                            </a>
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
                'messages' => array(
                    'text_total' => __('Total', 'intershield'),
                    'text_ScannedFiles' => __('Scanned Files:', 'intershield'),
                    'text_sentFiles' => __('Sent Files:', 'intershield'),
                ),
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
            } elseif (!empty($_GET['page']) && $_GET['page'] == 'intershield-configuration-check') {
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
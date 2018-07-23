<?php
defined('ABSPATH') or exit;
if (!class_exists('IntershieldAdminOptions')) {
    class IntershieldAdminOptions
    {
        public $intershield_settings;
        public $scanState;
        public $malwareFilesDb;
        public $goodFilesDb;
        public $unknownFilesDb;
        public $lastScannedInfo;
        public $msgAfterConfigCheck;
        public $startIntershieldUpdateBadIpList;
        public $msgAfterIntershieldUpdateBadIpList;
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
                add_menu_page(__('Intershield', 'wp-intershield'), __('Intershield', 'wp-intershield'), 'manage_options', 'intershield', array($this, 'main_menu'), 'dashicons-shield');
                add_submenu_page('intershield', __('Scan Files', 'wp-intershield'), __('Scan Files', 'wp-intershield'), 'manage_options', 'intershield', array($this, 'main_menu'));
                add_submenu_page('intershield', __('Settings', 'wp-intershield'), __('Settings', 'wp-intershield'), 'manage_options', 'intershield-settings', array($this, 'intershieldSettingsMenu'));
                add_submenu_page('intershield', __('Configuration Check', 'wp-intershield'), __('Configuration Check', 'wp-intershield'), 'manage_options', 'intershield-configuration-check', array($this, 'configurationCheckMenu'));
                if ($this->intershield_settings['show_check_unknown_files_menu_switch'] === 'on') {
                    add_submenu_page('intershield', __('Check Unknown Files', 'wp-intershield'), __('Check Unknown Files', 'wp-intershield'), 'manage_options', 'intershield-check-unknown-files', array($this, 'checkUnknownFilesMenu'));
                }

                /***When Blocking Bad Ip's Enabled In Settings***/
                if ($this->intershield_settings['enable_firewall_blocking'] === 'on' && $this->intershield_settings['intershield_update_bad_ip_list_menu'] === 'on') {
                    add_submenu_page('intershield', __('Update Bad IP List', 'wp-intershield'), __('Update Bad IP List', 'wp-intershield'), 'manage_options', 'intershield-update-bad-ip-list', array($this, 'IntershieldUpdateBadIpListMenu'));
                }
            });
        }

        public function main_menu()
        {
            ?>
            <div class="wrap">
                <h1><?php echo get_admin_page_title(); ?></h1>
                <div id="scan_page_parent">
                    <div class="information_section">
                        <h3>
                            Use the below to begin a scan of your site. Using InterServer's cached malware db file
                            checksums
                            are taken and compared to known good and bad files. Files which have not been scanned are
                            logged
                            as 'Unknown Files'. Please check the
                            <a href="?page=intershield-settings"> <?php _e('Settings', 'wp-intershield') ?> </a>
                        </h3>

                        <?php
                        $unknownFilesListArr = $this->unknownFilesDb;

                        if (is_array($unknownFilesListArr) && !empty($unknownFilesListArr)) {
                            // /****WHEN ENABLE FIREWALL BLOCKING IS "on" AND EXISTS UNKNOWN FILES***/
                            if ($this->intershield_settings['show_check_unknown_files_menu_switch'] === 'on') { ?>
                                <h3>
                                    <?php _e('Unknown files detected, please use', 'wp-intershield') ?>
                                    <a href="?page=intershield-check-unknown-files"> <?php _e('Scan Unknown Files', 'wp-intershield') ?></a>
                                </h3>
                                <?php
                            } else { ?>
                                <h3>
                                    <?php _e('You have unknown files', 'wp-intershield') ?>
                                </h3>
                            <?php }
                        } ?>
                    </div>
                    <div id="scan_section">
                        <form name="scan_info" action="#" method="post">
                            <input type="radio" name="scan_type" class="full_scan" id="full_scan" value="full_scan"
                                   checked>
                            <label for="full_scan"> <?php _e('Full Site Scan:', 'wp-intershield') ?> </label><br>
                            <input type="radio" name="scan_type" class="part_scan" id="part_scan" value="part_scan">
                            <label for="part_scan"> <?php _e('Partial Folder Scan:', 'wp-intershield') ?> </label><br>
                            <input type="text" name="folder_name_for_scan" id="folder_name_for_scan" class="hidden"
                                   placeholder="Enter folder name..."><br>
                            <input type="hidden" name="wp_nonce_start_scan"
                                   value="<?php echo wp_create_nonce('start-scan'); ?>">

                            <input type="submit" name="start_scan" id="start_scan"
                                   value=" <?php _e('Start Scan', 'wp-intershield') ?> ">
                            <a href="?page=intershield&end-scan=true" id="stop_scan" class="stop_button">
                                <?php _e('Stop Scan', 'wp-intershield') ?>
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
                                    <?php _e('Malware Files Information After Last Scan in', 'wp-intershield') ?>
                                    <span class="show_date">
                                       <?php echo trim($this->lastScannedInfo['date'], '""'); ?>
                                    </span>
                                </h1>
                                <h2 class="last_scanned_count">
                                    <?php echo __('Scanned', 'wp-intershield') . ' ' . $this->lastScannedInfo['scannedFiles'] . ' ' . __('files', 'wp-intershield'); ?>
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
                                                    $malwareMsg = __('Malware sha256 match from previous scan', 'wp-intershield');
                                                    break;
                                                case '127.0.0.10':
                                                    $malwareMsg = __('Malware sha256 match from known malware', 'wp-intershield');
                                                    break;
                                                case '127.0.0.20':
                                                    $malwareMsg = __('Malware hexmatch from known malware', 'wp-intershield');
                                                    break;
                                                case '127.0.0.40':
                                                    $malwareMsg = __('Malware logical virus match', 'wp-intershield');
                                                    break;
                                                case '127.0.0.50':
                                                    $malwareMsg = __('Malware SEO match', 'wp-intershield');
                                                    break;
                                                case '127.0.0.2':
                                                    $malwareMsg = __('Malware test strings', 'wp-intershield');
                                                    break;
                                            } ?>

                                            <div class="current_file_info">
                                                <div>
                                                    <strong><?php echo $malwareMsg; ?></strong>
                                                    <div class="current_malware_file_section popupToggle">
                                                        <div class="errorMsg">
                                                            <?php echo $fileDir; ?>
                                                        </div>
                                                        <div>
                                                            <span class="dashicons dashicons-visibility "></span>
                                                        </div>
                                                    </div>
                                                </div>

                                                <!-- /****SHOW CURRENT MALWARE FILE CONTENT****/-->
                                                <div class="popupParent">
                                                    <div class="popuptext">
                                                        <?php
                                                        $fileContent = (@file_get_contents($fileDir));
                                                        echo '<xmp>' . $fileContent . '</xmp>';
                                                        ?>
                                                    </div>
                                                </div>
                                            </div>
                                        <?php }
                                    }

                                    /***show  <<View Debugging Information>> Button When <<Malware Files List>> Is More Then <<Count Files Shown During Start>>***/
                                    if (count($this->malwareFilesDb) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                        <button type="button" id="loadMoreMalwareFiles" class="loadMore">
                                            <?php _e('View Debugging Information', 'wp-intershield') ?>
                                        </button>
                                    <?php }
                                } else {
                                    echo "<h2 class='successMsg'>" . __('No malware files were detected after the previous scan', 'wp-intershield') . "</h2>";
                                } ?>
                            <?php } else {
                                echo "<h2 class='successMsg'>" . __('No previous scan was detected', 'wp-intershield') . "</h2>";
                            } ?>
                        </div>

                        <?php if (!empty($this->goodFilesDb) && $this->goodFilesDb !== '[]') {
                            $goodFilesListArr = json_decode($this->goodFilesDb, true); ?>
                            <div>
                                <button type="button" id="show_good_files">
                                    <?php _e('Show clean files', 'wp-intershield') ?>
                                </button>
                            </div>

                            <div class="good_files_list">
                                <h2 class="infoMsg">Clean files</h2>
                                <?php foreach ($goodFilesListArr as $value) {
                                    foreach ($value as $hashCode => $dir) { ?>
                                        <div class="current_file_info">
                                            <strong>
                                                <?php echo $hashCode == '127.0.10.100' ? __('Good sha256 match from previous scan', 'wp-intershield') : __('Good sha256 match known wordpress files', 'wp-intershield'); ?>
                                            </strong>
                                            <p><?php echo $dir; ?></p>
                                        </div>
                                    <?php }
                                } ?>

                                <!--/***show <<View Debugging Information>> Button When <<Good Files List>> Is More Then <<Count Files Shown During Start>>***/-->
                                <?php if (count($goodFilesListArr) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                    <button type="button" id="loadMoreGoodFiles"
                                            class="loadMore"><?php _e('View Debugging Information', 'wp-intershield') ?> </button>
                                <?php } ?>
                            </div>

                        <?php } ?>
                    </div>
                </div>
            </div>
        <?php }

        public function intershieldSettingsMenu()
        { ?>
            <!--/***Update Settings Form***/-->
            <div class="wrap">
            <h1><?php echo get_admin_page_title(); ?></h1>
            <div id="settings_section">
                <form action="?page=intershield-settings&update-settings" method="post">
                    <table class="firewall_table">
                        <tr>
                            <td>
                                <h3>
                                    <label> <?php _e('Enable Firewall blocking:', 'wp-intershield') ?> </label>
                                </h3>
                            </td>
                            <td>
                                <?php _e('On', 'wp-intershield') ?>
                                <input type="radio" name="enable_firewall_blocking" value="on"
                                    <?php echo $this->intershield_settings['enable_firewall_blocking'] == 'on' ? 'checked' : '' ?> >
                                <?php _e('Off', 'wp-intershield') ?>
                                <input type="radio" name="enable_firewall_blocking" value="off"
                                    <?php echo $this->intershield_settings['enable_firewall_blocking'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>

                        <tr class="toggle_section">
                            <td>
                                <h3>
                                    <label> <?php _e('Automatically update bad IP list:', 'wp-intershield') ?> </label>
                                </h3>
                            </td>
                            <td>
                                <?php _e('On', 'wp-intershield') ?>
                                <input type="radio" name="auto_update_bad_ip_switch" value="on"
                                    <?php echo $this->intershield_settings['auto_update_bad_ip_switch'] == 'on' ? 'checked' : '' ?> >
                                <?php _e('Off', 'wp-intershield') ?>
                                <input type="radio" name="auto_update_bad_ip_switch" value="off"
                                    <?php echo $this->intershield_settings['auto_update_bad_ip_switch'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>

                        <tr class="toggle_section">
                            <td>
                                <h3>
                                    <label><?php _e('During bad IP block to show "403 forbidden":', 'wp-intershield') ?> </label>
                                </h3>
                            </td>
                            <td>
                                <?php _e('On', 'wp-intershield') ?>
                                <input type="radio" name="show_403_forbidden" value="on"
                                    <?php echo $this->intershield_settings['show_403_forbidden'] == 'on' ? 'checked' : '' ?> >
                                <?php _e('Off', 'wp-intershield') ?>
                                <input type="radio" name="show_403_forbidden" value="off"
                                    <?php echo $this->intershield_settings['show_403_forbidden'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>

                        <tr class="toggle_section">
                            <td class="interrogative_badge_parent">
                                <h3>
                                    <label for="forbidden_link"> <?php _e('Forbidden Link:', 'wp-intershield') ?> </label>
                                </h3>
                                <img src="<?php echo INTERSHIELD_URL . 'assets/images/interrogative-badge.png' ?>"
                                     class="interrogative_badge"
                                     title=" <?php _e('Need fill url, for example ... https://website.com/forbidden/', 'wp-intershield') ?>">
                            </td>
                            <td>
                                <input type="text" name="forbidden_link" id="forbidden_link"
                                       placeholder="<?php _e('Enter forbidden page url...', 'wp-intershield') ?> "
                                       value="<?php echo $this->intershield_settings['forbidden_link'] ?>">
                            </td>
                        </tr>

                        <tr class="toggle_section">
                            <td>
                                <h3>
                                    <label><?php _e('Show "Update Bad IP List" menu:', 'wp-intershield') ?> </label>
                                </h3>
                            </td>
                            <td>
                                <?php _e('On', 'wp-intershield') ?>
                                <input type="radio" name="intershield_update_bad_ip_list_menu" value="on"
                                    <?php echo $this->intershield_settings['intershield_update_bad_ip_list_menu'] == 'on' ? 'checked' : '' ?> >
                                <?php _e('Off', 'wp-intershield') ?>
                                <input type="radio" name="intershield_update_bad_ip_list_menu" value="off"
                                    <?php echo $this->intershield_settings['intershield_update_bad_ip_list_menu'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>
                    </table>

                    <table>
                        <tr>
                            <td>
                                <h3>
                                    <label> <?php _e('Show "Check Unknown Files" menu:', 'wp-intershield') ?> </label>
                                </h3>
                            </td>
                            <td>
                                <?php _e('On', 'wp-intershield') ?>
                                <input type="radio" name="show_check_unknown_files_menu_switch" value="on"
                                    <?php echo $this->intershield_settings['show_check_unknown_files_menu_switch'] == 'on' ? 'checked' : '' ?> >
                                <?php _e('Off', 'wp-intershield') ?>
                                <input type="radio" name="show_check_unknown_files_menu_switch" value="off"
                                    <?php echo $this->intershield_settings['show_check_unknown_files_menu_switch'] == 'off' ? 'checked' : '' ?> >
                            </td>
                        </tr>

                        <tr>
                            <td>
                                <h3>
                                    <label for="count_files_shown_during_start"> <?php _e('Files quantity on start:', 'wp-intershield') ?> </label>
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
                                        <?php _e('Loading files quantity on "View Debugging Information" button click:', 'wp-intershield') ?>
                                    </label>
                                </h3>
                            </td>
                            <td>
                                <input type="number" min="1" name="load_more_files_range" id="load_more_files_range"
                                       value="<?php echo $this->intershield_settings['load_more_files_range'] ?>">
                            </td>
                        </tr>
                    </table>

                    <div class="save_settings_section">
                        <input type="hidden" name="wp_nonce_update_settings"
                               value="<?php echo wp_create_nonce('update-settings'); ?>">
                        <input type="submit" value="<?php _e('Save', 'wp-intershield') ?>">
                    </div>

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
                       data-method="delete"><img src="<?php echo INTERSHIELD_URL . 'assets/images/delete.png' ?>"> </a>
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
                        <?php wp_die("
                            <h2 class='successMsg'>" . __('You have not done any scan yet!', 'wp-intershield') . "</h2>
                            <a href='?page=intershield' class='button'>Go to scan</a>
                            ") ?>
                    <?php }

                    if (is_array($unknownFilesListArr) && !empty($unknownFilesListArr)) { ?>
                        <div class="unknown_files_list">
                            <h1 class="description">
                                <?php _e('Unknown files have been detected. In order to scan then the check unknown files option must be enabled in configuration and then ran. This option is off by default because unknown files are sent to a remote scanner for scanning', 'wp-intershield') ?>
                            </h1>

                            <h2 class="description">
                                <?php _e('The list of the unknown files after last scan in', 'wp-intershield') ?>
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
                                    <?php _e('View Debugging Information', 'wp-intershield') ?>
                                </button>
                            <?php } ?>
                        </div>

                        <form name="send_unknown_files" action="#" method="post">
                            <input type="submit" name="send_unknown_files" id="send_unknown_files"
                                   value=" <?php _e('Send Unknown Files', 'wp-intershield') ?> ">
                            <input type="hidden" name="wp_nonce_unknown_files_nonce"
                                   value="<?php echo wp_create_nonce('unknown-files-nonce'); ?>">

                            <a href="?page=intershield&stop-sending-unknown-files=true" id="stop_sending_unknown_files"
                               class="stop_button">
                                <?php _e('Stop Sending', 'wp-intershield') ?>
                            </a>
                        </form>

                        <div id="progressbar_section">
                            <div class="curl_sent_files_info"></div>
                            <div id="progressbar"></div>
                        </div>
                        <?php
                    } else { ?>
                        <h2 class="successMsg"><?php _e('You have no unknown files!', 'wp-intershield') ?></h2>
                    <?php }

                    /***Show Section <<The list of the files after last check>>***/
                    if (!empty($filesInfoAfterCurlDb)) { ?>
                        <div class="files_list_after_curl">
                            <h2 class="description">
                                <?php _e('The list of the files after last check in', 'wp-intershield') ?>
                                <span class="show_date">
                                       <?php echo trim($this->curlProgressPercentDb['date'], '""'); ?>
                                </span>
                            </h2>
                            <?php foreach ($filesInfoAfterCurlDb as $info) { ?>
                                <div class="current_file_info">
                                    <?php
                                    $currentFileDir = array_keys($info)[0];
                                    if (!in_array($this->goodResponseCodeAfterCurl, $info)) { ?>
                                        <!-- /***Show Current Bad File Dir***/-->
                                        <div>
                                            <h3 class="file_desc"> <?php _e('scanned malware:', 'wp-intershield') ?> </h3>
                                            <div class="current_malware_file_section popupToggle">
                                                <div class="errorMsg">
                                                    <p> <?php echo $currentFileDir ?> </p>
                                                </div>
                                                <div>
                                                    <span class="dashicons dashicons-visibility "></span>
                                                </div>
                                            </div>
                                        </div>

                                        <div class="popupParent">
                                            <div class="popuptext">
                                                <?php
                                                $fileContent = (@file_get_contents($currentFileDir));
                                                echo '<xmp>' . $fileContent . '</xmp>';
                                                ?>
                                            </div>
                                        </div>

                                    <?php } else { ?>
                                        <!-- /***Show Current Good File Dir***/-->
                                        <h3 class="successMsg file_desc"> <?php _e('scanned clean:', 'wp-intershield') ?> </h3>
                                        <div>
                                            <p> <?php echo $currentFileDir ?> </p>
                                        </div>
                                    <?php } ?>
                                </div>
                            <?php } ?>

                            <!--/***show <<View Debugging Information>> Button When <<Files Info After Curl>> Is More Then <<Count Files Shown During Start>>***/-->
                            <?php if (count($filesInfoAfterCurlDb) > $this->intershield_settings['count_files_shown_during_start']) { ?>
                                <button type="button" id="loadMoreFilesListAfterCurl" class="loadMore">
                                    <?php _e('View Debugging Information', 'wp-intershield') ?>
                                </button>
                            <?php } ?>
                        </div>
                    <?php } ?>
                </div>
            </div>
        <?php }

        public function IntershieldUpdateBadIpListMenu()
        { ?>
            <div class="wrap">
                <h1><?php echo get_admin_page_title(); ?></h1>
                <div id="update_bad_ip_list_section">
                    <div class="update_bad_ip_list_info">
                        <h3>
                            <?php _e('The bad ip list will automatically update daily through wp-cron. Use the below to manually force an update.', 'wp-intershield') ?>
                        </h3>
                    </div>

                    <div class="update_bad_ip_list_button_parent">
                        <h3>
                            <a class="button"
                               href="?page=intershield-update-bad-ip-list&update_bad_ip_list=true&_wpnonce=<?php echo wp_create_nonce('update-ip-list'); ?>">
                                <?php _e('Update', 'wp-intershield') ?>
                            </a>
                        </h3>
                    </div>
                    <!--                    /***When Clicked <<Update>> Button***/-->
                    <?php if (!empty($this->msgAfterIntershieldUpdateBadIpList)) { ?>
                        <div class="update_bad_ip_list_result">
                            <h3 class="successMsg"><?php echo $this->msgAfterIntershieldUpdateBadIpList ?></h3>
                            <?php
                            $badIpListTxt = json_decode($this->getBadIpListDb());

                            if ($badIpListTxt) { ?>
                                <button type="button" id="show_bad_ip_list">
                                    <?php _e('Show bad IP list', 'wp-intershield') ?>
                                </button>
                                <div class="bad_ip_list">
                                    <?php
                                    echo '<pre>';
                                    echo $badIpListTxt;
                                    ?>
                                </div>
                            <?php } ?>

                        </div>
                    <?php } ?>
                </div>
            </div>
        <?php }

        public function registerScripts()
        {
            /***CSS***/
            wp_register_style('jquery_ui_progressbar_style', INTERSHIELD_URL . "assets/styles/jquery-ui.css");
            wp_enqueue_style('jquery_ui_progressbar_style');

            wp_register_style('intershield_style', INTERSHIELD_URL . "assets/styles/intershield-style.css", array(), 0.4);
            wp_enqueue_style('intershield_style');

            /***JS***/
            wp_enqueue_script('jquery-ui-progressbar');

            wp_register_script('intershield_script', INTERSHIELD_URL . "assets/js/intershield-script.js", array('jquery'), 0.4);
            wp_enqueue_script('intershield_script');

            wp_localize_script('intershield_script', 'intershield_data', array(
                'messages' => array(
                    'text_total' => __('Total', 'wp-intershield'),
                    'text_ScannedFiles' => __('Scanned Files:', 'wp-intershield'),
                    'text_sentFiles' => __('Sent Files:', 'wp-intershield'),
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
                    'enable_firewall_blocking' => $_POST['enable_firewall_blocking'],
                    'forbidden_link' => $_POST['forbidden_link'],
                    'show_403_forbidden' => $_POST['show_403_forbidden'],
                    'count_files_shown_during_start' => $_POST['count_files_shown_during_start'],
                    'load_more_files_range' => $_POST['load_more_files_range'],
                    'intershield_update_bad_ip_list_menu' => $_POST['intershield_update_bad_ip_list_menu'],
                    'auto_update_bad_ip_switch' => $_POST['auto_update_bad_ip_switch'],
                    'show_check_unknown_files_menu_switch' => $_POST['show_check_unknown_files_menu_switch'],
                );

                $this->updateSettingsDb($intershield_settings_arr);
                header("Refresh:0");
                exit;
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
                $this->startIntershieldUpdateBadIpList = true;
            }
        }

        public function unknownFilesController()
        {
            $unknownFilesListArr = $this->unknownFilesDb;
            if (!empty($unknownFilesListArr)) {

                /***Send Unknown Files By Curl For Check ***/
                if ($this->sendUnknownFilesByCurl()) {
                    /***After Curl Remove All Files Off intershield_unknown_files_list In wp-option***/
                    $this->updateUnknownFilesList(array());
                    $this->unknownFilesDb = array();

                    /***Update intershield_files_info_after_curl In wp-option***/
                    $this->updateFilesInfoAfterCurl($this->responseAfterCurlArr);

                    header("Refresh:0");
                    exit;
                }
            }
        }

        public function scannedFilesProgressPercent()
        {
            return get_option('intershield_scanned_files_progress_percent');
        }

        public function sendUnknownFilesByCurl()
        {
            add_action('http_api_curl', function ($handle, $requestArguments, $requestUrl) {
                $totalFilesCountForCurl = count($this->unknownFilesDb);
                $increment = 0;
                foreach ($this->unknownFilesDb as $fileInfo) {
                    $dir = array_values($fileInfo)[0];
                    if (file_exists($dir)) {
                        /***Send Current File For Check By Curl***/
                        $fileToUpload = new CURLFile($dir);
                        $request = curl_init($requestUrl);

                        // send a file
                        curl_setopt($request, CURLOPT_POST, true);
                        curl_setopt($request, CURLOPT_SAFE_UPLOAD, true);
                        curl_setopt(
                            $request,
                            CURLOPT_POSTFIELDS,
                            array(
                                'submit' => 'apache',
                                'fileToUpload' => $fileToUpload,
                            )
                        );

                        // output the response
                        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);

                        array_push($this->responseAfterCurlArr, array($dir => trim(curl_exec($request))));
                        // close the session
                        curl_close($request);

                        /***Get Percent For Send Unknown Files By Curl***/
                        $increment++;

                    } else {
                        /***For Correct Reckon  Total Files Count Which Sent By CURL***/
                        $totalFilesCountForCurl--;
                    }

                    $percent = round(($increment / $totalFilesCountForCurl) * 100, 0);

                    if ($percent % 5 === 0) {
                        $this->updateCurlProgressPercent($increment, $percent, $totalFilesCountForCurl);
                    }
                }
            }, 10, 3);

            do_action('http_api_curl', '', '', 'https://scanner.interserver.net/wpscan');

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

            return true;
        }

        public function updateCurlProgressPercent($increment, $percent, $totalFilesCountForCurl)
        {
            update_option('intershield_sent_files_progress_percent', json_encode(array('sentFiles' => $increment, 'percent' => $percent, 'total' => $totalFilesCountForCurl, 'date' => date('"d-m-Y H:i:s"'))));
        }

        public function updateBadIpListDb($badIpList)
        {
            update_option('intershield_bad_ip_list', json_encode($badIpList));
        }

        public function getSettingsDb()
        {
            $default_intershield_settings = array(
                'enable_firewall_blocking' => 'off',
                'forbidden_link' => '',
                'show_403_forbidden' => 'on',
                'count_files_shown_during_start' => 5,
                'load_more_files_range' => 5,
                'intershield_update_bad_ip_list_menu' => 'off',
                'auto_update_bad_ip_switch' => 'on',
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
            return get_option('intershield_sent_files_progress_percent');
        }

        public function getBadIpListDb()
        {
            return get_option('intershield_bad_ip_list');
        }
    }
}
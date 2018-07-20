<?php
include_once(INTERSHIELD_DIR . 'includes/IntershieldProcessHelper.php');

defined('ABSPATH') or exit;
if (!class_exists('IntershieldCheckFilesCorrect')) {

    class IntershieldCheckFilesCorrect extends intershieldProcessHelper
    {
        public $home_dir;
        public $filesList;
        public $malware_files_list = array();
        public $configCheckResult;
        public $unknownFilesList = array();
        public $goodFilesList = array();

        public function __construct()
        {
            /*****Get home directory****/
            preg_match("/(.*)wp-content/", INTERSHIELD_DIR, $matches);
            $this->home_dir = $matches[1];

            if (!empty($_POST['scan_type'])) {
                $this->process();

                /***To Cache All Files In filesList***/
                $this->hashFiles($this->filesList);
            } elseif (!empty($_GET['page']) && $_GET['page'] == 'intershield-configuration-check') {
                $this->testHashFiles();
            }
        }

        public function glob_recursive($base, $pattern, $flags = 0, $withoutWpIncludes = false)
        {
            $files = glob($base . $pattern, $flags);
            $directoriesArr = glob($base . '*', GLOB_ONLYDIR | GLOB_NOSORT | GLOB_MARK);

            /****For Delete All Directories Which Include <<wp-includes>> When Should Scan Without <<wp-includes>>****/
            if ($withoutWpIncludes) {
                $matches = preg_grep("@[\\\/]wp\-includes[\\\/]@i", $directoriesArr);
                $directoriesArr = array_diff($directoriesArr, $matches);
            }

            foreach ($directoriesArr as $dir) {
                $dirFiles = $this->glob_recursive($dir, $pattern, $flags);
                $dirFiles = str_replace('\\', '/', $dirFiles);
                if ($dirFiles !== false) {
                    $files = array_merge($files, $dirFiles);
                }
            }
            return $files;
        }


        public function load_data()
        {
            if ($_POST['scan_type'] == 'full_scan') {
                /***Check Access For <<wp-includes>> Directory***/
                $withoutWpIncludes = $this->checkHtaccess();
                /**Find All PHP And JS Files**/
                $this->filesList = $this->glob_recursive($this->home_dir, '*.{php,js,rb,py,pl,cgi,txt}', GLOB_BRACE, $withoutWpIncludes);

            } else if ($_POST['scan_type'] == 'part_scan' && !empty($_POST['folder_name_for_scan'])) {
                /***Find Current Folder Directory***/
                $folder_path_for_scan_arr = $this->glob_recursive($this->home_dir, $_POST['folder_name_for_scan'] . '/', GLOB_BRACE);
                if (!empty($folder_path_for_scan_arr)) {
                    /***Find All PHP And JS Files In Current Directory***/
                    $this->filesList = $this->glob_recursive($folder_path_for_scan_arr[0], '*.{php,js}', GLOB_BRACE);
                } else {
                    /***When *Current Folder Not Found**/
                    header("Location: " . home_url() . "/wp-admin/admin.php?page=intershield&errorMsg=" . urlencode("Folder not found"));
                }
            } else {
                /***When folder_name_for_scan Is Empty**/
                header("Location: " . home_url() . "/wp-admin/admin.php?page=intershield&errorMsg=" . urlencode("Folder name can not be empty"));
            }
        }

        /***Check Access For <<wp-includes>> Directory***/
        public function checkHtaccess()
        {
            $htaccessContent = @file_get_contents($this->home_dir . '.htaccess');
            $withoutWpIncludes = false;
            if ($htaccessContent && preg_match_all('@\^wp-includes\/\[\^\/\]\+\\\.php\$@', $htaccessContent)) {
                $withoutWpIncludes = true;
            }
            return $withoutWpIncludes;
        }

        public function hashFiles($filesList)
        {
            $malwareCodesList = array(
                '127.0.0.100',
                '127.0.0.10',
                '127.0.0.20',
                '127.0.0.40',
                '127.0.0.50',
                '127.0.0.2',
            );

            $goodCodesList = array(
                '127.0.10.100',
                '127.0.10.200'
            );

            $total = count($filesList);
            $increment = 0;

            foreach ($filesList as $file) {
                $increment++;
                /***Get Percent For Scan***/
                $percent = round(($increment / $total) * 100, 0);

                /***Save Percent For Every 5%***/
                if ($percent % 5 == 0) {
                    update_option('intershield_scanned_files_progress_percent', json_encode(array('scannedFiles' => $increment, 'percent' => $percent, 'total' => $total, 'date' => date('"d-m-Y H:i:s"'))));
                }

                $hash = hash_file('sha256', $file);
                $hashToCheck = substr($hash, 0, -1) . '.' . $hash[strlen($hash) - 1];
                $hostname = $hashToCheck . '.rblscanner.interserver.net';
                $returnedCode = gethostbyname($hostname);
                if (!in_array($returnedCode, $goodCodesList) && !in_array($returnedCode, $malwareCodesList)) {
                    /***When Return A Same Code What A Sent***/
                    /***Exclude <<wp-config.php>> File***/
                    if (!strpos($file, 'wp-config.php')) {
                        array_push($this->unknownFilesList, array($returnedCode => $file));
                    }
                } else if (in_array($returnedCode, $malwareCodesList)) {
                    /***When Return A Error Code***/
                    array_push($this->malware_files_list, array($returnedCode => $file));
                } else {
                    /***When Response A Good Code***/
                    array_push($this->goodFilesList, array($returnedCode => $file));
                }
            }
        }

        public function testHashFiles()
        {
            $url = 'https://scanner.interserver.net/wpscan';
            $data = '';

            $response = wp_remote_get($url, array('timeout' => 120));
            if (is_array($response)) {
                $data = $response['body']; // use the content
            }

            switch ($data) {
                case 'input..input..':
                    $this->configCheckResult = __('Remote scanner connection is working', 'wp-intershield');
                    break;
                default:
                    $this->configCheckResult = __('Remote scanner connection failing.', 'wp-intershield');
            }
        }
    }
}
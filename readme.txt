The intersheild plugin is a security plugin for wordpress that ultilizes the large amount of data that comes from InterServers secure intershield hosting which includes up to date
listing and reputations of ip addresses, millions of malware scans on wordpress sites and data of the current threats facing wordpress installs.

The main goals are to:

- block ips that are 100% malicious, while ensuring good ips including good bots are not blocked
- quick scans using checksums to find malware, only falling back to full scanning when the checksum is unknown


Privacy
- By default ips that are bad are send to a remote url where a real user can unblock the ip through a captcha. This also logs the ip, the url, and helps improve the waf firewall.
This setting can be changed in the settings section of the plugin to send the user to your own forbidden page.

- Files that have never been scanned before, can be sent to a remote scanning server. This will scan the file and return a result. The entire file is sent over SSL to be scanned.
This feature can be turned off in the settings section. Only files that have been scanned before will return a result.


Full InterShield Support
- There is no premium option for the plugin. The full intershield support only works on InterServer linux shared hosting at https://www.interserver.net/webhosting/ because
the premium features require software that must be installed at the server level outside of wordpress. Feature include:
 - phpmmdrop to drop php privaleges
 - automatic disabling of scripts in the uploads folder
 - disable directcalling of files in the wp-include folders and other folders that should never be called directly
 - WAF firewall
 - Smart firewall

For those with out full InterShield Support please review https://codex.wordpress.org/Hardening_WordPress
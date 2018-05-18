jQuery(document).ready(function ($) {
    /***Input where write folder name for part scan***/
    var folder_name_for_scan = $('#folder_name_for_scan');

    $('.full_scan').on('click', function () {
        $(folder_name_for_scan).removeAttr('required');
        $(folder_name_for_scan).hide('slow');
    });

    $('.part_scan').on('click', function () {
        $(folder_name_for_scan).attr('required', 'required');
        $(folder_name_for_scan).show('slow');
    });

    /***When Clicked Start Scan***/
    $('#start_scan').on('click', function () {
        /***When folder_name_for_scan Input Is Required And Empty ***/
        if ($(folder_name_for_scan).attr('required') && !$(folder_name_for_scan).val()) {
            return false;
        }
        $('#information_section').hide('slow');
        sendAjaxRequest('get_scan_percent');
    });

    /***When Clicked Send Unknown Files***/
    $('#send_unknown_files').on('click', function () {
        $('.unknown_files_list').hide('slow');
        $('.files_list_after_curl').hide('slow');
        sendAjaxRequest('get_curl_percent')
    });

    (function showMalwareFilesList() {
        console.log(data_block.malwareFilesDb);

        if(data_block.malwareFilesDb === '[]'){
            $('.malware_files_list').append('<h2 class="successMsg">Scan detected no malware</h2>');
            return false;
        }

        if (data_block.malwareFilesDb.length > 0 ) {
            var malwareFilesList = JSON.parse(data_block.malwareFilesDb);
            var malwareMsg = '';

            /***Append Files Directories In Dashboard***/
            malwareFilesList.forEach(function (obj) {
                $.each(obj, function (key, value) {
                    /***Check Error Code***/
                    switch (key) {
                        case '127.0.0.100':
                            malwareMsg = "Malware sha256match from previous scan";
                            break;
                        case '127.0.0.10':
                            malwareMsg = "Malware sha256match from known malware";
                            break;
                        case '127.0.0.20':
                            malwareMsg = "Malware hexmatch from known malware";
                            break;
                        case '127.0.0.40':
                            malwareMsg = "Malware logical virus match";
                            break;
                        case '127.0.0.50':
                            malwareMsg = "Malware SEO match";
                            break;
                        case '127.0.0.2':
                            malwareMsg = "Malware test strings";
                            break;
                    }

                    /***Add Msg In Dashboard***/
                    $('.malware_files_list').prepend('<div class="current_file_info">' +
                        '<strong>' + malwareMsg + '</strong> ' +
                        '<p class="errorMsg">' + value + '</p>' +
                        '</div>'
                    );
                });
            });
        }
    })();

    (function showInfoWithLoadMore() {
        var countFilesShownDuringStart = data_block.bl_settings['count_files_shown_during_start'];

        /***Part Of <<Good files list>>***/
        $(".good_files_list .current_file_info").slice(0, countFilesShownDuringStart).show();
        if ($(".good_files_list .current_file_info:hidden").length !== 0) {
            $("#loadMoreGoodFiles").show();
        }

        /***Part Of <<Malware files list>>***/
        $(".malware_files_list .current_file_info").slice(0, countFilesShownDuringStart).show();
        if ($(".malware_files_list .current_file_info:hidden").length !== 0) {
            $("#loadMoreMalwareFiles").show();
        }

        /***Part Of <<The list of the unknown files after last scan>>***/
        $(".unknown_files_list .current_file_info").slice(0, countFilesShownDuringStart).show();
        if ($(".unknown_files_list .current_file_info:hidden").length !== 0) {
            $("#loadMoreUnknownFiles").show();
        }

        /***Part Of <<The list of the files after last check>>***/
        $(".files_list_after_curl .current_file_info").slice(0, countFilesShownDuringStart).show();
        if ($(".files_list_after_curl .current_file_info:hidden").length !== 0) {
            $("#loadMoreFilesListAfterCurl").show();
        }
    })();

    $(".loadMore").on('click', function (e) {
        e.preventDefault();
        var loadMoreFilesRange = data_block.bl_settings['load_more_files_range'];
        var clickedLoadMoreParent = $(this).parent();

        $(clickedLoadMoreParent).find(".current_file_info:hidden").slice(0, loadMoreFilesRange).slideDown();
        if ($(clickedLoadMoreParent).find(".current_file_info:hidden").length === 0) {
            $(clickedLoadMoreParent).find(".loadMore").fadeOut('slow');
        }
    });

    function sendAjaxRequest(requestAction) {
        setInterval(function () {
        $.ajax({
            url: data_block.ajaxUrl,
            method: 'post',
            data: {action: requestAction}
        }).done(function (response) {
            var info = jQuery.parseJSON(response);

            if (requestAction === 'get_scan_percent') {
                $('.scanned_files_info').html('<h3> Total(' + info.total + ') Scanned Files: ' + info.scannedFiles + '</h3>');
            } else if (requestAction === 'get_curl_percent') {
                $('.curl_sent_files_info').html('<h3>Total(' + info.total + ') Sent Files: ' + info.sentFiles + '</h3>');
            }

            $("#progressbar").progressbar({
                value: info.percent,
                create: function (event, ui) {
                    var spanl = $("<span id='left'>0%</span>")
                        .css('float', 'left');
                    var spanr = $("<span id='right'>100%</span>")
                        .css('float', 'right');
                    var div = $("<div id='percent'></div>")
                        .css('width', $(this).width())
                        .append(spanl).append(spanr);
                    div.insertAfter($(this));
                }
            });
        });
        }, 2000)
    }

    /***Settings Page***/
    if ($('#forbidden_link_page_section').length > 0) {
        $(".delete_forbidden_link a").on("click", function (e) {
            var link = this;
            e.preventDefault();
            if (confirm('Are you sure?')) {
                window.location = link.href;
            }
        });
    }

    (function showErrorMsgInScanFilesPage() {
        var response = window.location.search;
        var errorMsgArr = response.match(/errorMsg=(.*)/);

        if (errorMsgArr != null) {
            var errorMsg = errorMsgArr[1].replace(/\+/g, ' ');
            $('#information_section').prepend('<h2 class="errorMsg">' + errorMsg + '</h2>');
        }
    })();

    $('#show_good_files').on('click', function () {
        $('#show_good_files').hide('slow');
        $('.good_files_list').show('slow');
    })
});
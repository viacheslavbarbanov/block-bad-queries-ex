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
        $('.stop_button').show('slow');
        $('#information_section').hide('slow');
        sendAjaxRequest('get_scan_percent');
    });

    /***When Clicked Send Unknown Files***/
    $('#send_unknown_files').on('click', function () {
        $('.stop_button').show('slow');
        $('.unknown_files_list').hide('slow');
        $('.files_list_after_curl').hide('slow');
        sendAjaxRequest('get_sent_files_percent')
    });

    (function showInfoWithLoadMore() {
        var countFilesShownDuringStart = intershield_data.intershield_settings['count_files_shown_during_start'];

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
        var loadMoreFilesRange = intershield_data.intershield_settings['load_more_files_range'];
        var clickedLoadMoreParent = $(this).parent();

        $(clickedLoadMoreParent).find(".current_file_info:hidden").slice(0, loadMoreFilesRange).slideDown();
        if ($(clickedLoadMoreParent).find(".current_file_info:hidden").length === 0) {
            $(clickedLoadMoreParent).find(".loadMore").fadeOut('slow');
        }
    });

    function sendAjaxRequest(requestAction) {
        setInterval(function () {
            $.ajax({
                url: intershield_data.ajaxUrl,
                method: 'post',
                data: {action: requestAction}
            }).done(function (response) {
                var info = jQuery.parseJSON(response);

                var currentFileNumber = '';

                if (requestAction === 'get_scan_percent') {
                    currentFileNumber = info.scannedFiles;

                    $('.scanned_files_info').html('' +
                        '<h3>'
                        + intershield_data.messages.text_total + '(' + info.total + ') '
                        + intershield_data.messages.text_ScannedFiles + ' ' + info.scannedFiles +
                        '</h3>');
                } else if (requestAction === 'get_sent_files_percent') {
                    currentFileNumber = info.sentFiles;

                    $('.curl_sent_files_info').html('<h3>' + intershield_data.messages.text_total + '(' + info.total + ') ' + intershield_data.messages.text_sentFiles + ' ' + info.sentFiles + '</h3>');
                }

                /***If during plugin work user goes to another page***/
                showMsgBeforeUnload(info.total, currentFileNumber);

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

    function showMsgBeforeUnload(total, currentFileNumber) {
        if (total > currentFileNumber) {
            $(window).bind('beforeunload', function () {
                return 'Please wait for scan to finish.';
            });
        } else {
            $(window).unbind("beforeunload");
            location.reload(true);
        }
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
    });

    /***Update Bad IP List Page***/
    $('#show_bad_ip_list').on('click', function () {
        $('#show_bad_ip_list').hide('slow');
        $('.bad_ip_list').show('slow');
    });

    /****FIREWALL TABLE IN SETTINGS MENU****/
    var enable_firewall_blocking = $('[name="enable_firewall_blocking"]');

    $.each($(enable_firewall_blocking), function (key, currentInput) {
        if ($(currentInput).is(':checked')) {
            $(currentInput).val() === 'on' ? hideShow_toggle_section('show') : hideShow_toggle_section('hide');
        }
    });

    $(enable_firewall_blocking).on('click', function () {
        $(this).val() === 'on' ? hideShow_toggle_section('show') : hideShow_toggle_section('hide')
    });

    function hideShow_toggle_section(query) {
        if (query === 'show') {
            $('.toggle_section').show('slow')
        } else if (query === 'hide') {
            $('.toggle_section').hide('slow')
        }
    }

    /*****POPUP IN MAIN MENU****/

    $(document.getElementsByClassName("popupToggle")).on('click', function () {
        var popuptext = $(this).parents('.current_file_info').find('.popuptext');

        if ($(popuptext).hasClass('show')) {
            $(popuptext).parent().css({"display": "none"});
            $(popuptext).removeClass('show');
        } else {
            $(popuptext).parent().css({"display": "flex", "justify-content": "center"});
            $(popuptext).addClass('show');
        }
    })
});
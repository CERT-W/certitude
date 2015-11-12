$(function () {
    console.log('init done');
    scan = function(ip) {
        $('#info-ip').val(ip);
        $('#info-hostname').val("");
        $('.form-infos').submit();
    };
    $('form.ajax').on('submit', function(event) {

        target = $(this).prop('action');
        data = $(this).serializeArray();
        $('#loading_gif').show();
        $('#result').load(target, data, function(responseText) {
            data = JSON.parse(responseText);
            $(this).html(prettyPrint(data, {expanded: true, maxDepth: 5}));
            $('.previous-scan').show();
            ips = data.ips
            for (key in ips) {
                $('.previous-scan ol').append('<li><a href="javascript:scan(\'' + key + '\');" data-target="' + key + '" class="previous-link">' + key + '</a></li>');
                $(".previous-scan").animate({ scrollTop: $('.previous-scan').height() }, "slow");
            }
            $('#loading_gif').hide();
        });
        console.log("Appel à l'API de scan en cours");
        event.preventDefault();
        return false;
    });
    $('input, textarea').placeholder();
});
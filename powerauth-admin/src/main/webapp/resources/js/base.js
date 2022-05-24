jQuery(document).ready(function($) {

    hljs.initHighlightingOnLoad();

    $(".action-remove").click(function (e) {
        if (!confirm("Are you sure you want to permanently remove this item?")) {
            e.stopPropagation();
            e.preventDefault();
        }
    });

    $(".action-revoke").click(function (e) {
        if (!confirm("Are you sure you want to permanently revoke this item?")) {
            e.stopPropagation();
            e.preventDefault();
        }
    });

    $(".clickable-row").click(function() {
        window.document.location = $(this).data("href");
    });

    // Tooltip

    $('.btn-clipboard').tooltip({
        trigger: 'click',
        placement: 'bottom'
    });

    function setTooltip(btn, message) {
        $(btn).tooltip('hide')
            .attr('data-original-title', message)
            .tooltip('show');
    }

    function hideTooltip(btn) {
        setTimeout(function() {
            $(btn).tooltip('hide');
        }, 1000);
    }

    // Clipboard

    var clipboard = new Clipboard('.btn-clipboard');

    clipboard.on('success', function(e) {
        setTooltip(e.trigger, 'Copied!');
        hideTooltip(e.trigger);
    });

    clipboard.on('error', function(e) {
        setTooltip(e.trigger, 'Failed!');
        hideTooltip(e.trigger);
    });
    
});
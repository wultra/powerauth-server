<script type="application/javascript">
    function refreshActivationCallbackJson(){
        const callback_json = document.getElementById('callback_json');
        callback_json.innerHTML = "";
        let callback_text = '{\n    "type": "ACTIVATION",\n    "activationId": "$ACTIVATION_ID"';
        if (document.getElementById('attr_userId').checked) {
            callback_text += ',\n    "userId": "$USER_ID"';
        }
        if (document.getElementById('attr_activationName').checked) {
            callback_text += ',\n    "activationName": "$ACTIVATION_NAME"';
        }
        if (document.getElementById('attr_deviceInfo').checked) {
            callback_text += ',\n    "deviceInfo": "$DEVICE_INFO"';
        }
        if (document.getElementById('attr_platform').checked) {
            callback_text += ',\n    "platform": "$PLATFORM"';
        }
        if (document.getElementById('attr_activationFlags').checked) {
            callback_text += ',\n    "activationFlags": [\n        "$ACTIVATION_FLAGS"\n    ]';
        }
        if (document.getElementById('attr_activationStatus').checked) {
            callback_text += ',\n    "activationStatus": "$ACTIVATION_STATUS"';
        }
        if (document.getElementById('attr_blockedReason').checked) {
            callback_text += ',\n    "blockedReason": "$BLOCKED_REASON"';
        }
        if (document.getElementById('attr_applicationId').checked) {
            callback_text += ',\n    "applicationId": "$APPLICATION_ID"';
        }
        callback_text += '\n}';
        callback_json.innerHTML = callback_text;
        hljs.highlightElement(callback_json);
    }
</script>
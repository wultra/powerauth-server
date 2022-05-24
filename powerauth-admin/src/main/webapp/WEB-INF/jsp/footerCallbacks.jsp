<script type="application/javascript">
    function refreshActivationCallbackJson(){
        const callback_json = document.getElementById('callback_json');
        callback_json.innerText='{\n    "type": "ACTIVATION",\n    "activationId": "$ACTIVATION_ID"';
        if (document.getElementById('attr_userId').checked) {
            callback_json.innerText+=',\n    "userId": "$USER_ID"';
        }
        if (document.getElementById('attr_activationName').checked) {
            callback_json.innerText+=',\n    "activationName": "$ACTIVATION_NAME"';
        }
        if (document.getElementById('attr_deviceInfo').checked) {
            callback_json.innerText+=',\n    "deviceInfo": "$DEVICE_INFO"';
        }
        if (document.getElementById('attr_platform').checked) {
            callback_json.innerText+=',\n    "platform": "$PLATFORM"';
        }
        if (document.getElementById('attr_activationFlags').checked) {
            callback_json.innerText+=',\n    "activationFlags": [\n        "$ACTIVATION_FLAGS"\n    ]';
        }
        if (document.getElementById('attr_activationStatus').checked) {
            callback_json.innerText+=',\n    "activationStatus": "$ACTIVATION_STATUS"';
        }
        if (document.getElementById('attr_blockedReason').checked) {
            callback_json.innerText+=',\n    "blockedReason": "$BLOCKED_REASON"';
        }
        if (document.getElementById('attr_applicationId').checked) {
            callback_json.innerText+=',\n    "applicationId": "$APPLICATION_ID"';
        }
        callback_json.innerText+='\n}';
        hljs.highlightBlock(callback_json);
    }
    refreshActivationCallbackJson();
</script>
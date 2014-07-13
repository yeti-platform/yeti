function sendmessage(websocket, data) {
    msg = JSON.stringify(data)
    websocket.send(msg)
    // console.log("Sent message to websocket: ")
    // console.log(data)
}

function initAnalyticsWebSocket() {
    if ("WebSocket" in window) {
        ws_analytics = new WebSocket(url_websocket_prefix+"api/analytics");
    } else {
        console.log("WebSocket not supported");
    }
}

function analyticsInterfaceInit() {
    sendmessage(ws_analytics, {'cmd': 'analyticsstatus'});
    // console.log("Sent analyticsstatus");

    ws_analytics.onmessage = function(msg) {
        data = $.parseJSON(msg.data);
        // console.log(data);

        $("#analytics-status-nav p").text(data.msg)

        if (data.msg == 'Inactive') { // deal with active / inactive status
            $("#analytics-status-nav p").css('color','')
        }
        else {
            $("#analytics-status-nav p").css('color','white')

        }

    };
}

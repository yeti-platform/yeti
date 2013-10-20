function sendmessage(websocket, data) {
    msg = JSON.stringify(data)
    websocket.send(msg)
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
    console.log("Sent analyticsstatus");

    ws_analytics.onmessage = function(msg) {
        data = $.parseJSON(msg.data);
        console.log(data);

        if (data.msg.active == true) { // deal with active status

            if (data.msg.status == true) {
                $("#analytics-status-nav p").text("Analytics: "+data.msg.status+"...")
                $("#analytics-status-nav p").css('color','white')
            }

            if (data.msg.progress) {
                $("#analytics-status-nav p").text("Analytics: "+data.msg.status+"... ("+data.msg.progress+")")
                $("#analytics-status-nav p").css('color','white')   
            }
        }

        else { // inactive status
            $("#analytics-status-nav p").text("Analytics: " +data.msg.status)
            $("#analytics-status-nav p").css('color','')
        }

        
        
        
    };
}
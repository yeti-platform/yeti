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

        if (data.msg.status == true) {
        	$("#analytics-status-nav p").text("Analytics: active...")
        	$("#analytics-status-nav p").css('color','white')
        }
        if (data.msg.status == false) { 
            $("#analytics-status-nav p").text("Analytics: inactive")
            $("#analytics-status-nav p").css('color','')
        }
        if (data.msg.progress) {
            $("#analytics-status-nav p").text("Analytics: active... ("+data.msg.progress+")")
            $("#analytics-status-nav p").css('color','white')   
        }
        
    };
}
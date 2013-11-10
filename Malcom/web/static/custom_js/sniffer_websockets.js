function initSnifferWebSocket() {
    if ("WebSocket" in window) {
        ws_sniffer = new WebSocket(url_websocket_prefix+"api/sniffer");
        ws_sniffer.onmessage = function(msg) { snifferWebSocketHandler(msg); }
    } else {
        console.log("WebSocket not supported");
    }
}

function snifferWebSocketHandler(msg) {
    data = $.parseJSON(msg.data);
    console.log("Received data: " + data.type); console.log(data);

    if (data.type == 'sniffstatus') {
        
                if (data.msg.status == 'inactive') {
                    $('#startsniff').removeAttr('disabled');
                    $('#stopsniff').attr('disabled','true');
                }
                else {
                    $('#startsniff').attr('disabled','true');
                    $('#stopsniff').removeAttr('disabled');
                }

                console.log("Retreiving session list (AJAX)")
                getSessionList()

                
                sendmessage(ws_sniffer, {'cmd': 'sniffupdate', 'session_name': $('#session_name').text()});
                console.log("Sent sniffupdate");
    }

    if (data.type == 'sniffupdate') {
            push_nodes(data.nodes);
            push_links(data.edges);
            start();
    }

    if (data.type == 'sniffstart') {
            $('#startsniff').attr('disabled','true')
            $('#stopsniff').removeAttr('disabled')
    }

    if (data.type == 'nodeupdate') {
            push_nodes(data.nodes);
            push_links(data.edges);
            start();
    }

    if (data.type == 'sniffstop') {
        $('#startsniff').removeAttr('disabled')
        $('#stopsniff').attr('disabled','true')
    }

    if (data.type == 'flowstatus') {
        table = $('#flow-list')
        table.empty()
        table.append("<tr><th>Timestamp</th><th style='text-align:right;'>Source</th><th></th><th style='text-align:right;'>Destination</th><th></th><th>Protocol</th><th>Packet count</th><th>Data transfered</th><th>Decoded as</th><th>Raw payload</th></tr>") //<th>First activity</th><th>Last activity</th><th>Content</th>
        for (var i in data.flows) {
            flow = data.flows[i]
            row = $('<tr />').attr('id',flow['fid'])
            row = netflow_row(flow, row)
            table.append(row)
        }
    }

    if (data.type == 'flow_statistics_update') {
        // find the column
        flow = data.flow
        row = $('#'+flow.fid)
        if (row.length > 0) {   // we found our row, let's update it
            row.empty()
            netflow_row(flow, row)
        }
        else {                  // row not found, let's create it
            row = $("<tr />").attr('id', flow.fid)
            console.log(row)
            row = netflow_row(flow, row)
            $("#flow-list").append(row)
        }
    }

    if (data.type == 'get_flow_payload') {
        pre = $('<pre />').text(data.payload)
        $('#PayloadModal .modal-body').empty().append(pre)
    }
}

function highlight_response(row) {
    id = row.attr('id')
    split = id.split('--')
    newid = split[0] +"--"+ split[2] +"--"+ split[1]
    $("#"+newid).toggleClass('flow-response')
}

function netflow_row(flow, row) {
    // row.append($('<td />').text(flow['src_addr']+":"+flow['src_port']))
    // row.append($('<td />').text(flow['dst_addr']+":"+flow['dst_port']))
    row.append($('<td />').text(flow['timestamp']))
    row.append($('<td />').text(flow['src_addr']).css('text-align', 'right'))
    row.append($('<td />').text(flow['src_port']))
    row.append($('<td />').text(flow['dst_addr']).css('text-align', 'right'))
    row.append($('<td />').text(flow['dst_port']))

    row.append($('<td />').text(flow['protocol']))
    row.append($('<td />').text(flow['packet_count']))

    // calculate transfered data

    data_transfered = flow['data_transfered']
    unit = 0
    while (data_transfered > 1024) {
        data_transfered = data_transfered / 1024;
        unit++ ;
    }

    data_transfered = Math.round(data_transfered*100)/100

    if (unit == 0)
        unit = ' B'
    else if (unit == 1)
        unit = ' KB'
    else if (unit == 2)
        unit = ' MB'
    else if (unit == 3)
        unit = ' GB'

    row.append($('<td />').text(data_transfered + unit))

    // setup decoding
    if (flow.decoded_flow) {
        decoded = $("<td />").text(flow.decoded_flow.type)
        decoded.tooltip({ 'title': flow.decoded_flow.info, 'container': 'body'})
    }
    else {
        decoded = $("<td />").text("N/A")
    }
    row.mouseover(function() {
        highlight_response($(this))
    });
    row.mouseout(function() {
        highlight_response($(this))
    });
    row.append(decoded)

    // setup payload visor

    payload = flow.payload
    // icon = $("<a />").attr({ 'href': "#PayloadModal", 'role': 'button', 'class':'btn', 'data-toggle': 'modal' })
    // icon.append($("<i />").addClass('icon-eye-open'))
    icon_view = $("<i />").addClass('icon-eye-open');
    icon_view.click(function() {
        get_flow_payload(flow.fid); 
        $("#PayloadModal").modal('toggle')
    });

    icon_download = $("<a />").attr('href', url_static_prefix+'/sniffer/'+$('#session_name').text()+"/"+flow.fid+'/raw');
    icon_download.append($("<i />").addClass('icon-download-alt'));
    
    payload = $('<td />').addClass('flow-payload')
    payload.append(icon_view)
    payload.append(icon_download)

    if (flow.tls == true) {
        payload.append("<img class='ssl-smiley' alt='SSL added and removed here!' src='/static/custom_img/ssl.png' />")
    }

    row.append(payload)

    return row
}

function get_flow_payload(id) {
    sendmessage(ws_sniffer, {'cmd': 'get_flow_payload', 'session_name': $('#session_name').text(), 'flowid': id})
}

function snifferInterfaceInit() {
    sendmessage(ws_sniffer, {'cmd': 'sniffstatus', 'session_name': $('#session_name').text()});
    sendmessage(ws_sniffer, {'cmd': 'flowstatus', 'session_name': $('#session_name').text()});
    console.log("Sent sniffstatus");
}


function startsniff(){
    session_name = $('#session_name').text()
    sendmessage(ws_sniffer, {'cmd': 'sniffstart', 'session_name': session_name})
    $('#startsniff').attr('disabled','true')
    console.log("Sent sniffstart")

}

function stopsniff() {
    session_name = $('#session_name').text()
    sendmessage(ws_sniffer, {'cmd': 'sniffstop', 'session_name': session_name})
    $('#stopsniff').attr('disabled','true')
    console.log("Sent sniffstop")
}

function getSessionList() {
    $.ajax({
        type: 'get',
        url: url_static_prefix+'/sniffer/sessionlist/',
        success: function(data) {
            data = $.parseJSON(data);
            console.log(data);

            table = $('#sessions');

            for (var i in data.session_list) {    
                
                tr = $('<tr></tr>');
                session_links = $('<a />').attr("href", url_static_prefix+'/sniffer/'+data.session_list[i]['name']).text(data.session_list[i]['name']);
                tr.append($("<td />").append(session_links))
                tr.append($("<td />").text(data.session_list[i]['packets']));
                tr.append($("<td />").text(data.session_list[i]['nodes']));
                tr.append($("<td />").text(data.session_list[i]['edges']));
                tr.append($("<td />").text(data.session_list[i]['status']));
                table.append(tr);
            }
            }
        });
}
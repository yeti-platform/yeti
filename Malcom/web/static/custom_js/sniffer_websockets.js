function initSnifferWebSocket() {
    if ("WebSocket" in window) {
        ws_sniffer = new WebSocket(url_websocket_prefix+"websocket/sniffer");
        ws_sniffer.onmessage = function(msg) { snifferWebSocketHandler(msg); }
    } else {
        console.log("WebSocket not supported (data)");
    }
}

function initSnifferRealtimeWebSocket(session_id) {
    if ("WebSocket" in window) {
        ws_sniffer_data = new WebSocket(url_websocket_prefix+"websocket/sniffer/streaming/"+session_id);
        ws_sniffer_data.onmessage = function(msg) { snifferWebSocketHandler(msg); }
    } else {
        console.log("WebSocket not supported (realtime)");
    }
}

function snifferWebSocketHandler(msg) {
    data = $.parseJSON(msg.data);
    // console.log("Received data: " + data.type); console.log(data);

    if (data.type == 'sniffstatus') {

                if (data.msg.status == 'inactive') {
                    $('#startsniff').removeAttr('disabled');
                    $('#stopsniff').attr('disabled','true');
                }
                else {
                    $('#startsniff').attr('disabled','true');
                    $('#stopsniff').removeAttr('disabled');
                }
                // getSessionList()

                sendmessage(ws_sniffer, {'cmd': 'sniffupdate', 'session_id': $('#session_id').text()});
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
            push_nodes(data.msg.nodes);
            push_links(data.msg.edges);
            start();
    }

    if (data.type == 'sniffstop' || data.type == 'sniffdone') {
        $('#startsniff').removeAttr('disabled')
        $('#stopsniff').attr('disabled','true')
    }

    if (data.type == 'flowstatus') {
        table = $('#flow-list')
        table.empty()
        table.append("<tr><th>Timestamp</th><th style='text-align:right;'>Source</th><th></th><th style='text-align:right;'>Destination</th><th></th><th>Proto</th><th>#</th><th>Data</th><th>Decoded as</th><th>Raw payload</th><th>YARA</th></tr>") //<th>First activity</th><th>Last activity</th><th>Content</th>
        for (var i in data.flows) {
            flow = data.flows[i]
            row = $('<tr />').attr('id',flow['fid'])
            row = netflow_row(flow, row)
            table.append(row)
        }
    }

    if (data.type == 'flow_statistics_update') {
        // find the column
        flow = data.msg.flow
        row = $('#'+flow.fid)
        if (row.length > 0) {   // we found our row, let's update it
            row.empty()
            netflow_row(flow, row)
        }
        else {                  // row not found, let's create it
            row = $("<tr />").attr('id', flow.fid)
            row = netflow_row(flow, row)
            $("#flow-list").append(row)
        }
    }

    if (data.type == 'get_flow_payload') {
        payload = atob(data.payload)

        div_ascii_dump = $('<pre />')
        div_ascii_dump.text(payload)

        div_hexdump = $('<div />')

        div_ascii = $('<pre />').attr('id', 'hexdump_ascii')

        div_ascii.text(splitSubstr(payload.replace(/[^\x20-\x7E]/g, "."), 16).join('\n'))

        div_hex = $('<pre />').attr('id', 'hexdump_hex')
        hex = ""
        hex_payload = hexdump(payload)
        lines = splitSubstr(hex_payload, 32)
        for (var i in lines) {
            bytes = splitSubstr(lines[i], 2)
            for (var b in bytes) {
                hex +=  bytes[b] + " "
            }
            hex += "\n"
        }
        div_hex.text(hex).css('float','left')

        div_offsets = $("<pre />").attr('id', 'hexdump_offsets')
        lines = Math.ceil(payload.length/16)
        offsets = ""
        ctr = 0
        for (var i=0; i<lines; i++) {
            offsets += "0x"+ctr.toString(16)
            offsets += "\n"
            ctr += 16
        }
        div_offsets.text(offsets).css('float','left').css('text-align', 'right')

        div_hexdump.append(div_offsets).append(div_hex).append(div_ascii)

        $('#hexdump').empty().append(div_hexdump)
        $('#ascii').empty().append(div_ascii_dump)
    }
}

function splitSubstr(str, len) {
  var ret = [ ];
  for (var offset = 0, strLen = str.length; offset < strLen; offset += len) {
    ret.push(str.substr(offset, len));
  }
  return ret;
}

function hexdump(payload) {
    var hex = '';
    for(var i = 0; i < payload.length; i++) {
        if (payload.charCodeAt(i) < 16) {b = "0"}
        else { b = ""}
        hex += b+payload.charCodeAt(i).toString(16);
    }
    return hex
}

function highlight_response(row) {
    id = row.attr('id')
    split = id.split('--')
    newid = split[0] +"--"+ split[2] +"--"+ split[1]

    row.toggleClass('flow-request')
    $("#"+newid).toggleClass('flow-response')

}

function netflow_row(flow, row) {
    // row.append($('<td />').text(flow['src_addr']+":"+flow['src_port']))
    // row.append($('<td />').text(flow['dst_addr']+":"+flow['dst_port']))
    d = new Date(flow['timestamp'] * 1000)
    row.append($('<td />').text(format_date(d, true)))
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
        decoded = $("<td />").text(flow.decoded_flow.info)
        decoded.tooltip({ 'title': flow.decoded_flow.type, 'container': 'body'})
        row.addClass(flow.decoded_flow.flow_type)
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
    icon_view = $("<span />").addClass('glyphicon glyphicon-eye-open');
    icon_view.click(function() {
        get_flow_payload(flow.fid);
        $("#PayloadModal").modal('toggle')
    });

    icon_download = $("<a />").attr('href', url_static_prefix+'/sniffer/'+$('#session_id').text()+"/"+flow.fid+'/raw');
    icon_download.append($("<span />").addClass('glyphicon glyphicon-download-alt'));

    payload = $('<td />').addClass('flow-payload')
    payload.append(icon_view)
    payload.append(icon_download)

    if (flow.tls == true) {
        payload.append("<img class='ssl-smiley' alt='SSL added and removed here!' src='/static/custom_img/ssl.png' />")
    }

    row.append(payload)

    // YARA matches
    icon_yara = $("<i />").addClass('icon-flag');
    matching_rules = []
    for (var i in flow.yara_matches) {
        matching_rules.push(i)
    }
    if (matching_rules.length > 0) {
        icon_yara.tooltip({ 'title': matching_rules.join(', '), 'container': 'body'})
        yara = $('<td />').append(icon_yara)
    }
    else { yara = $('<td />') }

    row.append(yara)

    return row
}

function get_flow_payload(id) {
    sendmessage(ws_sniffer, {'cmd': 'get_flow_payload', 'session_id': $('#session_id').text(), 'flowid': id})
}

function snifferInterfaceInit() {
    sendmessage(ws_sniffer, {'cmd': 'sniffstatus', 'session_id': $('#session_id').text()});
    sendmessage(ws_sniffer, {'cmd': 'flowstatus', 'session_id': $('#session_id').text()});
}

function startsniff(){
    session_id = $('#session_id').text()
    sendmessage(ws_sniffer, {'cmd': 'sniffstart', 'session_id': session_id})
    $('#startsniff').attr('disabled','true')
}

function stopsniff() {
    session_id = $('#session_id').text()
    sendmessage(ws_sniffer, {'cmd': 'sniffstop', 'session_id': session_id})
    $('#stopsniff').attr('disabled','true')
}

function delsniff(session_id) {
    r = confirm("Are you sure you want to remove session "+session_id+" and all of its data?")
    if (r == false) {return}
    $.ajax({
        type: 'get',
        url: url_static_prefix+'api/sniffer/delete/'+session_id,
        success: function(data) {
            if (data.success == 1) { // delete the corresponding row
                $("#session-"+session_id).remove()
            }

            display_message(data.status)
        }
    });
}

function display_message(text) {
  message = $('<div class="alert alert-warning"><button type="button" class="close" data-dismiss="alert">×</button>'+text+'</div>')
  $("#message").empty()
  $("#message").append(message)
}


function getSessionList(private) {
    console.log("Requesting session list")
    url = url_static_prefix+'api/sniffer/list/?user'
    if (private) {
        url += "&private"
    }
    $.ajax({
        type: 'get',
        url: url,
        accepts: 'application/json',
        success: function(data) {
            table = $('#sessions');
            console.log(data)
            for (var i in data.session_list) {
                    id = data.session_list[i].id
                    name = data.session_list[i]['name']
                    public = data.session_list[i]['public'] ? "Yes" : "No"

                    session_links = $('<a />').attr("href", url_static_prefix+'sniffer/'+id).text(name);
                    tr = $('<tr></tr>').attr('id', 'session-'+id);
                    d = new Date(data.session_list[i]['date_created'].$date)
                    // tr.append($("<td />").text(format_date(data.session_list[i]['date_created'])));
                    tr.append($("<td />").text(format_date(d, false)));
                    tr.append($("<td />").append(session_links));
                    tr.append($("<td />").text(data.session_list[i]['packets']));
                    tr.append($("<td />").text(data.session_list[i]['nodes']));
                    tr.append($("<td />").text(data.session_list[i]['edges']));
                    tr.append($("<td />").text(data.session_list[i]['status']));
                    tr.append($("<td />").text(public));
                    del = $("<td />")
                    if (private) {
                        i = $('<span class="glyphicon glyphicon-remove"></span>').data('session-id', id)
                        del.append(i)
                        i.click(function () { delsniff($(this).data('session-id')) })
                        tr.append(del)
                    }
                    table.append(tr);
                }
            }
        });
}

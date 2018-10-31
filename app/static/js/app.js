$(document).ready(function(){
    var socket = io.connect("http://" + document.domain +':' + location.port + '/test');
    var received_data = []

    socket.on("newdata", function(msg){
        var packet = msg.data;
        console.log("Received data" + packet);

        var new_record = '';

        if (packet.protocol == 'HTTP') {
            new_record = '<tr class="success">';
        }else if (packet.protocol == 'TCP') {
            new_record = '<tr class="info">';
        }else if (packet.protocol == 'UDP'){
            new_record = '<tr class="warning">';
        }

        new_record += '<td class="number">' + 1 + '</td>';
        new_record += '<td>' + 'time' + '</td>';
        new_record += '<td>' + 'packet.delta' + '</td>';
        new_record += '<td>' + packet.src_ip + '</td>';
        new_record += '<td>' + packet.dst_ip + '</td>';
        new_record += '<td>' + packet.protocol + '</td>';
        new_record += '<td>' + packet.length + '</td>';
        new_record += '</tr>';

        $('#packet_container').append(new_record);
    });

    socket.on('error', function(err){
        console.log(err);
    })
});
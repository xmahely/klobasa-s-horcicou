$(document).ready(function(){
    //connect to the socket server.

    // var socket = io.connect('http://' + document.domain + ':' + location.port + '/test');
    let socket = io.connect(document.domain + ':' + location.port);


    socket.on('load_time', function(msg) {
        $('.valid_to').each(function(){
            let valid_to = $(this).text();
            let id = ('#time'+valid_to).replace(/\s+/g, '-').replace(/:\s*/g, '-');
            let diff =  new Date(valid_to) - new Date(msg.time);
            let status;
            if (diff < 0) {
                status = "Inactive"
                $(id).removeClass("text-success");
                $(id).addClass("text-secondary");
            } else{
                let seconds = Math.floor(diff/1000); //ignore any left over units smaller than a second
                let minutes = Math.floor(seconds/60);
                seconds = seconds % 60;
                let hours = Math.floor(minutes/60);
                minutes = minutes % 60;
                let duration = hours.toString().padStart(2, "0") + ":" + minutes.toString().padStart(2, "0") + ":"
                    + seconds.toString().padStart(2, "0");
                status = " Active for " + duration
                $(id).addClass("text-success");
                $(id).removeClass("text-secondary");
            }
             $(id).html(status);
        });
    })
})
require(["jquery", "poll"], function($, poll) {
    //$.noConflict(true);

    var RATE_LIMIT_MS = 2000;
    var poller = poll.Poller("accumulator.json", RATE_LIMIT_MS, jsonLoaded);

    function main() {
        poller.start();
    }

    var jel = function(e) { return $(document.createElement(e)); }
    var td = function(text) { return jel("td").text(text); }

    function jsonLoaded(data) {
        var a = data["ip_by_address_pair"];
        var l = a.length;
        console.log("len " + l);
        var i;
        var tbody = $("#by_ip");
        tbody.html("")
        console.log("body: " + tbody);
        for(i = 0; i < l; ++i) {
            console.log("i is " + i);
            var c = a[i];
            var td1 = td(c["high-address"] + "<->" + c["low-address"]);
            var td2 = td("");
            var td3 = td("");
            tbody.append($("<tr>"), td1, td2, td3);
        }
    }

    $(document).ready(main);
});



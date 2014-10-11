require(["jquery", "poll", "protocol_view", "route"],
        function($, poll, protocol_view, route) {
    //$.noConflict(true);

    var RATE_LIMIT_MS = 2000;
    var poller = poll.Poller("accumulator.json", RATE_LIMIT_MS, jsonLoaded);
    var router = route.Router();

    router.add("protocol", function(p) {
        console.log("protocol");
    });

    $(window).bind("popstate", function(e) {
        router.route(window.location.hash);
    });

    function main() {
        poller.start(); 
    }

    var jel = function(e) { return $(document.createElement(e)); }
    var td = function(text) { return jel("td").text(text); }

    function jsonLoaded(data) {
/*
var a = data["ip_by_address_pair"];
        var l = a.length;
        console.log("len " + l);
        var i;
        var tbody = $("#by_ip");
        tbody.html("")
        for(i = 0; i < l; ++i) {
            var c = a[i];
            var td1 = td(c["high-address"] + "<->" + c["low-address"]);
            var td2 = td("");
            var td3 = td("");
            tbody.append($("<tr>"), td1, td2, td3);
        }
*/

        var d = accumulatorObjToProtocolViewObj(data);
        var body = $("#main-view");
        var pv = protocol_view.View();
        var d = { "title": "My Title" };
        body.html(pv.renderHTML(d));
    }

    /* There are 2 types of protocols: protocols that can envelop other protocols
       and those that cannot. Only enveloping protocols have addresses and packet names. */
    var ui_protocol = {
        ethernet: {
            name: "Ethernet",
            enveloped_protocol: "EtherType",
            address: "MAC Address",
            packet: "Frame"
        },
        ipv4: {
            name: "IPv4",
            address: "IPv4 Address",
            packet: "Packet",
            enveloped_protocol: "Protocol"
        },
        ipv6: {
            name: "IPv6",
            address: "IPv6 Address",
            packet: "Packet",
            enveloped_protocol: "Protocol"
        },
        arp: {
            name: "ARP"
        }
    }

    function accumulatorObjToProtocolViewObj(data) {
        var d = {};

    }

    $(document).ready(main);
});



require(["jquery", "poll"], function($, poll) {
    // $.noConflict(true);

    var RATE_LIMIT_MS = 2000;
    var poller = poll.Poller("accumulator.json", RATE_LIMIT_MS, jsonLoaded);

    function main() {
        poller.start();
    }

    function jsonLoaded(data, status, jqXHR) {
        console.log("JSON data loaded: " + data);
    }

    $(document).ready(main);
});



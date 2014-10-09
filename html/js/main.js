require(["jquery", "poll"], function($, poll) {
    // $.noConflict(true);

    var RATE_LIMIT_MS = 2000;

    function jsonLoaded(data, status, jqXHR) {
        console.log("JSON data loaded: " + data);
    }

    function main() {
        poll.getJSONLimit("accumulator.json", RATE_LIMIT_MS, jsonLoaded);
    }

    $(document).ready(main);
});



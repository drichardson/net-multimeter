define("poll", ["jquery"], function($) {
    var poll = {};


    // could either take a callback
    // or return a deferred whose progress is called whenever a JSON object is received
    // or poll forever without stopping
    // or return an object that allows user to cancel

    // returns a Deferred object whose progress calback is made each time a JSON
    // object is retrieved.
    var lastTime;
    poll.getJSONLimit = function(url, limit_ms, callback) {
        var thisTime = (new Date).getTime();
        if (typeof lastTime !== "undefined") {
            console.log("this: " + thisTime + ", last: " + lastTime + ", diff: " + (thisTime - lastTime));
        }
        lastTime = thisTime;
        var requestComplete = $.Deferred()
        var jsonRequest = $.getJSON(url)
            .done(callback)
            .always(function () { console.log("req always"); requestComplete.resolve(); });

        var rateLimitTimeout = $.Deferred();
        setTimeout(function() { console.log("TO"); rateLimitTimeout.resolve(); }, limit_ms);

        $.when(requestComplete, rateLimitTimeout).always(function() {
            poll.getJSONLimit(url, limit_ms, callback);
        });

    };

    return poll;
});

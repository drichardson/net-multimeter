define("poll", ["jquery"], function($) {
    var poll = {};

    poll.Poller = function(url, limit_ms, callback) {
        var r = {};
        r.cancelled = false;
        r.started = false;
        r._lastReq = null;

        r.start = function() {
            if (r.started) {
                console.warn("Already started request to url " + url + ". Ignoring.");
                return;
            }
            r.started = true;
            r.cancelled = false;            
            r._runOnce(url, limit_ms, callback);
        }

        r.cancel = function() {
            r.cancelled = true;
            r.started = false;
            var req = r._lastReq;
            r._lastReq = null;
            if (req) {
                req.abort();
            }
        }

        r._runOnce = function(url, limit_ms, callback) {
            /*
            var thisTime = (new Date).getTime();
            if (typeof r.lastTime !== "undefined") {
                console.log("this: " + thisTime + ", last: " + r.lastTime + ", diff: " + (thisTime - r.lastTime));
            }
            r.lastTime = thisTime;
            */

            var requestComplete = $.Deferred();
            r._lastReq = $.getJSON(url).done(callback).always(function () { requestComplete.resolve(); });

            var rateLimitTimeout = $.Deferred();
            setTimeout(rateLimitTimeout.resolve, limit_ms);

            $.when(requestComplete, rateLimitTimeout).always(function() {
                if (!r.cancelled) {
                    r._runOnce(url, limit_ms, callback);
                }
            });
        }
        
        return r;
    }

    return poll;
});

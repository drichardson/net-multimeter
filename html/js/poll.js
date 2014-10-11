define("poll", ["jquery"], function($) {
    var poll = {};

    poll.Poller = function(url, limit_ms, callback) {
        var r = {};
        r.cancelled = false;
        r.started = false;
        r._lastReq = null;

        r.start = function() {
            if (this.started) {
                console.warn("Already started request to url " + url + ". Ignoring.");
                return;
            }
            this.started = true;
            this.cancelled = false;            
            _runOnce(this, url, limit_ms, callback);
        }

        r.cancel = function() {
            this.cancelled = true;
            this.started = false;
            var req = this._lastReq;
            this._lastReq = null;
            if (req) {
                req.abort();
            }
        }

        function _runOnce(r, url, limit_ms, callback) {
            /*
            var thisTime = $.now();
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
                    _runOnce(r, url, limit_ms, callback);
                }
            });
        }
        
        return r;
    }

    return poll;
});

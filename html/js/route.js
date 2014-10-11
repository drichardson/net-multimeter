/*
   Route hash strings (e.g., #test, #test2/1?k=v&k2=v%202) to function calls.
   To use, call "add" to add routes. For example:
   // assumes you've used AMD to load this module as "route".
   var router = route.Router();
   router.add("test", function(queryParameters) {
       console.log("Param X is " + queryParameters["x"]);
    });
   
   Then, in your browsers onpopstate event
   call "route" with window.location.hash. For example, with jQuery:
     $(window).bind("popstate", function(e) {
        router.route(window.location.hash);
    });
    */
define(function() {
    var API = {};

    API.Router = function() {
        var O = {};
        var routes = {};

        O.onNotFound = function(hash) {
            console.warn("Route not found: " + hash);
        }

        O.add = function(hash, fn) {
            routes[hash] = fn;
        }

        O.route = function(hash) {
            var p = parseHash(hash);
            var fn = routes[p.hash] || this.onNotFound;
            fn.call(this, p.params);
        }

        function parseHash(hash) {
            var i = hash.indexOf("?");
            var r = {};
            if (i != -1) {
                r.hash = hash.substr(1, i-1); // skip #
                var pairs = hash.substr(i+1).split("&");
                var l = pairs.length;
                var params = {};
                for(var i = 0; i < l; ++i) {
                    var pair = pairs[i].split("=");
                    var key = decodeURIComponent(pair[0]);
                    var value = decodeURIComponent(pair[1]);
                    params[key] = value;
                }
                r.params = params;

            } else {
                r.hash = hash.substr(1); // skip #
                r.params = {};
            }
            return r;
        }

        return O;
    } 

    return API;
});

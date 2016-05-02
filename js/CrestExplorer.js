/**
 * Created by RZN on 5/2/2016.
 */

(function ($, window, document) {

    var redirectUri = "http://crestexplorer.ffevo.net";
    var clientId = "23b1b58dd7c841ab948beafee4b74439"; // OAuth client id
    var csrfTokenName = clientId + "csrftoken";
    var hashTokenName = clientId + "hash";
    var scopes = "publicData characterAccountRead characterAssetsRead characterFittingsRead characterFittingsWrite characterKillsRead characterLocationRead characterMailRead characterMarketOrdersRead characterNavigationWrite characterSkillsRead characterWalletRead fleetRead fleetWrite";
    var baseURL = "https://crest-tq.eveonline.com";
    var last = baseURL;
    var current = baseURL;

    // Request uri and render as HTML.
    function renderUri(uri) {
        if (uri.indexOf(baseURL) !== 0) {
            displayError("Bad domain");
            return;
        }
        last = current;
        current = uri;
        $("#srch-term").val(current);
        $("#main").hide();
        $("#loading").show();
        $.getJSON(uri, function(data, status, xhr) {
            $("#main").contents().replaceWith(jsonToHTML(data));
            $("#loading").hide();
            $("#main").show();
        });
    }

    function displayError(error, message) {
        $("#loading").hide();
        alert(error + ' : ' + message );
    }

    // Extract value from oauth formatted hash fragment.
    function extractFromHash(name, hash) {
        var match = hash.match(new RegExp(name + "=([^&]+)"));
        return !!match && match[1];
    }

    // Generate an RFC4122 version 4 UUID
    function uuidGen() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            var r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
            return v.toString(16);
        });
    }

    function ajaxSetup(token) {
        var headers = {
            "Accept": "application/json, charset=utf-8"
        };
        if (token) {
            headers.Authorization = "Bearer " + token;
        }
        if ($.cookie('market-language')) {
            headers['Accept-Language'] = $.cookie('market-language');
        }
        $.ajaxSetup({
            accepts: "application/json, charset=utf-8",
            crossDomain: true,
            type: "GET",
            dataType: "json",
            headers: headers,
            error: function (xhr, status, error) {
                displayError(error, xhr.responseJSON['message']);
            }
        });
    }


    $(document).ready(function() {

        var hash = window.location.hash;
        var token = extractFromHash("access_token", hash);

        if (token) {

            // Check CSRF token in state matches token saved in cookie
            if(extractFromHash("state", hash) !== $.cookie(csrfTokenName)) {
                displayError("CSRF token mismatch");
                return;
            }

            // Restore hash.
            window.location.hash = $.cookie(hashTokenName);

            // Delete cookies.
            $.cookie(csrfTokenName, null);
            $.cookie(hashTokenName, null);
            //$("#crestNavMain").show();
            renderUri(baseURL);
        } else {

            //$("#crestNavMain").hide();
            // Store CSRF token and current location as cookie
            var csrfToken = uuidGen();
            $.cookie(csrfTokenName, csrfToken);
            $.cookie(hashTokenName, window.location.hash);

            // No OAuth token, request one from the OAuth authentication endpoint
            window.location =  "https://login.eveonline.com/oauth/authorize/" +
                "?response_type=token" +
                "&client_id=" + clientId +
                "&scope=" + scopes +
                "&redirect_uri=" + redirectUri +
                "&state=" + csrfToken;
        }

        $("#btnBack").on("click", function (e) {
            e.stopImmediatePropagation();
            e.preventDefault();
            renderUri(last);
            return false;
        });

        $("#btnSubmit").on("click", function (e) {
            e.stopImmediatePropagation();
            e.preventDefault();
            renderUri($("#srch-term").val());
            return false;
        });

        $("#srch-term").keydown(function(e) {
            var code = (e.keyCode ? e.keyCode : e.which);
            if (code == 13) {
                e.preventDefault();
                e.stopPropagation();
                renderUri($("#srch-term").val());
            }
        });

        $("#btnHome").on("click", function (e) {
            e.stopImmediatePropagation();
            e.preventDefault();
            renderUri(baseURL);
            return false;
        });

        $("#main").on("click","a", function(e){
            e.stopImmediatePropagation();
            e.preventDefault();
            renderUri($(this).attr("href"));
            return false;
        });

        ajaxSetup(token);
    });

    function htmlEncode(t) {
        return t != null ? t.toString().replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;") : '';
    }

    function decorateWithSpan(value, className) {
        return '<span class="' + className + '">' + htmlEncode(value) + '</span>';
    }

    function valueToHTML(value) {
        var valueType = typeof value, output = "";
        if (value == null)
            output += decorateWithSpan("null", "type-null");
        else if (value && value.constructor == Array)
            output += arrayToHTML(value);
        else if (valueType == "object")
            output += objectToHTML(value);
        else if (valueType == "number")
            output += decorateWithSpan(value, "type-number");
        else if (valueType == "string")
            if (/^(http|https):\/\/[^\s]+$/.test(value))
                output += decorateWithSpan('"', "type-string") + '<a href="' + value + '">' + htmlEncode(value) + '</a>' + decorateWithSpan('"', "type-string");
            else
                output += decorateWithSpan('"' + value + '"', "type-string");
        else if (valueType == "boolean")
            output += decorateWithSpan(value, "type-boolean");

        return output;
    }

    function arrayToHTML(json) {
        var i, length, output = '<div class="collapser"></div>[<span class="ellipsis"></span><ul class="array collapsible">', hasContents = false;
        for (i = 0, length = json.length; i < length; i++) {
            hasContents = true;
            output += '<li><div class="hoverable">';
            output += valueToHTML(json[i]);
            if (i < length - 1)
                output += ',';
            output += '</div></li>';
        }
        output += '</ul>]';
        if (!hasContents)
            output = "[ ]";
        return output;
    }

    function objectToHTML(json) {
        var i, key, length, keys = Object.keys(json), output = '<div class="collapser"></div>{<span class="ellipsis"></span><ul class="obj collapsible">', hasContents = false;
        for (i = 0, length = keys.length; i < length; i++) {
            key = keys[i];
            hasContents = true;
            output += '<li><div class="hoverable">';
            output += '<span class="property">' + htmlEncode(key) + '</span>: ';
            output += valueToHTML(json[key]);
            if (i < length - 1)
                output += ',';
            output += '</div></li>';
        }
        output += '</ul>}';
        if (!hasContents)
            output = "{ }";
        return output;
    }

    function jsonToHTML(json, fnName) {
        var output = '';
        if (fnName)
            output += '<div class="callback-function">' + fnName + '(</div>';
        output += '<div id="json">';
        output += valueToHTML(json);
        output += '</div>';
        if (fnName)
            output += '<div class="callback-function">)</div>';
        return output;
    }
}($, window, document));
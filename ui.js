(function () {
    function oauthParameters() {
        var self = this;
        var fields = ko.observableArray([]);
        var headers = ko.observableArray([]);

        self.parameters = {
            method: ko.observable('GET'),
            url: ko.observable(''),
            consumerKey: ko.observable(''),
            consumerSecret: ko.observable(''),
            token: ko.observable(''),
            tokenSecret: ko.observable(''),
            nonce: ko.observable(''),
            timestamp: ko.observable(''),
            version: ko.observable('1.0'),
            body: ko.observable(''),
            bodyEncoding: ko.observable('application/json'),
            curlParameters: {
                output: ko.observable(''),
                verbose: ko.observable(false)
            },
            actualUrl: ko.observable(''),
            addField: function () {
                fields.push({
                    name: ko.observable(''),
                    value: ko.observable('')
                });
            },
            fields: fields,
            removeField: function () { return fields.remove(this); },
            addHeader: function () {
                headers.push({
                    name: ko.observable(''),
                    value: ko.observable('')
                });
            },
            headers: headers,
            removeHeader: function () { return headers.remove(this); }
        };

        self.refreshTimestamp = function () {
            var nowInSeconds = Math.floor((new Date()).getTime() / 1000);
            return self.parameters.timestamp(nowInSeconds);
        };

        self.newNonce = function () {
            var nonce = Math.floor(Math.random() * 1e9);
            return self.parameters.nonce(nonce);
        };

        self.refreshTimestamp();
        self.newNonce();

        self.methodOptions = ko.observableArray([ 'GET', 'POST', 'PUT', 'DELETE', 'HEAD' ]);
        self.encodingOptions = ko.observableArray([ 'application/json', 'application/xml' ]);
        self.oauthSignature = ko.computed(function () {
            return oauthSigner(self.parameters);
        });
        self.signature = {
            queryString: ko.computed(function () {
                return self.oauthSignature().queryString();
            }),
            baseString: ko.computed(function () {
                return self.oauthSignature().baseString();
            }),
            hmacKey: ko.computed(function () {
                return self.oauthSignature().hmacKey();
            }),
            base64Signature: ko.computed(function () {
                return self.oauthSignature().base64Signature();
            }),
            signature: ko.computed(function () {
                return self.oauthSignature().signature();
            }),
            authorizationHeader: ko.computed(function () {
                return self.oauthSignature().authorizationHeader();
            }),
            signedUrl: ko.computed(function () {
                return self.oauthSignature().signedUrl();
            }),
            prettySignedUrl: ko.computed(function () {
                var url = self.parameters.url()
                if (self.parameters.actualUrl()) {
                  url = self.parameters.actualUrl()
                }
                return self.parameters.method() + ' ' + url.substring(0, 60) + '?...';
            }),
            curl: ko.computed(function () {
                return self.oauthSignature().curl();
            })
        };
    };
    window.oauthPage = new oauthParameters();
    ko.applyBindings(oauthPage);
}).call(this);

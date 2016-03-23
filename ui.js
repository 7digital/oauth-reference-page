((function() {
    var oauthParameters = function() {
        var self, fieldsArray;
        self = this;
        self.timestampForNow = function() {
            return Math.floor((new Date).getTime() / 1e3);
        };
        fieldsArray = ko.observableArray([]);
        self.parameters = {
            method: ko.observable("GET"),
            url: ko.observable(""),
            consumerKey: ko.observable(""),
            consumerSecret: ko.observable(""),
            token: ko.observable(""),
            tokenSecret: ko.observable(""),
            nonce: ko.observable(""),
            timestamp: ko.observable(""),
            version: ko.observable("1.0"),
            body: ko.observable(""),
            bodyEncoding: ko.observable("application/json"),
            curlParameters: {
                output: ko.observable(""),
                verbose: ko.observable(false)
            },
            fields: ko.observable,
            addField: function() {
                return fieldsArray.push({
                    value: ko.observable(""),
                    name: ko.observable("")
                });
            },
            fieldsArray: fieldsArray,
            removeField: function() {
                return fieldsArray.remove(this);
            },
            fields: ko.computed(function() {
                var fieldsToReturn, observedFormFields, fieldIndex;
                fieldsToReturn = {};
                observedFormFields = fieldsArray();
                for (fieldIndex = 0; fieldIndex < observedFormFields.length; fieldIndex++) {
                    var field = observedFormFields[fieldIndex];
                    if (field.name()) {
                        fieldsToReturn[field.name()] = field.value();
                    }
                }
                return fieldsToReturn;
            })
        };
        self.refreshTimestamp = function() {
            var self;
            self = this;
            return self.parameters.timestamp(self.timestampForNow());
        };
        self.refreshTimestamp();
        self.newNonce = function() {
            var self;
            self = this;
            return self.parameters.nonce(Math.floor(Math.random() * 1e9).toString());
        };
        self.newNonce();
        self.methodOptions = ko.observableArray([ "GET", "POST", "PUT", "DELETE", "HEAD" ]);
        self.encodingOptions = ko.observableArray([ "application/json", "application/xml" ]);
        self.oauthSignature = ko.computed(function() {
            return oauthSigner(self.parameters);
        });
        self.signature = {
            queryString: ko.computed(function() {
                return self.oauthSignature().queryString();
            }),
            baseString: ko.computed(function() {
                return self.oauthSignature().baseString();
            }),
            hmacKey: ko.computed(function() {
                return self.oauthSignature().hmacKey();
            }),
            base64Signature: ko.computed(function() {
                return self.oauthSignature().base64Signature();
            }),
            signature: ko.computed(function() {
                return self.oauthSignature().signature();
            }),
            authorizationHeader: ko.computed(function() {
                return self.oauthSignature().authorizationHeader();
            }),
            signedUrl: ko.computed(function() {
                return self.oauthSignature().signedUrl();
            }),
            prettySignedUrl: ko.computed(function() {
                return self.parameters.method() + " " + self.parameters.url() + "?...";
            }),
            curl: ko.computed(function() {
                return self.oauthSignature().curl();
            })
        };
    };
    window.oauthPage = new oauthParameters;
    ko.applyBindings(oauthPage);
})).call(this);
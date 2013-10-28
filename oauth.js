((function() {
    window.oauthSigner = function(parameters) {
	    var oauthSignerOld = window.oauthSignerOld(parameters);
        return _.extend({
            token: function() {
                return "";
            },
            tokenSecret: function() {
                return "";
            },
            version: function() {
                return "1.0";
            },
            signatureMethod: function() {
                return "HMAC-SHA1";
            },
            method: function() {
                return "GET";
            },
            timestamp: function() {
                return Math.floor((new Date).getTime() / 1e3);
            },
            fields: function() {
                return {};
            },
            queryString: function() {
                var queryArguments, orderedFields;
                queryArguments = oauthSignerOld.queryStringFields();
                orderedFields = _.keys(queryArguments).sort();
                return _.map(orderedFields, function(fieldName) {
                    return fieldName + "=" + oauthSignerOld.percentEncode(queryArguments[fieldName]);
                }).join("&");
            },
            authorizationHeader: function() {
                var self, fields;
                self = this;
                fields = oauthSignerOld.oauthParameters();
                fields["oauth_signature"] = self.base64Signature();
                return oauthSignerOld.headerEncoded(fields);
            },
            baseString: function() {
                var self;
                self = this;
                return oauthSignerOld.parameterEncoded([ self.method(), self.url(), self.queryString() ]);
            },
            hmacKey: function() {
                var self;
                self = this;
                return oauthSignerOld.parameterEncoded([ self.consumerSecret(), self.tokenSecret() ]);
            },
            base64Signature: function() {
                return oauthSignerOld.hmac({
                    encoding: "base64"
                });
            },
            signature: function() {
                var self;
                self = this;

	            // var signatureNew = oauthSignature.generate(self.method(), self.url(), self.queryString(), self.consumerSecret(), self.tokenSecret());
	            var signatureNew = oauthSignature.generate(self.method(), self.url(), oauthSignerOld.queryStringFields(), self.consumerSecret(), self.tokenSecret());
	            var signatureOld = oauthSignerOld.percentEncode(oauthSignerOld.base64Signature());

	            var baseStringNew = new oauthSignature.SignatureBaseString(self.method(), self.url(), oauthSignerOld.queryStringFields()).generate();
	            var baseStringOld = self.baseString();

	            console.log('New signature: ' + signatureNew);
	            console.log('Old signature: ' + signatureOld);

	            console.log('New base string: ' + baseStringNew);
	            console.log('Old base string: ' + baseStringOld);

	            if (signatureNew != signatureOld) {
		            throw new Error('The signatures are different');
	            }

                return signatureNew;
            },
            signedUrl: function() {
                var self;
                self = this;
                return self.url() + "?" + self.queryString() + "&oauth_signature=" + self.signature();
            },
            curl: function() {
                var self;
                self = this;
                if (self.method() === "GET") {
                    return "curl '" + self.url() + "?" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                } else if (self.method() === "POST" || self.method() === "PUT") {
                    if (self.body()) {
                        return "curl -X " + self.method() + " '" + oauthSignerOld.urlAndFields() + "' -d '" + self.body() + "' -H 'Authorization: " + self.authorizationHeader() + "' -H 'Content-Type: " + self.bodyEncoding() + "'";
                    } else {
                        return "curl -X " + self.method() + " '" + self.url() + "' -d '" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                    }
                } else {
                    return "curl -X DELETE '" + self.url() + "?" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                }
            }
        }, parameters);
    };
})).call(this);
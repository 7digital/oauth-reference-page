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
	        oauthParameters: function() {
		        var queryFields;
		        queryFields = {
			        oauth_consumer_key: this.consumerKey(),
			        oauth_nonce: this.nonce(),
			        oauth_timestamp: this.timestamp(),
			        oauth_signature_method: this.signatureMethod()
		        };
		        if (this.token()) {
			        queryFields["oauth_token"] = this.token();
		        }
		        if (this.version()) {
			        queryFields["oauth_version"] = this.version();
		        }
		        return queryFields;
	        },
	        parameters: function() {
		        var parameters, fields;
		        parameters = this.oauthParameters();
		        fields = this.fields();
		        _.each(_.keys(fields), function(field) {
			        return parameters[field] = fields[field];
		        });
		        return parameters;
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
                var fields;
                fields = oauthSignerOld.oauthParameters();
                fields["oauth_signature"] = this.base64Signature();
                return oauthSignerOld.headerEncoded(fields);
            },
            baseString: function() {
	            return new oauthSignature.SignatureBaseString(this.method(), this.url(), this.parameters())
		            .generate();
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

	            var signatureNew = oauthSignature.generate(this.method(), this.url(), this.parameters(),
	                                                       this.consumerSecret(), this.tokenSecret());
	            var signatureOld = oauthSignerOld.encodedBase64Signature();

	            console.info('New signature: ' + signatureNew);
	            console.info('Old signature: ' + signatureOld);

	            if (baseStringNew != baseStringOld) {
		            console.warn('WARNING: The base strings are different');
	            }

	            var baseStringNew =this.baseString();
	            var baseStringOld = oauthSignerOld.baseString();

	            console.info('New base string: ' + baseStringNew);
	            console.info('Old base string: ' + baseStringOld);

	            if (signatureNew != signatureOld) {
		            console.warn('WARNING: The signatures are different');
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

                var curlCommand = "";
                if (self.method() === "GET") {
                    curlCommand = "curl '" + self.url() + "?" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                } else if (self.method() === "POST" || self.method() === "PUT") {
                    if (self.body()) {
                        curlCommand = "curl -X " + self.method() + " '" + oauthSignerOld.urlAndFields() + "' -d '" + self.body() + "' -H 'Authorization: " + self.authorizationHeader() + "' -H 'Content-Type: " + self.bodyEncoding() + "'";
                    } else {
                        curlCommand = "curl -X " + self.method() + " '" + self.url() + "' -d '" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                    }
                } else {
                    curlCommand = "curl -X " + self.method() + " '" + self.url() + "?" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
                }
                if (parameters.curlParameters.output()) {
                    curlCommand += ' -o ' + parameters.curlParameters.output();
                }

                if (parameters.curlParameters.verbose()) {
                    curlCommand += ' -v';
                }

                if (parameters.headersArray().length > 0) {
                    parameters.headersArray().forEach(function(header) {
                        if (header.name()) {
                            curlCommand += ' -H "' + header.name();
                            if (header.value()) {
                              curlCommand += ':' + header.value();  
                            }   
                            curlCommand += '"';
                        }
                    })
                }
                return curlCommand;
            }
        }, parameters);
    };
})).call(this);
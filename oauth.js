(function () {
    window.oauthSigner = function (parameters) {
        return {
            signatureMethod: function () { return 'HMAC-SHA1'; },
            oauthParameters: function () {
                var params = {
                    oauth_consumer_key: parameters.consumerKey(),
                    oauth_nonce: parameters.nonce(),
                    oauth_timestamp: parameters.timestamp(),
                    oauth_signature_method: this.signatureMethod()
                };
                if (parameters.token()) {
                    params['oauth_token'] = parameters.token();
                }
                if (parameters.version()) {
                    params['oauth_version'] = parameters.version();
                }
                return params;
            },
            fields: function () {
                var fields = parameters.fields().reduce(function (fields, field) {
                    if (field.name()) {
                        fields[field.name()] = field.value();
                    }
                    return fields;
                }, {});
                return _.extend(this.oauthParameters(), fields);
            },
            percentEncode: function (s) {
                return encodeURIComponent(s).replace(/\*/g, '%2A');
            },
            queryString: function () {
                var self = this;
                var fields = this.fields();
                var fieldNames = _.keys(fields).sort();
                return fieldNames.map(function (name) {
                    return name + '=' + self.percentEncode(fields[name]);
                }).join('&');
            },
            headerEncoded: function (fields) {
                return _.keys(fields).map(function (key) {
                    return key + '="' + encodeURIComponent(fields[key]) + '"';
                }).join(", ");
            },
            authorizationHeader: function () {
                var fields = this.oauthParameters();
                fields['oauth_signature'] = this.base64Signature();
                return this.headerEncoded(fields);
            },
            baseString: function () {
                return new oauthSignature.SignatureBaseString(
                    parameters.method(),
                    parameters.url(),
                    this.fields()
                ).generate();
            },
            parameterEncoded: function (fields) {
                return fields.map(this.percentEncode).join('&');
            },
            hmacKey: function () {
                return this.parameterEncoded([
                    parameters.consumerSecret(),
                    parameters.tokenSecret()
                ]);
            },
            hmac: function (gen1_options) {
                var encoding = (gen1_options && gen1_options.encoding) || 'binary';
                var binaryHash = CryptoJS.HmacSHA1(this.baseString(), this.hmacKey());

                if (encoding === 'base64') {
                    return binaryHash.toString(CryptoJS.enc.Base64);
                }

                return binaryHash;
            },
            base64Signature: function () {
                return this.hmac({ encoding: 'base64' });
            },
            signature: function () {
                var signatureNew = oauthSignature.generate(
                    parameters.method(),
                    parameters.url(),
                    this.fields(),
                    parameters.consumerSecret(),
                    parameters.tokenSecret()
                );

                return signatureNew;
            },
            signedUrl: function () {
                var url = parameters.url()
                if (parameters.actualUrl()) {
                    url = parameters.actualUrl()
                }
                return url + '?' + this.queryString() + '&oauth_signature=' + this.signature();
            },
            urlEncoded: function (fields) {
                return _.keys(fields).map(function(key) {
                    return key + "=" + encodeURIComponent(fields[key]);
                }).join("&");
            },
            urlAndFields: function (url) {
                var encodedFields = this.urlEncoded(this.fields());
                return encodedFields ? url + '?' + encodedFields : url;
            },
            curl: function () {
                var url = parameters.url()
                if (parameters.actualUrl()) {
                    url = parameters.actualUrl()
                }

                var curlCommand = "";
                if (parameters.method() === "GET") {
                    curlCommand = "curl '" + url + "?" + this.queryString() + "&oauth_signature=" + this.signature() + "'";
                } else if (parameters.method() === "POST" || parameters.method() === "PUT") {
                    if (parameters.body()) {
                        curlCommand = "curl -X " + parameters.method() + " '" + this.urlAndFields(url) + "' -d '" + parameters.body() + "' -H 'Authorization: " + this.authorizationHeader() + "' -H 'Content-Type: " + parameters.bodyEncoding() + "'";
                    } else {
                        curlCommand = "curl -X " + parameters.method() + " '" + url + "' -d '" + this.queryString() + "&oauth_signature=" + this.signature() + "'";
                    }
                } else {
                    curlCommand = "curl -X " + parameters.method() + " '" + url + "?" + this.queryString() + "&oauth_signature=" + this.signature() + "'";
                }
                if (parameters.curlParameters.output()) {
                    curlCommand += ' -o ' + parameters.curlParameters.output();
                }

                if (parameters.curlParameters.verbose()) {
                    curlCommand += ' -v';
                }

                parameters.headers().forEach(function (header) {
                    if (header.name()) {
                        curlCommand += ' -H "' + header.name();
                        if (header.value()) {
                            curlCommand += ':' + header.value();
                        }
                        curlCommand += '"';
                    }
                });

                return curlCommand;
            }
        };
    };
}).call(this);

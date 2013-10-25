(function() {
	window.oauthSignerOld = function(parameters) {
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
			queryStringFields: function() {
				var queryFields, fields;
				queryFields = this.oauthParameters();
				fields = this.fields();
				_.each(_.keys(fields), function(field) {
					return queryFields[field] = fields[field];
				});
				return queryFields;
			},
			queryString: function() {
				var self, queryArguments, orderedFields;
				self = this;
				queryArguments = this.queryStringFields();
				orderedFields = _.keys(queryArguments).sort();
				return _.map(orderedFields, function(fieldName) {
					return fieldName + "=" + self.percentEncode(queryArguments[fieldName]);
				}).join("&");
			},
			urlEncoded: function(fields) {
				return _.map(_.keys(fields), function(fieldName) {
					return fieldName + "=" + encodeURIComponent(fields[fieldName]);
				}).join("&");
			},
			headerEncoded: function(fields) {
				return _.map(_.keys(fields), function(fieldName) {
					return fieldName + '="' + encodeURIComponent(fields[fieldName]) + '"';
				}).join(", ");
			},
			urlEncodedFields: function() {
				return this.urlEncoded(this.fields());
			},
			authorizationHeader: function() {
				fields = this.oauthParameters();
				fields["oauth_signature"] = this.base64Signature();
				return this.headerEncoded(fields);
			},
			urlAndFields: function() {
				var encodedFields;
				encodedFields = this.urlEncodedFields();
				if (encodedFields) {
					return this.url() + "?" + encodedFields;
				} else {
					return this.url();
				}
			},
			parameterEncoded: function(fields) {
				var self = this;
				return _.map(fields, function(field) {
					return self.percentEncode(field);
				}).join("&");
			},
			baseString: function() {
				return this.parameterEncoded([ this.method(), this.url(), this.queryString() ]);
			},
			hmacKey: function() {
				return this.parameterEncoded([ this.consumerSecret(), this.tokenSecret() ]);
			},
			hmac: function(gen1_options) {
				var encoding;
				encoding = gen1_options && gen1_options.hasOwnProperty("encoding") && gen1_options.encoding !== void 0 ? gen1_options.encoding : "binary";
				var binaryHash;
				binaryHash = CryptoJS.HmacSHA1(this.baseString(), this.hmacKey());
				if (encoding === "base64") {
					return binaryHash.toString(CryptoJS.enc.Base64);
				} else {
					return binaryHash;
				}
			},
			base64Signature: function() {
				return this.hmac({
					encoding: "base64"
				});
			},
			signature: function() {
				return oauthSignature.generate(this.method(), this.url(), this.queryStringFields(), this.consumerSecret(), this.tokenSecret());
			},
			signedUrl: function() {
				return this.url() + "?" + this.queryString() + "&oauth_signature=" + this.signature();
			},
			curl: function() {
				if (this.method() === "GET") {
					return "curl '" + this.url() + "?" + this.queryString() + "&oauth_signature=" + this.signature() + "'";
				} else if (this.method() === "POST" || this.method() === "PUT") {
					if (this.body()) {
						return "curl -X " + this.method() + " '" + this.urlAndFields() + "' -d '" + this.body() + "' -H 'Authorization: " + this.authorizationHeader() + "' -H 'Content-Type: " + this.bodyEncoding() + "'";
					} else {
						return "curl -X " + this.method() + " '" + this.url() + "' -d '" + this.queryString() + "&oauth_signature=" + this.signature() + "'";
					}
				} else {
					return "curl -X DELETE '" + this.url() + "?" + this.queryString() + "&oauth_signature=" + this.signature() + "'";
				}
			},
			percentEncode: function(s) {
				return encodeURIComponent(s).replace(/\*/g, "%2A");
			}
		}, parameters);
	};
}).call(this);
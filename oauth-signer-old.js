(function() {
	window.oauthSignerOld = function(parameters) {
		return _.extend({
			token: function() {
				var self;
				self = this;
				return "";
			},
			tokenSecret: function() {
				var self;
				self = this;
				return "";
			},
			version: function() {
				var self;
				self = this;
				return "1.0";
			},
			signatureMethod: function() {
				var self;
				self = this;
				return "HMAC-SHA1";
			},
			method: function() {
				var self;
				self = this;
				return "GET";
			},
			timestamp: function() {
				var self;
				self = this;
				return Math.floor((new Date).getTime() / 1e3);
			},
			fields: function() {
				var self;
				self = this;
				return {};
			},
			oauthParameters: function() {
				var self, queryFields;
				self = this;
				queryFields = {
					oauth_consumer_key: self.consumerKey(),
					oauth_nonce: self.nonce(),
					oauth_timestamp: self.timestamp(),
					oauth_signature_method: self.signatureMethod()
				};
				if (self.token()) {
					queryFields["oauth_token"] = self.token();
				}
				if (self.version()) {
					queryFields["oauth_version"] = self.version();
				}
				return queryFields;
			},
			queryStringFields: function() {
				var self, queryFields, fields;
				self = this;
				queryFields = self.oauthParameters();
				fields = self.fields();
				_.each(_.keys(fields), function(field) {
					return queryFields[field] = fields[field];
				});
				return queryFields;
			},
			queryString: function() {
				var self, queryArguments, orderedFields;
				self = this;
				queryArguments = self.queryStringFields();
				orderedFields = _.keys(queryArguments).sort();
				return _.map(orderedFields, function(fieldName) {
					return fieldName + "=" + self.percentEncode(queryArguments[fieldName]);
				}).join("&");
			},
			urlEncoded: function(fields) {
				var self;
				self = this;
				return _.map(_.keys(fields), function(fieldName) {
					return fieldName + "=" + encodeURIComponent(fields[fieldName]);
				}).join("&");
			},
			headerEncoded: function(fields) {
				var self;
				self = this;
				return _.map(_.keys(fields), function(fieldName) {
					return fieldName + '="' + encodeURIComponent(fields[fieldName]) + '"';
				}).join(", ");
			},
			urlEncodedFields: function() {
				var self;
				self = this;
				return self.urlEncoded(self.fields());
			},
			authorizationHeader: function() {
				var self, fields;
				self = this;
				fields = self.oauthParameters();
				fields["oauth_signature"] = self.base64Signature();
				return self.headerEncoded(fields);
			},
			urlAndFields: function() {
				var self, encodedFields;
				self = this;
				encodedFields = self.urlEncodedFields();
				if (encodedFields) {
					return self.url() + "?" + encodedFields;
				} else {
					return self.url();
				}
			},
			parameterEncoded: function(fields) {
				var self;
				self = this;
				return _.map(fields, function(field) {
					return self.percentEncode(field);
				}).join("&");
			},
			baseString: function() {
				var self;
				self = this;
				return self.parameterEncoded([ self.method(), self.url(), self.queryString() ]);
			},
			hmacKey: function() {
				var self;
				self = this;
				return self.parameterEncoded([ self.consumerSecret(), self.tokenSecret() ]);
			},
			hmac: function(gen1_options) {
				var encoding, self;
				encoding = gen1_options && gen1_options.hasOwnProperty("encoding") && gen1_options.encoding !== void 0 ? gen1_options.encoding : "binary";
				self = this;
				var binaryHash;
				binaryHash = CryptoJS.HmacSHA1(self.baseString(), self.hmacKey());
				if (encoding === "base64") {
					return binaryHash.toString(CryptoJS.enc.Base64);
				} else {
					return binaryHash;
				}
			},
			base64Signature: function() {
				var self;
				self = this;
				return self.hmac({
					encoding: "base64"
				});
			},
			signature: function() {
				var self;
				self = this;

				return oauthSignature.generate(self.method(), self.url(), self.queryStringFields(), self.consumerSecret(), self.tokenSecret());
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
						return "curl -X " + self.method() + " '" + self.urlAndFields() + "' -d '" + self.body() + "' -H 'Authorization: " + self.authorizationHeader() + "' -H 'Content-Type: " + self.bodyEncoding() + "'";
					} else {
						return "curl -X " + self.method() + " '" + self.url() + "' -d '" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
					}
				} else {
					return "curl -X DELETE '" + self.url() + "?" + self.queryString() + "&oauth_signature=" + self.signature() + "'";
				}
			},
			percentEncode: function(s) {
				var self;
				self = this;
				return encodeURIComponent(s).replace(/\*/g, "%2A");
			}
		}, parameters);
	};
}).call(this);
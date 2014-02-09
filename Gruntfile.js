/*global module */

module.exports = function (grunt) {
	'use strict';

	grunt.initConfig({
		pkg : grunt.file.readJSON('package.json'),
		clean : {
			dist : [ 'dist' ]
		},
		concat : {
			options : {
				separator : '\n'
			},
			specs : {
				src : [
					'app/oauth-signature.js',
					'lib/cryptojs/hmac-sha1.js',
					'lib/cryptojs/enc-base64.min.js',
					'lib/url.min.js'
				],
				dest : 'dist/oauth-signature.js',
				nonull : true
			}
		},
		uglify : {
			dist : {
				files : {
					'dist/oauth-signature.min.js' : [ 'dist/oauth-signature.js' ]
				},
				options : {
					// sourceMap : '<%= cfg.dist.dir %>/pub.min.map.js';
				}
			}
		}
	});

	grunt.loadNpmTasks('grunt-contrib-clean');
	grunt.loadNpmTasks('grunt-contrib-concat');
	grunt.loadNpmTasks('grunt-contrib-uglify');

	grunt.registerTask('build', [ 'clean', 'concat', 'uglify' ]);

};

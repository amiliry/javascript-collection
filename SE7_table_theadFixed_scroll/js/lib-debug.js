/*!
 * SHINE JS Library 0.1.0
 * Copyright(c) shine.
 */
/*
 * jQuery MD5 Plugin 1.2.1
 * https://github.com/blueimp/jQuery-MD5
 *
 * Copyright 2010, Sebastian Tschan
 * https://blueimp.net
 *
 * Licensed under the MIT license:
 * http://creativecommons.org/licenses/MIT/
 * 
 * Based on
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*jslint bitwise: true */
/*global unescape, jQuery */
var MD5_ATTACH_STR = "shinetechnology";
function getCurrentDate() {
	var t = new Date();
	
	var str = t.getFullYear()+""  ;	
	str += t.getMonth() > 8 ? t.getMonth()+1 : "0"+(t.getMonth()+1);
	str += t.getDate() > 8 ? t.getDate() : "0"+t.getDate();
	str += t.getHours() > 8 ? t.getHours() : "0"+t.getHours();
	str += t.getMinutes() > 8 ? t.getMinutes() : "0"+t.getMinutes();
	str += t.getSeconds() > 8 ? t.getSeconds() : "0"+t.getSeconds();
	str += t.getMilliseconds();
	
	return str;
}
(function ($) {
    'use strict';

    /*
    * Add integers, wrapping at 2^32. This uses 16-bit operations internally
    * to work around bugs in some JS interpreters.
    */
    function safe_add(x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF),
            msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
    * Bitwise rotate a 32-bit number to the left.
    */
    function bit_rol(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
    * These functions implement the four basic operations the algorithm uses.
    */
    function md5_cmn(q, a, b, x, s, t) {
        return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
    }
    function md5_ff(a, b, c, d, x, s, t) {
        return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
    }
    function md5_gg(a, b, c, d, x, s, t) {
        return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
    }
    function md5_hh(a, b, c, d, x, s, t) {
        return md5_cmn(b ^ c ^ d, a, b, x, s, t);
    }
    function md5_ii(a, b, c, d, x, s, t) {
        return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
    }

    /*
    * Calculate the MD5 of an array of little-endian words, and a bit length.
    */
    function binl_md5(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << ((len) % 32);
        x[(((len + 64) >>> 9) << 4) + 14] = len;

        var i, olda, oldb, oldc, oldd,
            a =  1732584193,
            b = -271733879,
            c = -1732584194,
            d =  271733878;

        for (i = 0; i < x.length; i += 16) {
            olda = a;
            oldb = b;
            oldc = c;
            oldd = d;

            a = md5_ff(a, b, c, d, x[i],       7, -680876936);
            d = md5_ff(d, a, b, c, x[i +  1], 12, -389564586);
            c = md5_ff(c, d, a, b, x[i +  2], 17,  606105819);
            b = md5_ff(b, c, d, a, x[i +  3], 22, -1044525330);
            a = md5_ff(a, b, c, d, x[i +  4],  7, -176418897);
            d = md5_ff(d, a, b, c, x[i +  5], 12,  1200080426);
            c = md5_ff(c, d, a, b, x[i +  6], 17, -1473231341);
            b = md5_ff(b, c, d, a, x[i +  7], 22, -45705983);
            a = md5_ff(a, b, c, d, x[i +  8],  7,  1770035416);
            d = md5_ff(d, a, b, c, x[i +  9], 12, -1958414417);
            c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
            b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
            a = md5_ff(a, b, c, d, x[i + 12],  7,  1804603682);
            d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
            c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
            b = md5_ff(b, c, d, a, x[i + 15], 22,  1236535329);

            a = md5_gg(a, b, c, d, x[i +  1],  5, -165796510);
            d = md5_gg(d, a, b, c, x[i +  6],  9, -1069501632);
            c = md5_gg(c, d, a, b, x[i + 11], 14,  643717713);
            b = md5_gg(b, c, d, a, x[i],      20, -373897302);
            a = md5_gg(a, b, c, d, x[i +  5],  5, -701558691);
            d = md5_gg(d, a, b, c, x[i + 10],  9,  38016083);
            c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
            b = md5_gg(b, c, d, a, x[i +  4], 20, -405537848);
            a = md5_gg(a, b, c, d, x[i +  9],  5,  568446438);
            d = md5_gg(d, a, b, c, x[i + 14],  9, -1019803690);
            c = md5_gg(c, d, a, b, x[i +  3], 14, -187363961);
            b = md5_gg(b, c, d, a, x[i +  8], 20,  1163531501);
            a = md5_gg(a, b, c, d, x[i + 13],  5, -1444681467);
            d = md5_gg(d, a, b, c, x[i +  2],  9, -51403784);
            c = md5_gg(c, d, a, b, x[i +  7], 14,  1735328473);
            b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

            a = md5_hh(a, b, c, d, x[i +  5],  4, -378558);
            d = md5_hh(d, a, b, c, x[i +  8], 11, -2022574463);
            c = md5_hh(c, d, a, b, x[i + 11], 16,  1839030562);
            b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
            a = md5_hh(a, b, c, d, x[i +  1],  4, -1530992060);
            d = md5_hh(d, a, b, c, x[i +  4], 11,  1272893353);
            c = md5_hh(c, d, a, b, x[i +  7], 16, -155497632);
            b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
            a = md5_hh(a, b, c, d, x[i + 13],  4,  681279174);
            d = md5_hh(d, a, b, c, x[i],      11, -358537222);
            c = md5_hh(c, d, a, b, x[i +  3], 16, -722521979);
            b = md5_hh(b, c, d, a, x[i +  6], 23,  76029189);
            a = md5_hh(a, b, c, d, x[i +  9],  4, -640364487);
            d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
            c = md5_hh(c, d, a, b, x[i + 15], 16,  530742520);
            b = md5_hh(b, c, d, a, x[i +  2], 23, -995338651);

            a = md5_ii(a, b, c, d, x[i],       6, -198630844);
            d = md5_ii(d, a, b, c, x[i +  7], 10,  1126891415);
            c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
            b = md5_ii(b, c, d, a, x[i +  5], 21, -57434055);
            a = md5_ii(a, b, c, d, x[i + 12],  6,  1700485571);
            d = md5_ii(d, a, b, c, x[i +  3], 10, -1894986606);
            c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
            b = md5_ii(b, c, d, a, x[i +  1], 21, -2054922799);
            a = md5_ii(a, b, c, d, x[i +  8],  6,  1873313359);
            d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
            c = md5_ii(c, d, a, b, x[i +  6], 15, -1560198380);
            b = md5_ii(b, c, d, a, x[i + 13], 21,  1309151649);
            a = md5_ii(a, b, c, d, x[i +  4],  6, -145523070);
            d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
            c = md5_ii(c, d, a, b, x[i +  2], 15,  718787259);
            b = md5_ii(b, c, d, a, x[i +  9], 21, -343485551);

            a = safe_add(a, olda);
            b = safe_add(b, oldb);
            c = safe_add(c, oldc);
            d = safe_add(d, oldd);
        }
        return [a, b, c, d];
    }

    /*
    * Convert an array of little-endian words to a string
    */
    function binl2rstr(input) {
        var i,
            output = '';
        for (i = 0; i < input.length * 32; i += 8) {
            output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
        }
        return output;
    }

    /*
    * Convert a raw string to an array of little-endian words
    * Characters >255 have their high-byte silently ignored.
    */
    function rstr2binl(input) {
        var i,
            output = [];
        output[(input.length >> 2) - 1] = undefined;
        for (i = 0; i < output.length; i += 1) {
            output[i] = 0;
        }
        for (i = 0; i < input.length * 8; i += 8) {
            output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
        }
        return output;
    }

    /*
    * Calculate the MD5 of a raw string
    */
    function rstr_md5(s) {
        return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
    }

    /*
    * Calculate the HMAC-MD5, of a key and some data (raw strings)
    */
    function rstr_hmac_md5(key, data) {
        var i,
            bkey = rstr2binl(key),
            ipad = [],
            opad = [],
            hash;
        ipad[15] = opad[15] = undefined;                        
        if (bkey.length > 16) {
            bkey = binl_md5(bkey, key.length * 8);
        }
        for (i = 0; i < 16; i += 1) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }
        hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
        return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
    }

    /*
    * Convert a raw string to a hex string
    */
    function rstr2hex(input) {
        var hex_tab = '0123456789abcdef',
            output = '',
            x,
            i;
        for (i = 0; i < input.length; i += 1) {
            x = input.charCodeAt(i);
            output += hex_tab.charAt((x >>> 4) & 0x0F) +
                hex_tab.charAt(x & 0x0F);
        }
        return output;
    }

    /*
    * Encode a string as utf-8
    */
    function str2rstr_utf8(input) {
        return unescape(encodeURIComponent(input));
    }

    /*
    * Take string arguments and return either raw or hex encoded strings
    */
    function raw_md5(s) {
        return rstr_md5(str2rstr_utf8(s));
    }
    function hex_md5(s) {
        return rstr2hex(raw_md5(s));
    }
    function raw_hmac_md5(k, d) {
        return rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d));
    }
    function hex_hmac_md5(k, d) {
        return rstr2hex(raw_hmac_md5(k, d));
    }
    
    $.md5 = function (string, key, raw) {
        if (!key) {
            if (!raw) {
                return hex_md5(string);
            } else {
                return raw_md5(string);
            }
        }
        if (!raw) {
            return hex_hmac_md5(key, string);
        } else {
            return raw_hmac_md5(key, string);
        }
    };
    //md5加密附加字符串
    $.md5.MD5_ATTACH_STR = "shinetechnology";
    
}(typeof jQuery === 'function' ? jQuery : this));(function($, undefined) {
  $.extend({
    jsonRPC: {
      // RPC Version Number
      version: '2.0',
      
      // End point URL, sets default in requests if not
      // specified with the request call
      endPoint: null,
      cache: false,
      // Default namespace for methods
      namespace: null,

      request: function(method, options) {
        if(options === undefined) {
          options = { id: 1 };
        }
        if (options.id === undefined) {
          options.id = 1;
        }
        if (options.cache === undefined) {
          options.cache = this.cache;
        }

        // Validate method arguments
        this._validateRequestMethod(method);
        this._validateRequestParams(options.params);
        this._validateRequestCallbacks(options.success, options.error);

        // Perform the actual request
        this._doRequest(JSON.stringify(this._requestDataObj(method, options.params, options.id)), options,method);

        return true;
      },
      init: function(serviceUrl, cache){
    	  if(serviceUrl)
    		  this.endPoint = serviceUrl;
    	  if(cache)
    		  this.cache = cache;
      },
      callService: function(method,success,error,params){
          var options = { 
        		  id: 1,
        		  cache: this.cache,
        		  success: success,
        		  error: error,
        		  endPoint:this.endPoint,
        		  params:[]
        		  };
          	for(var i=3;i<arguments.length;i++){
          		options.params[i-3]=arguments[i];
          	}
            // Validate method arguments
            this._validateRequestMethod(method);
            this._validateRequestParams(options.params);
            this._validateRequestCallbacks(options.success, options.error);

            // Perform the actual request
            this._doRequest(JSON.stringify(this._requestDataObj(method, options.params, options.id)), options,method);

            return true;   	  
      },
      
      // Validate a params hash
      _validateConfigParams: function(params) {
        if(params === undefined) {
          throw("No params specified");
        }
        else {
          if(params.endPoint && typeof(params.endPoint) !== 'string'){
            throw("endPoint must be a string");
          }
          if(params.namespace && typeof(params.namespace) !== 'string'){
            throw("namespace must be a string");
          }
        }
      },

      // Request method must be a string
      _validateRequestMethod: function(method) {
        if(typeof(method) !== 'string') throw("Invalid method supplied for jsonRPC request")
        return true;
      },

      // Validate request params.  Must be a) empty, b) an object (e.g. {}), or c) an array
      _validateRequestParams: function(params) {
        if(!(params === null ||
             params === undefined ||
             typeof(params) === 'object' ||
             $.isArray(params))) {
          throw("Invalid params supplied for jsonRPC request. It must be empty, an object or an array.");
        }
        return true;
      },

      _validateRequestCallbacks: function(success, error) {
        // Make sure callbacks are either empty or a function
        if(success !== undefined &&
           typeof(success) !== 'function') throw("Invalid success callback supplied for jsonRPC request");
        if(error !== undefined &&
         typeof(error) !== 'function') throw("Invalid error callback supplied for jsonRPC request");
        return true;
      },
      _getCookieByName: function(c_name){
    	  if (document.cookie.length <= 0)
    		  return null;
    	  
    	  var tid = null;
		  var c_start=document.cookie.indexOf(c_name + "=");
		  var c_end = -1;
		  if (c_start != -1){ 
		      c_start = c_start + c_name.length+1;
		   	  c_end = document.cookie.indexOf(";",c_start);
		   	  if (c_end == -1) 
		   		  c_end=document.cookie.length;
		   	  tid = unescape(document.cookie.substring(c_start,c_end));
		  }
		  return tid;
      },
	  _getExheader: function(tm,randomval){
		  var c_name="cid";
		  //获取csrfid
		  var tid= this._getCookieByName(c_name);	
		  //请求流水
		  if(tid == null || tid ==undefined || tid == ''){
			  tid = ""+Math.floor(Math.random() * Math.random() *1000000000);
		  }
		  var req_id = getCurrentDate() + tid.substr(0,9);
		  
		  tm = tm +''+randomval;
		  
		  var exh = $.md5(tid+tm);
		  var result = {'Ex-h':exh,'Ex-reqid':req_id};
		  return result;
	  },
      // Internal method used for generic ajax requests
      _doRequest: function(data, options,method) {
        var _that = this;
        var tm = new Date().getTime();
        
        var random = Math.floor(Math.random()*10000);
        //获取头数据对象       
        var exHeader=  this._getExheader(tm, random);
        tm = tm +""+ random;
        $.ajax({
          type: 'POST',
          async: false !== options.async,
          dataType: 'json',
          contentType: 'application/json ; charset=UTF-8',
          url: this._requestUrl((options.endPoint || options.url), options.cache,tm),
          data: data,
          cache: options.cache,
          processData: false,
          headers:exHeader,
          error: function(json) {
            _that._requestError.call(_that, json, options.error,method);
          },
          success: function(json) {
            _that._requestSuccess.call(_that, json, options.success, options.error,method);
          }
        })
      },

      // Determines the appropriate request URL to call for a request
      _requestUrl: function(url, cache,tm) {
        url = url || this.endPoint;
        if (!cache) {
            if (url.indexOf("?") < 0) {
              url += '?tm=' + tm;
            }
            else {
              url += "&tm=" + tm;
            }
        }
        return url;
      },

      // Creates an RPC suitable request object
      _requestDataObj: function(method, params, id) {
        var dataObj = {
          jsonrpc: this.version,
          method: this.namespace ? this.namespace +'.'+ method : method,
          id: id
        }
        if(params !== undefined) {
          dataObj.params = params;
        }
        return dataObj;
      },

      // Handles calling of error callback function
      _requestError: function(json, error,method) {
        if (error !== undefined && typeof(error) === 'function') {
          if(typeof(json.responseText) === 'string') {
            try {
              error(method,{error:{message:json.statusText,errorCode:json.status}});
            }
            catch(e) {
              error(method,this._response());
            }
          }
          else {
            error(method,this._response());
          }
        }
      },

      // Handles calling of RPC success, calls error callback
      // if the response contains an error
      // TODO: Handle error checking for batch requests
      _requestSuccess: function(json, success, error,method) {
        var response = this._response(json);

        // If we've encountered an error in the response, trigger the error callback if it exists
        if(response.error && typeof(error) === 'function') {
          error(method,response);
          return;
        }

        // Otherwise, successful request, run the success request if it exists
        if(typeof(success) === 'function') {
          success(method,response);
        }
      },

      // Returns a generic RPC 2.0 compatible response object
      _response: function(json) {
        if (json === undefined) {
          return {
            error: 'Internal server error',
            version: '2.0'
          };
        }
        else {
          try {
            if(typeof(json) === 'string') {
              json = eval ( '(' + json + ')' );
            }

            if (($.isArray(json) && json.length > 0 && json[0].jsonrpc !== '2.0') ||
                (!$.isArray(json) && json.jsonrpc !== '2.0')) {
              throw 'Version error';
            }

            return json;
          }
          catch (e) {
            return {
              error: 'Internal server error: ' + e,
              version: '2.0'
            }
          }
        }
      }

    }
  });
})(jQuery);/*
    json2.js
    2014-02-04

    Public Domain.

    NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.

    See http://www.JSON.org/js.html


    This code should be minified before deployment.
    See http://javascript.crockford.com/jsmin.html

    USE YOUR OWN COPY. IT IS EXTREMELY UNWISE TO LOAD CODE FROM SERVERS YOU DO
    NOT CONTROL.


    This file creates a global JSON object containing two methods: stringify
    and parse.

        JSON.stringify(value, replacer, space)
            value       any JavaScript value, usually an object or array.

            replacer    an optional parameter that determines how object
                        values are stringified for objects. It can be a
                        function or an array of strings.

            space       an optional parameter that specifies the indentation
                        of nested structures. If it is omitted, the text will
                        be packed without extra whitespace. If it is a number,
                        it will specify the number of spaces to indent at each
                        level. If it is a string (such as '\t' or '&nbsp;'),
                        it contains the characters used to indent at each level.

            This method produces a JSON text from a JavaScript value.

            When an object value is found, if the object contains a toJSON
            method, its toJSON method will be called and the result will be
            stringified. A toJSON method does not serialize: it returns the
            value represented by the name/value pair that should be serialized,
            or undefined if nothing should be serialized. The toJSON method
            will be passed the key associated with the value, and this will be
            bound to the value

            For example, this would serialize Dates as ISO strings.

                Date.prototype.toJSON = function (key) {
                    function f(n) {
                        // Format integers to have at least two digits.
                        return n < 10 ? '0' + n : n;
                    }

                    return this.getUTCFullYear()   + '-' +
                         f(this.getUTCMonth() + 1) + '-' +
                         f(this.getUTCDate())      + 'T' +
                         f(this.getUTCHours())     + ':' +
                         f(this.getUTCMinutes())   + ':' +
                         f(this.getUTCSeconds())   + 'Z';
                };

            You can provide an optional replacer method. It will be passed the
            key and value of each member, with this bound to the containing
            object. The value that is returned from your method will be
            serialized. If your method returns undefined, then the member will
            be excluded from the serialization.

            If the replacer parameter is an array of strings, then it will be
            used to select the members to be serialized. It filters the results
            such that only members with keys listed in the replacer array are
            stringified.

            Values that do not have JSON representations, such as undefined or
            functions, will not be serialized. Such values in objects will be
            dropped; in arrays they will be replaced with null. You can use
            a replacer function to replace those with JSON values.
            JSON.stringify(undefined) returns undefined.

            The optional space parameter produces a stringification of the
            value that is filled with line breaks and indentation to make it
            easier to read.

            If the space parameter is a non-empty string, then that string will
            be used for indentation. If the space parameter is a number, then
            the indentation will be that many spaces.

            Example:

            text = JSON.stringify(['e', {pluribus: 'unum'}]);
            // text is '["e",{"pluribus":"unum"}]'


            text = JSON.stringify(['e', {pluribus: 'unum'}], null, '\t');
            // text is '[\n\t"e",\n\t{\n\t\t"pluribus": "unum"\n\t}\n]'

            text = JSON.stringify([new Date()], function (key, value) {
                return this[key] instanceof Date ?
                    'Date(' + this[key] + ')' : value;
            });
            // text is '["Date(---current time---)"]'


        JSON.parse(text, reviver)
            This method parses a JSON text to produce an object or array.
            It can throw a SyntaxError exception.

            The optional reviver parameter is a function that can filter and
            transform the results. It receives each of the keys and values,
            and its return value is used instead of the original value.
            If it returns what it received, then the structure is not modified.
            If it returns undefined then the member is deleted.

            Example:

            // Parse the text. Values that look like ISO date strings will
            // be converted to Date objects.

            myData = JSON.parse(text, function (key, value) {
                var a;
                if (typeof value === 'string') {
                    a =
/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d*)?)Z$/.exec(value);
                    if (a) {
                        return new Date(Date.UTC(+a[1], +a[2] - 1, +a[3], +a[4],
                            +a[5], +a[6]));
                    }
                }
                return value;
            });

            myData = JSON.parse('["Date(09/09/2001)"]', function (key, value) {
                var d;
                if (typeof value === 'string' &&
                        value.slice(0, 5) === 'Date(' &&
                        value.slice(-1) === ')') {
                    d = new Date(value.slice(5, -1));
                    if (d) {
                        return d;
                    }
                }
                return value;
            });


    This is a reference implementation. You are free to copy, modify, or
    redistribute.
*/

/*jslint evil: true, regexp: true */

/*members "", "\b", "\t", "\n", "\f", "\r", "\"", JSON, "\\", apply,
    call, charCodeAt, getUTCDate, getUTCFullYear, getUTCHours,
    getUTCMinutes, getUTCMonth, getUTCSeconds, hasOwnProperty, join,
    lastIndex, length, parse, prototype, push, replace, slice, stringify,
    test, toJSON, toString, valueOf
*/


// Create a JSON object only if one does not already exist. We create the
// methods in a closure to avoid creating global variables.

if (typeof JSON !== 'object') {
    JSON = {};
}

(function () {
    'use strict';

    function f(n) {
        // Format integers to have at least two digits.
        return n < 10 ? '0' + n : n;
    }

    if (typeof Date.prototype.toJSON !== 'function') {

        Date.prototype.toJSON = function () {

            return isFinite(this.valueOf())
                ? this.getUTCFullYear()     + '-' +
                    f(this.getUTCMonth() + 1) + '-' +
                    f(this.getUTCDate())      + 'T' +
                    f(this.getUTCHours())     + ':' +
                    f(this.getUTCMinutes())   + ':' +
                    f(this.getUTCSeconds())   + 'Z'
                : null;
        };

        String.prototype.toJSON      =
            Number.prototype.toJSON  =
            Boolean.prototype.toJSON = function () {
                return this.valueOf();
            };
    }

    var cx,
        escapable,
        gap,
        indent,
        meta,
        rep;


    function quote(string) {

// If the string contains no control characters, no quote characters, and no
// backslash characters, then we can safely slap some quotes around it.
// Otherwise we must also replace the offending characters with safe escape
// sequences.

        escapable.lastIndex = 0;
        return escapable.test(string) ? '"' + string.replace(escapable, function (a) {
            var c = meta[a];
            return typeof c === 'string'
                ? c
                : '\\u' + ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
        }) + '"' : '"' + string + '"';
    }


    function str(key, holder) {

// Produce a string from holder[key].

        var i,          // The loop counter.
            k,          // The member key.
            v,          // The member value.
            length,
            mind = gap,
            partial,
            value = holder[key];

// If the value has a toJSON method, call it to obtain a replacement value.

        if (value && typeof value === 'object' &&
                typeof value.toJSON === 'function') {
            value = value.toJSON(key);
        }

// If we were called with a replacer function, then call the replacer to
// obtain a replacement value.

        if (typeof rep === 'function') {
            value = rep.call(holder, key, value);
        }

// What happens next depends on the value's type.

        switch (typeof value) {
        case 'string':
            return quote(value);

        case 'number':

// JSON numbers must be finite. Encode non-finite numbers as null.

            return isFinite(value) ? String(value) : 'null';

        case 'boolean':
        case 'null':

// If the value is a boolean or null, convert it to a string. Note:
// typeof null does not produce 'null'. The case is included here in
// the remote chance that this gets fixed someday.

            return String(value);

// If the type is 'object', we might be dealing with an object or an array or
// null.

        case 'object':

// Due to a specification blunder in ECMAScript, typeof null is 'object',
// so watch out for that case.

            if (!value) {
                return 'null';
            }

// Make an array to hold the partial results of stringifying this object value.

            gap += indent;
            partial = [];

// Is the value an array?

            if (Object.prototype.toString.apply(value) === '[object Array]') {

// The value is an array. Stringify every element. Use null as a placeholder
// for non-JSON values.

                length = value.length;
                for (i = 0; i < length; i += 1) {
                    partial[i] = str(i, value) || 'null';
                }

// Join all of the elements together, separated with commas, and wrap them in
// brackets.

                v = partial.length === 0
                    ? '[]'
                    : gap
                    ? '[\n' + gap + partial.join(',\n' + gap) + '\n' + mind + ']'
                    : '[' + partial.join(',') + ']';
                gap = mind;
                return v;
            }

// If the replacer is an array, use it to select the members to be stringified.

            if (rep && typeof rep === 'object') {
                length = rep.length;
                for (i = 0; i < length; i += 1) {
                    if (typeof rep[i] === 'string') {
                        k = rep[i];
                        v = str(k, value);
                        if (v) {
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);
                        }
                    }
                }
            } else {

// Otherwise, iterate through all of the keys in the object.

                for (k in value) {
                    if (Object.prototype.hasOwnProperty.call(value, k)) {
                        v = str(k, value);
                        if (v) {
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);
                        }
                    }
                }
            }

// Join all of the member texts together, separated with commas,
// and wrap them in braces.

            v = partial.length === 0
                ? '{}'
                : gap
                ? '{\n' + gap + partial.join(',\n' + gap) + '\n' + mind + '}'
                : '{' + partial.join(',') + '}';
            gap = mind;
            return v;
        }
    }

// If the JSON object does not yet have a stringify method, give it one.

    if (typeof JSON.stringify !== 'function') {
        escapable = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;
        meta = {    // table of character substitutions
            '\b': '\\b',
            '\t': '\\t',
            '\n': '\\n',
            '\f': '\\f',
            '\r': '\\r',
            '"' : '\\"',
            '\\': '\\\\'
        };
        JSON.stringify = function (value, replacer, space) {

// The stringify method takes a value and an optional replacer, and an optional
// space parameter, and returns a JSON text. The replacer can be a function
// that can replace values, or an array of strings that will select the keys.
// A default replacer method can be provided. Use of the space parameter can
// produce text that is more easily readable.

            var i;
            gap = '';
            indent = '';

// If the space parameter is a number, make an indent string containing that
// many spaces.

            if (typeof space === 'number') {
                for (i = 0; i < space; i += 1) {
                    indent += ' ';
                }

// If the space parameter is a string, it will be used as the indent string.

            } else if (typeof space === 'string') {
                indent = space;
            }

// If there is a replacer, it must be a function or an array.
// Otherwise, throw an error.

            rep = replacer;
            if (replacer && typeof replacer !== 'function' &&
                    (typeof replacer !== 'object' ||
                    typeof replacer.length !== 'number')) {
                throw new Error('JSON.stringify');
            }

// Make a fake root object containing our value under the key of ''.
// Return the result of stringifying the value.

            return str('', {'': value});
        };
    }


// If the JSON object does not yet have a parse method, give it one.

    if (typeof JSON.parse !== 'function') {
        cx = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g;
        JSON.parse = function (text, reviver) {

// The parse method takes a text and an optional reviver function, and returns
// a JavaScript value if the text is a valid JSON text.

            var j;

            function walk(holder, key) {

// The walk method is used to recursively walk the resulting structure so
// that modifications can be made.

                var k, v, value = holder[key];
                if (value && typeof value === 'object') {
                    for (k in value) {
                        if (Object.prototype.hasOwnProperty.call(value, k)) {
                            v = walk(value, k);
                            if (v !== undefined) {
                                value[k] = v;
                            } else {
                                delete value[k];
                            }
                        }
                    }
                }
                return reviver.call(holder, key, value);
            }


// Parsing happens in four stages. In the first stage, we replace certain
// Unicode characters with escape sequences. JavaScript handles many characters
// incorrectly, either silently deleting them, or treating them as line endings.

            text = String(text);
            cx.lastIndex = 0;
            if (cx.test(text)) {
                text = text.replace(cx, function (a) {
                    return '\\u' +
                        ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
                });
            }

// In the second stage, we run the text against regular expressions that look
// for non-JSON patterns. We are especially concerned with '()' and 'new'
// because they can cause invocation, and '=' because it can cause mutation.
// But just to be safe, we want to reject all unexpected forms.

// We split the second stage into 4 regexp operations in order to work around
// crippling inefficiencies in IE's and Safari's regexp engines. First we
// replace the JSON backslash pairs with '@' (a non-JSON character). Second, we
// replace all simple value tokens with ']' characters. Third, we delete all
// open brackets that follow a colon or comma or that begin the text. Finally,
// we look to see that the remaining characters are only whitespace or ']' or
// ',' or ':' or '{' or '}'. If that is so, then the text is safe for eval.

            if (/^[\],:{}\s]*$/
                    .test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@')
                        .replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, ']')
                        .replace(/(?:^|:|,)(?:\s*\[)+/g, ''))) {

// In the third stage we use the eval function to compile the text into a
// JavaScript structure. The '{' operator is subject to a syntactic ambiguity
// in JavaScript: it can begin a block or an object literal. We wrap the text
// in parens to eliminate the ambiguity.

                j = eval('(' + text + ')');

// In the optional fourth stage, we recursively walk the new structure, passing
// each name/value pair to a reviver function for possible transformation.

                return typeof reviver === 'function'
                    ? walk({'': j}, '')
                    : j;
            }

// If the text is not JSON parseable, then a SyntaxError is thrown.

            throw new SyntaxError('JSON.parse');
        };
    }
}());(function(factory){factory(jQuery);}(function($){$.ui=$.ui||{};$.extend($.ui,{version:"1.11.4",keyCode:{BACKSPACE:8,COMMA:188,DELETE:46,DOWN:40,END:35,ENTER:13,ESCAPE:27,HOME:36,LEFT:37,PAGE_DOWN:34,PAGE_UP:33,PERIOD:190,RIGHT:39,SPACE:32,TAB:9,UP:38}});$.fn.extend({scrollParent:function(includeHidden){var position=this.css("position"),excludeStaticParent=position==="absolute",overflowRegex=includeHidden?/(auto|scroll|hidden)/:/(auto|scroll)/,scrollParent=this.parents().filter(function(){var parent=$(this);if(excludeStaticParent&&parent.css("position")==="static"){return false;}
return overflowRegex.test(parent.css("overflow")+parent.css("overflow-y")+parent.css("overflow-x"));}).eq(0);return position==="fixed"||!scrollParent.length?$(this[0].ownerDocument||document):scrollParent;},uniqueId:(function(){var uuid=0;return function(){return this.each(function(){if(!this.id){this.id="ui-id-"+(++uuid);}});};})(),removeUniqueId:function(){return this.each(function(){if(/^ui-id-\d+$/.test(this.id)){$(this).removeAttr("id");}});}});function focusable(element,isTabIndexNotNaN){var map,mapName,img,nodeName=element.nodeName.toLowerCase();if("area"===nodeName){map=element.parentNode;mapName=map.name;if(!element.href||!mapName||map.nodeName.toLowerCase()!=="map"){return false;}
img=$("img[usemap='#"+mapName+"']")[0];return!!img&&visible(img);}
return(/^(input|select|textarea|button|object)$/.test(nodeName)?!element.disabled:"a"===nodeName?element.href||isTabIndexNotNaN:isTabIndexNotNaN)&&visible(element);}
function visible(element){return $.expr.filters.visible(element)&&!$(element).parents().addBack().filter(function(){return $.css(this,"visibility")==="hidden";}).length;}
$.extend($.expr[":"],{data:$.expr.createPseudo?$.expr.createPseudo(function(dataName){return function(elem){return!!$.data(elem,dataName);};}):function(elem,i,match){return!!$.data(elem,match[3]);},focusable:function(element){return focusable(element,!isNaN($.attr(element,"tabindex")));},tabbable:function(element){var tabIndex=$.attr(element,"tabindex"),isTabIndexNaN=isNaN(tabIndex);return(isTabIndexNaN||tabIndex>=0)&&focusable(element,!isTabIndexNaN);}});if(!$("<a>").outerWidth(1).jquery){$.each(["Width","Height"],function(i,name){var side=name==="Width"?["Left","Right"]:["Top","Bottom"],type=name.toLowerCase(),orig={innerWidth:$.fn.innerWidth,innerHeight:$.fn.innerHeight,outerWidth:$.fn.outerWidth,outerHeight:$.fn.outerHeight};function reduce(elem,size,border,margin){$.each(side,function(){size-=parseFloat($.css(elem,"padding"+this))||0;if(border){size-=parseFloat($.css(elem,"border"+this+"Width"))||0;}
if(margin){size-=parseFloat($.css(elem,"margin"+this))||0;}});return size;}
$.fn["inner"+name]=function(size){if(size===undefined){return orig["inner"+name].call(this);}
return this.each(function(){$(this).css(type,reduce(this,size)+"px");});};$.fn["outer"+name]=function(size,margin){if(typeof size!=="number"){return orig["outer"+name].call(this,size);}
return this.each(function(){$(this).css(type,reduce(this,size,true,margin)+"px");});};});}
if(!$.fn.addBack){$.fn.addBack=function(selector){return this.add(selector==null?this.prevObject:this.prevObject.filter(selector));};}
if($("<a>").data("a-b","a").removeData("a-b").data("a-b")){$.fn.removeData=(function(removeData){return function(key){if(arguments.length){return removeData.call(this,$.camelCase(key));}else{return removeData.call(this);}};})($.fn.removeData);}
$.ui.ie=!!/msie [\w.]+/.exec(navigator.userAgent.toLowerCase());$.fn.extend({focus:(function(orig){return function(delay,fn){return typeof delay==="number"?this.each(function(){var elem=this;setTimeout(function(){$(elem).focus();if(fn){fn.call(elem);}},delay);}):orig.apply(this,arguments);};})($.fn.focus),disableSelection:(function(){var eventType="onselectstart"in document.createElement("div")?"selectstart":"mousedown";return function(){return this.bind(eventType+".ui-disableSelection",function(event){event.preventDefault();});};})(),enableSelection:function(){return this.unbind(".ui-disableSelection");},zIndex:function(zIndex){if(zIndex!==undefined){return this.css("zIndex",zIndex);}
if(this.length){var elem=$(this[0]),position,value;while(elem.length&&elem[0]!==document){position=elem.css("position");if(position==="absolute"||position==="relative"||position==="fixed"){value=parseInt(elem.css("zIndex"),10);if(!isNaN(value)&&value!==0){return value;}}
elem=elem.parent();}}
return 0;}});$.ui.plugin={add:function(module,option,set){var i,proto=$.ui[module].prototype;for(i in set){proto.plugins[i]=proto.plugins[i]||[];proto.plugins[i].push([option,set[i]]);}},call:function(instance,name,args,allowDisconnected){var i,set=instance.plugins[name];if(!set){return;}
if(!allowDisconnected&&(!instance.element[0].parentNode||instance.element[0].parentNode.nodeType===11)){return;}
for(i=0;i<set.length;i++){if(instance.options[set[i][0]]){set[i][1].apply(instance.element,args);}}}};var widget_uuid=0,widget_slice=Array.prototype.slice;$.cleanData=(function(orig){return function(elems){var events,elem,i;for(i=0;(elem=elems[i])!=null;i++){try{events=$._data(elem,"events");if(events&&events.remove){$(elem).triggerHandler("remove");}}catch(e){}}
orig(elems);};})($.cleanData);$.widget=function(name,base,prototype){var fullName,existingConstructor,constructor,basePrototype,proxiedPrototype={},namespace=name.split(".")[0];name=name.split(".")[1];fullName=namespace+"-"+name;if(!prototype){prototype=base;base=$.Widget;}
$.expr[":"][fullName.toLowerCase()]=function(elem){return!!$.data(elem,fullName);};$[namespace]=$[namespace]||{};existingConstructor=$[namespace][name];constructor=$[namespace][name]=function(options,element){if(!this._createWidget){return new constructor(options,element);}
if(arguments.length){this._createWidget(options,element);}};$.extend(constructor,existingConstructor,{version:prototype.version,_proto:$.extend({},prototype),_childConstructors:[]});basePrototype=new base();basePrototype.options=$.widget.extend({},basePrototype.options);$.each(prototype,function(prop,value){if(!$.isFunction(value)){proxiedPrototype[prop]=value;return;}
proxiedPrototype[prop]=(function(){var _super=function(){return base.prototype[prop].apply(this,arguments);},_superApply=function(args){return base.prototype[prop].apply(this,args);};return function(){var __super=this._super,__superApply=this._superApply,returnValue;this._super=_super;this._superApply=_superApply;returnValue=value.apply(this,arguments);this._super=__super;this._superApply=__superApply;return returnValue;};})();});constructor.prototype=$.widget.extend(basePrototype,{widgetEventPrefix:existingConstructor?(basePrototype.widgetEventPrefix||name):name},proxiedPrototype,{constructor:constructor,namespace:namespace,widgetName:name,widgetFullName:fullName});if(existingConstructor){$.each(existingConstructor._childConstructors,function(i,child){var childPrototype=child.prototype;$.widget(childPrototype.namespace+"."+childPrototype.widgetName,constructor,child._proto);});delete existingConstructor._childConstructors;}else{base._childConstructors.push(constructor);}
$.widget.bridge(name,constructor);return constructor;};$.widget.extend=function(target){var input=widget_slice.call(arguments,1),inputIndex=0,inputLength=input.length,key,value;for(;inputIndex<inputLength;inputIndex++){for(key in input[inputIndex]){value=input[inputIndex][key];if(input[inputIndex].hasOwnProperty(key)&&value!==undefined){if($.isPlainObject(value)){target[key]=$.isPlainObject(target[key])?$.widget.extend({},target[key],value):$.widget.extend({},value);}else{target[key]=value;}}}}
return target;};$.widget.bridge=function(name,object){var fullName=object.prototype.widgetFullName||name;$.fn[name]=function(options){var isMethodCall=typeof options==="string",args=widget_slice.call(arguments,1),returnValue=this;if(isMethodCall){this.each(function(){var methodValue,instance=$.data(this,fullName);if(options==="instance"){returnValue=instance;return false;}
if(!instance){return $.error("cannot call methods on "+name+" prior to initialization; "+"attempted to call method '"+options+"'");}
if(!$.isFunction(instance[options])||options.charAt(0)==="_"){return $.error("no such method '"+options+"' for "+name+" widget instance");}
methodValue=instance[options].apply(instance,args);if(methodValue!==instance&&methodValue!==undefined){returnValue=methodValue&&methodValue.jquery?returnValue.pushStack(methodValue.get()):methodValue;return false;}});}else{if(args.length){options=$.widget.extend.apply(null,[options].concat(args));}
this.each(function(){var instance=$.data(this,fullName);if(instance){instance.option(options||{});if(instance._init){instance._init();}}else{$.data(this,fullName,new object(options,this));}});}
return returnValue;};};$.Widget=function(){};$.Widget._childConstructors=[];$.Widget.prototype={widgetName:"widget",widgetEventPrefix:"",defaultElement:"<div>",options:{disabled:false,create:null},_createWidget:function(options,element){element=$(element||this.defaultElement||this)[0];this.element=$(element);this.uuid=widget_uuid++;this.eventNamespace="."+this.widgetName+this.uuid;this.bindings=$();this.hoverable=$();this.focusable=$();if(element!==this){$.data(element,this.widgetFullName,this);this._on(true,this.element,{remove:function(event){if(event.target===element){this.destroy();}}});this.document=$(element.style?element.ownerDocument:element.document||element);this.window=$(this.document[0].defaultView||this.document[0].parentWindow);}
this.options=$.widget.extend({},this.options,this._getCreateOptions(),options);this._create();this._trigger("create",null,this._getCreateEventData());this._init();},_getCreateOptions:$.noop,_getCreateEventData:$.noop,_create:$.noop,_init:$.noop,destroy:function(){this._destroy();this.element.unbind(this.eventNamespace).removeData(this.widgetFullName).removeData($.camelCase(this.widgetFullName));this.widget().unbind(this.eventNamespace).removeAttr("aria-disabled").removeClass(this.widgetFullName+"-disabled "+"ui-state-disabled");this.bindings.unbind(this.eventNamespace);this.hoverable.removeClass("ui-state-hover");this.focusable.removeClass("ui-state-focus");},_destroy:$.noop,widget:function(){return this.element;},option:function(key,value){var options=key,parts,curOption,i;if(arguments.length===0){return $.widget.extend({},this.options);}
if(typeof key==="string"){options={};parts=key.split(".");key=parts.shift();if(parts.length){curOption=options[key]=$.widget.extend({},this.options[key]);for(i=0;i<parts.length-1;i++){curOption[parts[i]]=curOption[parts[i]]||{};curOption=curOption[parts[i]];}
key=parts.pop();if(arguments.length===1){return curOption[key]===undefined?null:curOption[key];}
curOption[key]=value;}else{if(arguments.length===1){return this.options[key]===undefined?null:this.options[key];}
options[key]=value;}}
this._setOptions(options);return this;},_setOptions:function(options){var key;for(key in options){this._setOption(key,options[key]);}
return this;},_setOption:function(key,value){this.options[key]=value;if(key==="disabled"){this.widget().toggleClass(this.widgetFullName+"-disabled",!!value);if(value){this.hoverable.removeClass("ui-state-hover");this.focusable.removeClass("ui-state-focus");}}
return this;},enable:function(){return this._setOptions({disabled:false});},disable:function(){return this._setOptions({disabled:true});},_on:function(suppressDisabledCheck,element,handlers){var delegateElement,instance=this;if(typeof suppressDisabledCheck!=="boolean"){handlers=element;element=suppressDisabledCheck;suppressDisabledCheck=false;}
if(!handlers){handlers=element;element=this.element;delegateElement=this.widget();}else{element=delegateElement=$(element);this.bindings=this.bindings.add(element);}
$.each(handlers,function(event,handler){function handlerProxy(){if(!suppressDisabledCheck&&(instance.options.disabled===true||$(this).hasClass("ui-state-disabled"))){return;}
return(typeof handler==="string"?instance[handler]:handler).apply(instance,arguments);}
if(typeof handler!=="string"){handlerProxy.guid=handler.guid=handler.guid||handlerProxy.guid||$.guid++;}
var match=event.match(/^([\w:-]*)\s*(.*)$/),eventName=match[1]+instance.eventNamespace,selector=match[2];if(selector){delegateElement.delegate(selector,eventName,handlerProxy);}else{element.bind(eventName,handlerProxy);}});},_off:function(element,eventName){eventName=(eventName||"").split(" ").join(this.eventNamespace+" ")+this.eventNamespace;element.unbind(eventName).undelegate(eventName);this.bindings=$(this.bindings.not(element).get());this.focusable=$(this.focusable.not(element).get());this.hoverable=$(this.hoverable.not(element).get());},_delay:function(handler,delay){function handlerProxy(){return(typeof handler==="string"?instance[handler]:handler).apply(instance,arguments);}
var instance=this;return setTimeout(handlerProxy,delay||0);},_hoverable:function(element){this.hoverable=this.hoverable.add(element);this._on(element,{mouseenter:function(event){$(event.currentTarget).addClass("ui-state-hover");},mouseleave:function(event){$(event.currentTarget).removeClass("ui-state-hover");}});},_focusable:function(element){this.focusable=this.focusable.add(element);this._on(element,{focusin:function(event){$(event.currentTarget).addClass("ui-state-focus");},focusout:function(event){$(event.currentTarget).removeClass("ui-state-focus");}});},_trigger:function(type,event,data){var prop,orig,callback=this.options[type];data=data||{};event=$.Event(event);event.type=(type===this.widgetEventPrefix?type:this.widgetEventPrefix+type).toLowerCase();event.target=this.element[0];orig=event.originalEvent;if(orig){for(prop in orig){if(!(prop in event)){event[prop]=orig[prop];}}}
this.element.trigger(event,data);return!($.isFunction(callback)&&callback.apply(this.element[0],[event].concat(data))===false||event.isDefaultPrevented());}};$.each({show:"fadeIn",hide:"fadeOut"},function(method,defaultEffect){$.Widget.prototype["_"+method]=function(element,options,callback){if(typeof options==="string"){options={effect:options};}
var hasOptions,effectName=!options?method:options===true||typeof options==="number"?defaultEffect:options.effect||defaultEffect;options=options||{};if(typeof options==="number"){options={duration:options};}
hasOptions=!$.isEmptyObject(options);options.complete=callback;if(options.delay){element.delay(options.delay);}
if(hasOptions&&$.effects&&$.effects.effect[effectName]){element[method](options);}else if(effectName!==method&&element[effectName]){element[effectName](options.duration,options.easing,callback);}else{element.queue(function(next){$(this)[method]();if(callback){callback.call(element[0]);}
next();});}};});var widget=$.widget;var mouseHandled=false;$(document).mouseup(function(){mouseHandled=false;});var mouse=$.widget("ui.mouse",{version:"1.11.4",options:{cancel:"input,textarea,button,select,option",distance:1,delay:0},_mouseInit:function(){var that=this;this.element.bind("mousedown."+this.widgetName,function(event){return that._mouseDown(event);}).bind("click."+this.widgetName,function(event){if(true===$.data(event.target,that.widgetName+".preventClickEvent")){$.removeData(event.target,that.widgetName+".preventClickEvent");event.stopImmediatePropagation();return false;}});this.started=false;},_mouseDestroy:function(){this.element.unbind("."+this.widgetName);if(this._mouseMoveDelegate){this.document.unbind("mousemove."+this.widgetName,this._mouseMoveDelegate).unbind("mouseup."+this.widgetName,this._mouseUpDelegate);}},_mouseDown:function(event){if(mouseHandled){return;}
this._mouseMoved=false;(this._mouseStarted&&this._mouseUp(event));this._mouseDownEvent=event;var that=this,btnIsLeft=(event.which===1),elIsCancel=(typeof this.options.cancel==="string"&&event.target.nodeName?$(event.target).closest(this.options.cancel).length:false);if(!btnIsLeft||elIsCancel||!this._mouseCapture(event)){return true;}
this.mouseDelayMet=!this.options.delay;if(!this.mouseDelayMet){this._mouseDelayTimer=setTimeout(function(){that.mouseDelayMet=true;},this.options.delay);}
if(this._mouseDistanceMet(event)&&this._mouseDelayMet(event)){this._mouseStarted=(this._mouseStart(event)!==false);if(!this._mouseStarted){event.preventDefault();return true;}}
if(true===$.data(event.target,this.widgetName+".preventClickEvent")){$.removeData(event.target,this.widgetName+".preventClickEvent");}
this._mouseMoveDelegate=function(event){return that._mouseMove(event);};this._mouseUpDelegate=function(event){return that._mouseUp(event);};this.document.bind("mousemove."+this.widgetName,this._mouseMoveDelegate).bind("mouseup."+this.widgetName,this._mouseUpDelegate);event.preventDefault();mouseHandled=true;return true;},_mouseMove:function(event){if(this._mouseMoved){if($.ui.ie&&(!document.documentMode||document.documentMode<9)&&!event.button){return this._mouseUp(event);}else if(!event.which){return this._mouseUp(event);}}
if(event.which||event.button){this._mouseMoved=true;}
if(this._mouseStarted){this._mouseDrag(event);return event.preventDefault();}
if(this._mouseDistanceMet(event)&&this._mouseDelayMet(event)){this._mouseStarted=(this._mouseStart(this._mouseDownEvent,event)!==false);(this._mouseStarted?this._mouseDrag(event):this._mouseUp(event));}
return!this._mouseStarted;},_mouseUp:function(event){this.document.unbind("mousemove."+this.widgetName,this._mouseMoveDelegate).unbind("mouseup."+this.widgetName,this._mouseUpDelegate);if(this._mouseStarted){this._mouseStarted=false;if(event.target===this._mouseDownEvent.target){$.data(event.target,this.widgetName+".preventClickEvent",true);}
this._mouseStop(event);}
mouseHandled=false;return false;},_mouseDistanceMet:function(event){return(Math.max(Math.abs(this._mouseDownEvent.pageX-event.pageX),Math.abs(this._mouseDownEvent.pageY-event.pageY))>=this.options.distance);},_mouseDelayMet:function(){return this.mouseDelayMet;},_mouseStart:function(){},_mouseDrag:function(){},_mouseStop:function(){},_mouseCapture:function(){return true;}});var sortable=$.widget("ui.sortable",$.ui.mouse,{version:"1.11.4",widgetEventPrefix:"sort",ready:false,options:{appendTo:"parent",axis:false,connectWith:false,containment:false,cursor:"auto",cursorAt:false,dropOnEmpty:true,forcePlaceholderSize:false,forceHelperSize:false,grid:false,handle:false,helper:"original",items:"> *",opacity:false,placeholder:false,revert:false,scroll:true,scrollSensitivity:20,scrollSpeed:20,scope:"default",tolerance:"intersect",zIndex:1000,activate:null,beforeStop:null,change:null,deactivate:null,out:null,over:null,receive:null,remove:null,sort:null,start:null,stop:null,update:null},_isOverAxis:function(x,reference,size){return(x>=reference)&&(x<(reference+size));},_isFloating:function(item){return(/left|right/).test(item.css("float"))||(/inline|table-cell/).test(item.css("display"));},_create:function(){this.containerCache={};this.element.addClass("ui-sortable");this.refresh();this.offset=this.element.offset();this._mouseInit();this._setHandleClassName();this.ready=true;},_setOption:function(key,value){this._super(key,value);if(key==="handle"){this._setHandleClassName();}},_setHandleClassName:function(){this.element.find(".ui-sortable-handle").removeClass("ui-sortable-handle");$.each(this.items,function(){(this.instance.options.handle?this.item.find(this.instance.options.handle):this.item).addClass("ui-sortable-handle");});},_destroy:function(){this.element.removeClass("ui-sortable ui-sortable-disabled").find(".ui-sortable-handle").removeClass("ui-sortable-handle");this._mouseDestroy();for(var i=this.items.length-1;i>=0;i--){this.items[i].item.removeData(this.widgetName+"-item");}
return this;},_mouseCapture:function(event,overrideHandle){var currentItem=null,validHandle=false,that=this;if(this.reverting){return false;}
if(this.options.disabled||this.options.type==="static"){return false;}
this._refreshItems(event);$(event.target).parents().each(function(){if($.data(this,that.widgetName+"-item")===that){currentItem=$(this);return false;}});if($.data(event.target,that.widgetName+"-item")===that){currentItem=$(event.target);}
if(!currentItem){return false;}
if(this.options.handle&&!overrideHandle){$(this.options.handle,currentItem).find("*").addBack().each(function(){if(this===event.target){validHandle=true;}});if(!validHandle){return false;}}
this.currentItem=currentItem;this._removeCurrentsFromItems();return true;},_mouseStart:function(event,overrideHandle,noActivation){var i,body,o=this.options;this.currentContainer=this;this.refreshPositions();this.helper=this._createHelper(event);this._cacheHelperProportions();this._cacheMargins();this.scrollParent=this.helper.scrollParent();this.offset=this.currentItem.offset();this.offset={top:this.offset.top-this.margins.top,left:this.offset.left-this.margins.left};$.extend(this.offset,{click:{left:event.pageX-this.offset.left,top:event.pageY-this.offset.top},parent:this._getParentOffset(),relative:this._getRelativeOffset()});this.helper.css("position","absolute");this.cssPosition=this.helper.css("position");this.originalPosition=this._generatePosition(event);this.originalPageX=event.pageX;this.originalPageY=event.pageY;(o.cursorAt&&this._adjustOffsetFromHelper(o.cursorAt));this.domPosition={prev:this.currentItem.prev()[0],parent:this.currentItem.parent()[0]};if(this.helper[0]!==this.currentItem[0]){this.currentItem.hide();}
this._createPlaceholder();if(o.containment){this._setContainment();}
if(o.cursor&&o.cursor!=="auto"){body=this.document.find("body");this.storedCursor=body.css("cursor");body.css("cursor",o.cursor);this.storedStylesheet=$("<style>*{ cursor: "+o.cursor+" !important; }</style>").appendTo(body);}
if(o.opacity){if(this.helper.css("opacity")){this._storedOpacity=this.helper.css("opacity");}
this.helper.css("opacity",o.opacity);}
if(o.zIndex){if(this.helper.css("zIndex")){this._storedZIndex=this.helper.css("zIndex");}
this.helper.css("zIndex",o.zIndex);}
if(this.scrollParent[0]!==this.document[0]&&this.scrollParent[0].tagName!=="HTML"){this.overflowOffset=this.scrollParent.offset();}
this._trigger("start",event,this._uiHash());if(!this._preserveHelperProportions){this._cacheHelperProportions();}
if(!noActivation){for(i=this.containers.length-1;i>=0;i--){this.containers[i]._trigger("activate",event,this._uiHash(this));}}
if($.ui.ddmanager){$.ui.ddmanager.current=this;}
if($.ui.ddmanager&&!o.dropBehaviour){$.ui.ddmanager.prepareOffsets(this,event);}
this.dragging=true;this.helper.addClass("ui-sortable-helper");this._mouseDrag(event);return true;},_mouseDrag:function(event){var i,item,itemElement,intersection,o=this.options,scrolled=false;this.position=this._generatePosition(event);this.positionAbs=this._convertPositionTo("absolute");if(!this.lastPositionAbs){this.lastPositionAbs=this.positionAbs;}
if(this.options.scroll){if(this.scrollParent[0]!==this.document[0]&&this.scrollParent[0].tagName!=="HTML"){if((this.overflowOffset.top+this.scrollParent[0].offsetHeight)-event.pageY<o.scrollSensitivity){this.scrollParent[0].scrollTop=scrolled=this.scrollParent[0].scrollTop+o.scrollSpeed;}else if(event.pageY-this.overflowOffset.top<o.scrollSensitivity){this.scrollParent[0].scrollTop=scrolled=this.scrollParent[0].scrollTop-o.scrollSpeed;}
if((this.overflowOffset.left+this.scrollParent[0].offsetWidth)-event.pageX<o.scrollSensitivity){this.scrollParent[0].scrollLeft=scrolled=this.scrollParent[0].scrollLeft+o.scrollSpeed;}else if(event.pageX-this.overflowOffset.left<o.scrollSensitivity){this.scrollParent[0].scrollLeft=scrolled=this.scrollParent[0].scrollLeft-o.scrollSpeed;}}else{if(event.pageY-this.document.scrollTop()<o.scrollSensitivity){scrolled=this.document.scrollTop(this.document.scrollTop()-o.scrollSpeed);}else if(this.window.height()-(event.pageY-this.document.scrollTop())<o.scrollSensitivity){scrolled=this.document.scrollTop(this.document.scrollTop()+o.scrollSpeed);}
if(event.pageX-this.document.scrollLeft()<o.scrollSensitivity){scrolled=this.document.scrollLeft(this.document.scrollLeft()-o.scrollSpeed);}else if(this.window.width()-(event.pageX-this.document.scrollLeft())<o.scrollSensitivity){scrolled=this.document.scrollLeft(this.document.scrollLeft()+o.scrollSpeed);}}
if(scrolled!==false&&$.ui.ddmanager&&!o.dropBehaviour){$.ui.ddmanager.prepareOffsets(this,event);}}
this.positionAbs=this._convertPositionTo("absolute");if(!this.options.axis||this.options.axis!=="y"){this.helper[0].style.left=this.position.left+"px";}
if(!this.options.axis||this.options.axis!=="x"){this.helper[0].style.top=this.position.top+"px";}
for(i=this.items.length-1;i>=0;i--){item=this.items[i];itemElement=item.item[0];intersection=this._intersectsWithPointer(item);if(!intersection){continue;}
if(item.instance!==this.currentContainer){continue;}
if(itemElement!==this.currentItem[0]&&this.placeholder[intersection===1?"next":"prev"]()[0]!==itemElement&&!$.contains(this.placeholder[0],itemElement)&&(this.options.type==="semi-dynamic"?!$.contains(this.element[0],itemElement):true)){this.direction=intersection===1?"down":"up";if(this.options.tolerance==="pointer"||this._intersectsWithSides(item)){this._rearrange(event,item);}else{break;}
this._trigger("change",event,this._uiHash());break;}}
this._contactContainers(event);if($.ui.ddmanager){$.ui.ddmanager.drag(this,event);}
this._trigger("sort",event,this._uiHash());this.lastPositionAbs=this.positionAbs;return false;},_mouseStop:function(event,noPropagation){if(!event){return;}
if($.ui.ddmanager&&!this.options.dropBehaviour){$.ui.ddmanager.drop(this,event);}
if(this.options.revert){var that=this,cur=this.placeholder.offset(),axis=this.options.axis,animation={};if(!axis||axis==="x"){animation.left=cur.left-this.offset.parent.left-this.margins.left+(this.offsetParent[0]===this.document[0].body?0:this.offsetParent[0].scrollLeft);}
if(!axis||axis==="y"){animation.top=cur.top-this.offset.parent.top-this.margins.top+(this.offsetParent[0]===this.document[0].body?0:this.offsetParent[0].scrollTop);}
this.reverting=true;$(this.helper).animate(animation,parseInt(this.options.revert,10)||500,function(){that._clear(event);});}else{this._clear(event,noPropagation);}
return false;},cancel:function(){if(this.dragging){this._mouseUp({target:null});if(this.options.helper==="original"){this.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper");}else{this.currentItem.show();}
for(var i=this.containers.length-1;i>=0;i--){this.containers[i]._trigger("deactivate",null,this._uiHash(this));if(this.containers[i].containerCache.over){this.containers[i]._trigger("out",null,this._uiHash(this));this.containers[i].containerCache.over=0;}}}
if(this.placeholder){if(this.placeholder[0].parentNode){this.placeholder[0].parentNode.removeChild(this.placeholder[0]);}
if(this.options.helper!=="original"&&this.helper&&this.helper[0].parentNode){this.helper.remove();}
$.extend(this,{helper:null,dragging:false,reverting:false,_noFinalSort:null});if(this.domPosition.prev){$(this.domPosition.prev).after(this.currentItem);}else{$(this.domPosition.parent).prepend(this.currentItem);}}
return this;},serialize:function(o){var items=this._getItemsAsjQuery(o&&o.connected),str=[];o=o||{};$(items).each(function(){var res=($(o.item||this).attr(o.attribute||"id")||"").match(o.expression||(/(.+)[\-=_](.+)/));if(res){str.push((o.key||res[1]+"[]")+"="+(o.key&&o.expression?res[1]:res[2]));}});if(!str.length&&o.key){str.push(o.key+"=");}
return str.join("&");},toArray:function(o){var items=this._getItemsAsjQuery(o&&o.connected),ret=[];o=o||{};items.each(function(){ret.push($(o.item||this).attr(o.attribute||"id")||"");});return ret;},_intersectsWith:function(item){var x1=this.positionAbs.left,x2=x1+this.helperProportions.width,y1=this.positionAbs.top,y2=y1+this.helperProportions.height,l=item.left,r=l+item.width,t=item.top,b=t+item.height,dyClick=this.offset.click.top,dxClick=this.offset.click.left,isOverElementHeight=(this.options.axis==="x")||((y1+dyClick)>t&&(y1+dyClick)<b),isOverElementWidth=(this.options.axis==="y")||((x1+dxClick)>l&&(x1+dxClick)<r),isOverElement=isOverElementHeight&&isOverElementWidth;if(this.options.tolerance==="pointer"||this.options.forcePointerForContainers||(this.options.tolerance!=="pointer"&&this.helperProportions[this.floating?"width":"height"]>item[this.floating?"width":"height"])){return isOverElement;}else{return(l<x1+(this.helperProportions.width/2)&&x2-(this.helperProportions.width/2)<r&&t<y1+(this.helperProportions.height/2)&&y2-(this.helperProportions.height/2)<b);}},_intersectsWithPointer:function(item){var isOverElementHeight=(this.options.axis==="x")||this._isOverAxis(this.positionAbs.top+this.offset.click.top,item.top,item.height),isOverElementWidth=(this.options.axis==="y")||this._isOverAxis(this.positionAbs.left+this.offset.click.left,item.left,item.width),isOverElement=isOverElementHeight&&isOverElementWidth,verticalDirection=this._getDragVerticalDirection(),horizontalDirection=this._getDragHorizontalDirection();if(!isOverElement){return false;}
return this.floating?(((horizontalDirection&&horizontalDirection==="right")||verticalDirection==="down")?2:1):(verticalDirection&&(verticalDirection==="down"?2:1));},_intersectsWithSides:function(item){var isOverBottomHalf=this._isOverAxis(this.positionAbs.top+this.offset.click.top,item.top+(item.height/2),item.height),isOverRightHalf=this._isOverAxis(this.positionAbs.left+this.offset.click.left,item.left+(item.width/2),item.width),verticalDirection=this._getDragVerticalDirection(),horizontalDirection=this._getDragHorizontalDirection();if(this.floating&&horizontalDirection){return((horizontalDirection==="right"&&isOverRightHalf)||(horizontalDirection==="left"&&!isOverRightHalf));}else{return verticalDirection&&((verticalDirection==="down"&&isOverBottomHalf)||(verticalDirection==="up"&&!isOverBottomHalf));}},_getDragVerticalDirection:function(){var delta=this.positionAbs.top-this.lastPositionAbs.top;return delta!==0&&(delta>0?"down":"up");},_getDragHorizontalDirection:function(){var delta=this.positionAbs.left-this.lastPositionAbs.left;return delta!==0&&(delta>0?"right":"left");},refresh:function(event){this._refreshItems(event);this._setHandleClassName();this.refreshPositions();return this;},_connectWith:function(){var options=this.options;return options.connectWith.constructor===String?[options.connectWith]:options.connectWith;},_getItemsAsjQuery:function(connected){var i,j,cur,inst,items=[],queries=[],connectWith=this._connectWith();if(connectWith&&connected){for(i=connectWith.length-1;i>=0;i--){cur=$(connectWith[i],this.document[0]);for(j=cur.length-1;j>=0;j--){inst=$.data(cur[j],this.widgetFullName);if(inst&&inst!==this&&!inst.options.disabled){queries.push([$.isFunction(inst.options.items)?inst.options.items.call(inst.element):$(inst.options.items,inst.element).not(".ui-sortable-helper").not(".ui-sortable-placeholder"),inst]);}}}}
queries.push([$.isFunction(this.options.items)?this.options.items.call(this.element,null,{options:this.options,item:this.currentItem}):$(this.options.items,this.element).not(".ui-sortable-helper").not(".ui-sortable-placeholder"),this]);function addItems(){items.push(this);}
for(i=queries.length-1;i>=0;i--){queries[i][0].each(addItems);}
return $(items);},_removeCurrentsFromItems:function(){var list=this.currentItem.find(":data("+this.widgetName+"-item)");this.items=$.grep(this.items,function(item){for(var j=0;j<list.length;j++){if(list[j]===item.item[0]){return false;}}
return true;});},_refreshItems:function(event){this.items=[];this.containers=[this];var i,j,cur,inst,targetData,_queries,item,queriesLength,items=this.items,queries=[[$.isFunction(this.options.items)?this.options.items.call(this.element[0],event,{item:this.currentItem}):$(this.options.items,this.element),this]],connectWith=this._connectWith();if(connectWith&&this.ready){for(i=connectWith.length-1;i>=0;i--){cur=$(connectWith[i],this.document[0]);for(j=cur.length-1;j>=0;j--){inst=$.data(cur[j],this.widgetFullName);if(inst&&inst!==this&&!inst.options.disabled){queries.push([$.isFunction(inst.options.items)?inst.options.items.call(inst.element[0],event,{item:this.currentItem}):$(inst.options.items,inst.element),inst]);this.containers.push(inst);}}}}
for(i=queries.length-1;i>=0;i--){targetData=queries[i][1];_queries=queries[i][0];for(j=0,queriesLength=_queries.length;j<queriesLength;j++){item=$(_queries[j]);item.data(this.widgetName+"-item",targetData);items.push({item:item,instance:targetData,width:0,height:0,left:0,top:0});}}},refreshPositions:function(fast){this.floating=this.items.length?this.options.axis==="x"||this._isFloating(this.items[0].item):false;if(this.offsetParent&&this.helper){this.offset.parent=this._getParentOffset();}
var i,item,t,p;for(i=this.items.length-1;i>=0;i--){item=this.items[i];if(item.instance!==this.currentContainer&&this.currentContainer&&item.item[0]!==this.currentItem[0]){continue;}
t=this.options.toleranceElement?$(this.options.toleranceElement,item.item):item.item;if(!fast){item.width=t.outerWidth();item.height=t.outerHeight();}
p=t.offset();item.left=p.left;item.top=p.top;}
if(this.options.custom&&this.options.custom.refreshContainers){this.options.custom.refreshContainers.call(this);}else{for(i=this.containers.length-1;i>=0;i--){p=this.containers[i].element.offset();this.containers[i].containerCache.left=p.left;this.containers[i].containerCache.top=p.top;this.containers[i].containerCache.width=this.containers[i].element.outerWidth();this.containers[i].containerCache.height=this.containers[i].element.outerHeight();}}
return this;},_createPlaceholder:function(that){that=that||this;var className,o=that.options;if(!o.placeholder||o.placeholder.constructor===String){className=o.placeholder;o.placeholder={element:function(){var nodeName=that.currentItem[0].nodeName.toLowerCase(),element=$("<"+nodeName+">",that.document[0]).addClass(className||that.currentItem[0].className+" ui-sortable-placeholder").removeClass("ui-sortable-helper");if(nodeName==="tbody"){that._createTrPlaceholder(that.currentItem.find("tr").eq(0),$("<tr>",that.document[0]).appendTo(element));}else if(nodeName==="tr"){that._createTrPlaceholder(that.currentItem,element);}else if(nodeName==="img"){element.attr("src",that.currentItem.attr("src"));}
if(!className){element.css("visibility","hidden");}
return element;},update:function(container,p){if(className&&!o.forcePlaceholderSize){return;}
if(!p.height()){p.height(that.currentItem.innerHeight()-parseInt(that.currentItem.css("paddingTop")||0,10)-parseInt(that.currentItem.css("paddingBottom")||0,10));}
if(!p.width()){p.width(that.currentItem.innerWidth()-parseInt(that.currentItem.css("paddingLeft")||0,10)-parseInt(that.currentItem.css("paddingRight")||0,10));}}};}
that.placeholder=$(o.placeholder.element.call(that.element,that.currentItem));that.currentItem.after(that.placeholder);o.placeholder.update(that,that.placeholder);},_createTrPlaceholder:function(sourceTr,targetTr){var that=this;sourceTr.children().each(function(){$("<td>&#160;</td>",that.document[0]).attr("colspan",$(this).attr("colspan")||1).appendTo(targetTr);});},_contactContainers:function(event){var i,j,dist,itemWithLeastDistance,posProperty,sizeProperty,cur,nearBottom,floating,axis,innermostContainer=null,innermostIndex=null;for(i=this.containers.length-1;i>=0;i--){if($.contains(this.currentItem[0],this.containers[i].element[0])){continue;}
if(this._intersectsWith(this.containers[i].containerCache)){if(innermostContainer&&$.contains(this.containers[i].element[0],innermostContainer.element[0])){continue;}
innermostContainer=this.containers[i];innermostIndex=i;}else{if(this.containers[i].containerCache.over){this.containers[i]._trigger("out",event,this._uiHash(this));this.containers[i].containerCache.over=0;}}}
if(!innermostContainer){return;}
if(this.containers.length===1){if(!this.containers[innermostIndex].containerCache.over){this.containers[innermostIndex]._trigger("over",event,this._uiHash(this));this.containers[innermostIndex].containerCache.over=1;}}else{dist=10000;itemWithLeastDistance=null;floating=innermostContainer.floating||this._isFloating(this.currentItem);posProperty=floating?"left":"top";sizeProperty=floating?"width":"height";axis=floating?"clientX":"clientY";for(j=this.items.length-1;j>=0;j--){if(!$.contains(this.containers[innermostIndex].element[0],this.items[j].item[0])){continue;}
if(this.items[j].item[0]===this.currentItem[0]){continue;}
cur=this.items[j].item.offset()[posProperty];nearBottom=false;if(event[axis]-cur>this.items[j][sizeProperty]/2){nearBottom=true;}
if(Math.abs(event[axis]-cur)<dist){dist=Math.abs(event[axis]-cur);itemWithLeastDistance=this.items[j];this.direction=nearBottom?"up":"down";}}
if(!itemWithLeastDistance&&!this.options.dropOnEmpty){return;}
if(this.currentContainer===this.containers[innermostIndex]){if(!this.currentContainer.containerCache.over){this.containers[innermostIndex]._trigger("over",event,this._uiHash());this.currentContainer.containerCache.over=1;}
return;}
itemWithLeastDistance?this._rearrange(event,itemWithLeastDistance,null,true):this._rearrange(event,null,this.containers[innermostIndex].element,true);this._trigger("change",event,this._uiHash());this.containers[innermostIndex]._trigger("change",event,this._uiHash(this));this.currentContainer=this.containers[innermostIndex];this.options.placeholder.update(this.currentContainer,this.placeholder);this.containers[innermostIndex]._trigger("over",event,this._uiHash(this));this.containers[innermostIndex].containerCache.over=1;}},_createHelper:function(event){var o=this.options,helper=$.isFunction(o.helper)?$(o.helper.apply(this.element[0],[event,this.currentItem])):(o.helper==="clone"?this.currentItem.clone():this.currentItem);if(!helper.parents("body").length){$(o.appendTo!=="parent"?o.appendTo:this.currentItem[0].parentNode)[0].appendChild(helper[0]);}
if(helper[0]===this.currentItem[0]){this._storedCSS={width:this.currentItem[0].style.width,height:this.currentItem[0].style.height,position:this.currentItem.css("position"),top:this.currentItem.css("top"),left:this.currentItem.css("left")};}
if(!helper[0].style.width||o.forceHelperSize){helper.width(this.currentItem.width());}
if(!helper[0].style.height||o.forceHelperSize){helper.height(this.currentItem.height());}
return helper;},_adjustOffsetFromHelper:function(obj){if(typeof obj==="string"){obj=obj.split(" ");}
if($.isArray(obj)){obj={left:+obj[0],top:+obj[1]||0};}
if("left"in obj){this.offset.click.left=obj.left+this.margins.left;}
if("right"in obj){this.offset.click.left=this.helperProportions.width-obj.right+this.margins.left;}
if("top"in obj){this.offset.click.top=obj.top+this.margins.top;}
if("bottom"in obj){this.offset.click.top=this.helperProportions.height-obj.bottom+this.margins.top;}},_getParentOffset:function(){this.offsetParent=this.helper.offsetParent();var po=this.offsetParent.offset();if(this.cssPosition==="absolute"&&this.scrollParent[0]!==this.document[0]&&$.contains(this.scrollParent[0],this.offsetParent[0])){po.left+=this.scrollParent.scrollLeft();po.top+=this.scrollParent.scrollTop();}
if(this.offsetParent[0]===this.document[0].body||(this.offsetParent[0].tagName&&this.offsetParent[0].tagName.toLowerCase()==="html"&&$.ui.ie)){po={top:0,left:0};}
return{top:po.top+(parseInt(this.offsetParent.css("borderTopWidth"),10)||0),left:po.left+(parseInt(this.offsetParent.css("borderLeftWidth"),10)||0)};},_getRelativeOffset:function(){if(this.cssPosition==="relative"){var p=this.currentItem.position();return{top:p.top-(parseInt(this.helper.css("top"),10)||0)+this.scrollParent.scrollTop(),left:p.left-(parseInt(this.helper.css("left"),10)||0)+this.scrollParent.scrollLeft()};}else{return{top:0,left:0};}},_cacheMargins:function(){this.margins={left:(parseInt(this.currentItem.css("marginLeft"),10)||0),top:(parseInt(this.currentItem.css("marginTop"),10)||0)};},_cacheHelperProportions:function(){this.helperProportions={width:this.helper.outerWidth(),height:this.helper.outerHeight()};},_setContainment:function(){var ce,co,over,o=this.options;if(o.containment==="parent"){o.containment=this.helper[0].parentNode;}
if(o.containment==="document"||o.containment==="window"){this.containment=[0-this.offset.relative.left-this.offset.parent.left,0-this.offset.relative.top-this.offset.parent.top,o.containment==="document"?this.document.width():this.window.width()-this.helperProportions.width-this.margins.left,(o.containment==="document"?this.document.width():this.window.height()||this.document[0].body.parentNode.scrollHeight)-this.helperProportions.height-this.margins.top];}
if(!(/^(document|window|parent)$/).test(o.containment)){ce=$(o.containment)[0];co=$(o.containment).offset();over=($(ce).css("overflow")!=="hidden");this.containment=[co.left+(parseInt($(ce).css("borderLeftWidth"),10)||0)+(parseInt($(ce).css("paddingLeft"),10)||0)-this.margins.left,co.top+(parseInt($(ce).css("borderTopWidth"),10)||0)+(parseInt($(ce).css("paddingTop"),10)||0)-this.margins.top,co.left+(over?Math.max(ce.scrollWidth,ce.offsetWidth):ce.offsetWidth)-(parseInt($(ce).css("borderLeftWidth"),10)||0)-(parseInt($(ce).css("paddingRight"),10)||0)-this.helperProportions.width-this.margins.left,co.top+(over?Math.max(ce.scrollHeight,ce.offsetHeight):ce.offsetHeight)-(parseInt($(ce).css("borderTopWidth"),10)||0)-(parseInt($(ce).css("paddingBottom"),10)||0)-this.helperProportions.height-this.margins.top];}},_convertPositionTo:function(d,pos){if(!pos){pos=this.position;}
var mod=d==="absolute"?1:-1,scroll=this.cssPosition==="absolute"&&!(this.scrollParent[0]!==this.document[0]&&$.contains(this.scrollParent[0],this.offsetParent[0]))?this.offsetParent:this.scrollParent,scrollIsRootNode=(/(html|body)/i).test(scroll[0].tagName);return{top:(pos.top+
this.offset.relative.top*mod+
this.offset.parent.top*mod-
((this.cssPosition==="fixed"?-this.scrollParent.scrollTop():(scrollIsRootNode?0:scroll.scrollTop()))*mod)),left:(pos.left+
this.offset.relative.left*mod+
this.offset.parent.left*mod-
((this.cssPosition==="fixed"?-this.scrollParent.scrollLeft():scrollIsRootNode?0:scroll.scrollLeft())*mod))};},_generatePosition:function(event){var top,left,o=this.options,pageX=event.pageX,pageY=event.pageY,scroll=this.cssPosition==="absolute"&&!(this.scrollParent[0]!==this.document[0]&&$.contains(this.scrollParent[0],this.offsetParent[0]))?this.offsetParent:this.scrollParent,scrollIsRootNode=(/(html|body)/i).test(scroll[0].tagName);if(this.cssPosition==="relative"&&!(this.scrollParent[0]!==this.document[0]&&this.scrollParent[0]!==this.offsetParent[0])){this.offset.relative=this._getRelativeOffset();}
if(this.originalPosition){if(this.containment){if(event.pageX-this.offset.click.left<this.containment[0]){pageX=this.containment[0]+this.offset.click.left;}
if(event.pageY-this.offset.click.top<this.containment[1]){pageY=this.containment[1]+this.offset.click.top;}
if(event.pageX-this.offset.click.left>this.containment[2]){pageX=this.containment[2]+this.offset.click.left;}
if(event.pageY-this.offset.click.top>this.containment[3]){pageY=this.containment[3]+this.offset.click.top;}}
if(o.grid){top=this.originalPageY+Math.round((pageY-this.originalPageY)/o.grid[1])*o.grid[1];pageY=this.containment?((top-this.offset.click.top>=this.containment[1]&&top-this.offset.click.top<=this.containment[3])?top:((top-this.offset.click.top>=this.containment[1])?top-o.grid[1]:top+o.grid[1])):top;left=this.originalPageX+Math.round((pageX-this.originalPageX)/o.grid[0])*o.grid[0];pageX=this.containment?((left-this.offset.click.left>=this.containment[0]&&left-this.offset.click.left<=this.containment[2])?left:((left-this.offset.click.left>=this.containment[0])?left-o.grid[0]:left+o.grid[0])):left;}}
return{top:(pageY-
this.offset.click.top-
this.offset.relative.top-
this.offset.parent.top+
((this.cssPosition==="fixed"?-this.scrollParent.scrollTop():(scrollIsRootNode?0:scroll.scrollTop())))),left:(pageX-
this.offset.click.left-
this.offset.relative.left-
this.offset.parent.left+
((this.cssPosition==="fixed"?-this.scrollParent.scrollLeft():scrollIsRootNode?0:scroll.scrollLeft())))};},_rearrange:function(event,i,a,hardRefresh){a?a[0].appendChild(this.placeholder[0]):i.item[0].parentNode.insertBefore(this.placeholder[0],(this.direction==="down"?i.item[0]:i.item[0].nextSibling));this.counter=this.counter?++this.counter:1;var counter=this.counter;this._delay(function(){if(counter===this.counter){this.refreshPositions(!hardRefresh);}});},_clear:function(event,noPropagation){this.reverting=false;var i,delayedTriggers=[];if(!this._noFinalSort&&this.currentItem.parent().length){this.placeholder.before(this.currentItem);}
this._noFinalSort=null;if(this.helper[0]===this.currentItem[0]){for(i in this._storedCSS){if(this._storedCSS[i]==="auto"||this._storedCSS[i]==="static"){this._storedCSS[i]="";}}
this.currentItem.css(this._storedCSS).removeClass("ui-sortable-helper");}else{this.currentItem.show();}
if(this.fromOutside&&!noPropagation){delayedTriggers.push(function(event){this._trigger("receive",event,this._uiHash(this.fromOutside));});}
if((this.fromOutside||this.domPosition.prev!==this.currentItem.prev().not(".ui-sortable-helper")[0]||this.domPosition.parent!==this.currentItem.parent()[0])&&!noPropagation){delayedTriggers.push(function(event){this._trigger("update",event,this._uiHash());});}
if(this!==this.currentContainer){if(!noPropagation){delayedTriggers.push(function(event){this._trigger("remove",event,this._uiHash());});delayedTriggers.push((function(c){return function(event){c._trigger("receive",event,this._uiHash(this));};}).call(this,this.currentContainer));delayedTriggers.push((function(c){return function(event){c._trigger("update",event,this._uiHash(this));};}).call(this,this.currentContainer));}}
function delayEvent(type,instance,container){return function(event){container._trigger(type,event,instance._uiHash(instance));};}
for(i=this.containers.length-1;i>=0;i--){if(!noPropagation){delayedTriggers.push(delayEvent("deactivate",this,this.containers[i]));}
if(this.containers[i].containerCache.over){delayedTriggers.push(delayEvent("out",this,this.containers[i]));this.containers[i].containerCache.over=0;}}
if(this.storedCursor){this.document.find("body").css("cursor",this.storedCursor);this.storedStylesheet.remove();}
if(this._storedOpacity){this.helper.css("opacity",this._storedOpacity);}
if(this._storedZIndex){this.helper.css("zIndex",this._storedZIndex==="auto"?"":this._storedZIndex);}
this.dragging=false;if(!noPropagation){this._trigger("beforeStop",event,this._uiHash());}
this.placeholder[0].parentNode.removeChild(this.placeholder[0]);if(!this.cancelHelperRemoval){if(this.helper[0]!==this.currentItem[0]){this.helper.remove();}
this.helper=null;}
if(!noPropagation){for(i=0;i<delayedTriggers.length;i++){delayedTriggers[i].call(this,event);}
this._trigger("stop",event,this._uiHash());}
this.fromOutside=false;return!this.cancelHelperRemoval;},_trigger:function(){if($.Widget.prototype._trigger.apply(this,arguments)===false){this.cancel();}},_uiHash:function(_inst){var inst=_inst||this;return{helper:inst.helper,placeholder:inst.placeholder||$([]),position:inst.position,originalPosition:inst.originalPosition,offset:inst.positionAbs,item:inst.currentItem,sender:_inst?_inst.element:null};}});}));if(!window.xyz) window.xyz = {};

//生成命名空间
xyz.namespace = function() {
	var o, d;
	$.each(arguments, function(i, v) {
		d = v.split(".");
		o = window[d[0]] = window[d[0]] || {};
		$.each(d.slice(1), function(j, v2) {
			o = o[v2] = o[v2] || {};
		});
	});
	return o;
};
xyz.ns = xyz.namespace; (function (){

	var exports = {
		supportCss3Animation: function() {
			var e = document.createElement("div");
			return "animation" in e.style || "webkitAnimation" in e.style ? !0 : !1
		},
		animationend: function(e, t) {
			t && t();
			//return;
			if (this.supportCss3Animation()) {
				var n = $(e),
					r = function() {
						var t = n.data("cb");
						e.removeEventListener("animationend", t);
						e.removeEventListener("webkitAnimationEnd", t);
					},
					o = function() {
						t && t();
						r();
					};
					r();
					e.addEventListener("webkitAnimationEnd", o);
					e.addEventListener("animationend", o);
					n.data("cb", o);
			} else {
				t && t();
			}
		}
	};

	xyz.util = exports;

})();
/**
 * 模板.
 * 如：
 * var html = '<span><%=data.name%></span>';
 * var data = {data: {id: 1, name: 'test'}} ;
 * xyz.utils.tmpl(html, data)  => <span>test</span>
 * 
 */
$.extend(xyz.util, {
	tmpl : function () {
		function t(t, e) {
			if (e)
				for (var i in e) {
					var a = new RegExp("<%#" + i + "%>", "g");
					t = t.replace(a, e[i])
				}
			return t
		}
		var e = {};
		return function i(a, n, s) {
			s = s || {};
			var o = s.key,
			r = s.mixinTmpl,
			c = !/\W/.test(a);
			o = o || (c ? a : null);
			var l = o ? e[o] = e[o] || i(t(c ? document.getElementById(a).innerHTML : a, r))
				 : new Function("obj", "var _p_=[],print=function(){_p_.push.apply(_p_,arguments);};with(obj){_p_.push('" + a.replace(/[\r\t\n]/g, " ").split("\\'").join("\\\\'").split("'").join("\\'").split("<%").join("	").replace(/\t=(.*?)%>/g, "',$1,'").split("	").join("');").split("%>").join("_p_.push('") + "');}return _p_.join('');");
			return n ? l(n) : l;
		}
	}()
});
/** 
 * 防页面XSS脚本注入攻击规范.
 *
 */
$.extend(xyz.util, {
	//在javascript内容中输出的“用户可控数据”，需要做javascript escape转义
	escapeJavascript : function(str) {
		var s="";
		for(var i=0;i<str.length;i++){
			switch(str[i]){
				case "'":
					s = s+"\\'";
				break;
				case "/":
					s = s +"\\/";
				break;
				case "\\":
					s = s +"\\\\";
				break;
				case "\"":
					s = s +"\\\""
				break;
				default:
					s=s+str[i];
			}
		}
		return s;
	},
	//在HTML/XML中显示“用户可控数据”前，应该进行html escape转义
	escapeHtml : function(str) {
		var s="";
		for(var i=0;i<str.length;i++){
			switch(str[i]){
				case "&":
					s = s+"&amp;";
				break;
				case "<":
					s = s +"&lt;";
				break;
				case ">":
					s = s +"&gt;";
				break;
				case "\"":
					s = s +"&quot;";
				break;
				case "'":
					s = s +"&#39;";
				break;
				default:
					s=s+str[i];
			}
		}
		return s;
	},
	//输出在url中的数据，做url安全输出
	escapeUrl : function(str) {
		var s="";
		for(var i=0;i<str.length;i++){
			switch(str[i]){
				case ">":
					s = s+"%3C";
				break;
				case ">":
					s = s +"%3E";
				break;
				case "\"":
					s = s +"%22";
				break;
				case "\'":
					s = s +"%27";
				break;
				default:
					s=s+str[i];
			}
		}
		return s;
	}
});
if(!window.xyz) window.xyz = {};

xyz.cmpmgr = function($){
	return function e(i, n, r) {
		function a(o, l) {
			if (!n[o]) {
				if (!i[o]) {
					var c = "function" == typeof t && t;
					if (!l && c) return c(o, !0);
					if (s) return s(o, !0);
					var h = new Error("Cannot find module '" + o + "'");
					throw h.code = "MODULE_NOT_FOUND",
					h
				}
				var d = n[o] = {
					exports: {}
				};
				i[o][0].call(d.exports,
				function(t) {
					var e = i[o][1][t];
					return a(e ? e: t)
				},
				d, d.exports, e, i, n, r)
			}
			return n[o].exports
		}
		for (var s = "function" == typeof t && t,
		o = 0; o < r.length; o++) a(r[o]);
		return a
	} ({
		1 : [function(t, e) {
			var i = t("beejs"),
			n = t("beejs/addons/event"),
			r = t("beejs/src/event-bind");
			window.Bee = i,
			i.directive("on", $.extend({},
			i.directives.on, {
				update: function(t) {
					var e, i;
					for (var n in t) e = n.split(/\s+/),
					i = e.shift(),
					e = e.join(" "),
					$(this.el).on(i, e, t[n].bind(this.vm))
				}
			}));
			var a = i.extend({
				$beforeInit: function() {
					var t, e = this.$data.dataSelector || "script[data]";
					this.$content && (t = this.$content.querySelector(e), this.$set(JSON.parse(t && t.innerHTML.trim() || "{}")))
				},
				$mixins: [n]
			});
			r.addEvent = function(t, e, i) {
				$(t).on(e, i)
			},
			r.removeEvent = function(t, e, i) {
				$(t).off(e, i)
			},
			i.ComponentBase = a,
			e.exports = a
		},
		{
			beejs: 28,
			"beejs/addons/event": 27,
			"beejs/src/event-bind": 48
		}],
		2 : [function(t, e) {
			"use strict";
			var i = '<div b-on="$events" data-role="qc-combo" class="tc-15-simulate-select-wrap">\n	<input input-handler type="text" autocomplete="off" class="tc-15-simulate-select m{{popup ? \' show\' : \'\'}}" placeholder="{{placeholder}}"  value="{{selected ? selected[displayField] : \'\'}}" style="text-align:left;padding-left:10px;cursor:pointer"/>\n  <div class="dropdown-list-mask" style="left: 0; right: 0; bottom: 0; top: 0; position: fixed; background: transparent; z-index: 999;" b-style="{display: popup ? \'block\' : \'none\'}"></div>\n	<ul data-list class="tc-15-simulate-option" style="z-index: 1000;top:27px;min-width:100%;overflow-y: auto" b-style="{ display: popup ? \'block\' : \'none\', minHeight: minHeight,height:height, maxHeight: maxHeight}">\n		<span b-content="listTpl"></span>\n	</ul>\n</div>\n',
			n = (t("beejs"), t("../componentBase")),
			r = {
				popup: !1,
				//simulateSelect: !1,
				label: "更多",
				maxHeight: "auto",
				height: "auto",
				minHeight: "auto",
				list: [],
				_list: [],
				valueField: null,
				displayField: null
			},
			a = n.extend({
				$tpl: i,
				$valuekey: "selected",
				listTpl: '<li data-item role="presentation" b-repeat="item in _list" class="{{selected == item ? \'selected\' : \'\'}}">\n              <a role="menuitem" href="javascript:;">{{item[displayField]}}</a>\n            </li>',
				constructor: function() {
					var t = this;
					n.apply(this, arguments);
					var e = this.selected || this.list[0];
					this.$set("selected", e),
					this.mode = this.list && this.list.length ? "local" : "remote",
					this.popup ? this.open() : this.close(),
					$(window).on("click.qc-dropdown-list",
					function(e) {
						$(e.target).parents().is(t.$el) || t.close()
					})
				},
				$afterInit: function() {
					var t = this;
					setTimeout(function() {
						return t.initGetData && t._listFn();
					}, 0);
				},
				$beforeDestroy: function() {
					$(window).off("click.qc-dropdown-list")
				},
				open: function() {
					this.$set("popup", !0)
				},
				close: function() {
					this.$set("popup", !1)
				},
				select: function(t) {
					var e;
					"object" == typeof t ? e = this._list[t.$index] || t: isNaN(1 * t) || (e = this._list[t]),
					e && (this.close(), this.$replace("selected", e), this.$emit("selected", e), "function" == typeof e.action && e.action.call(e, e))
				},
				$dataCallback: function(t, e) {
					t || this.setData(e);
				},
				setData: function(t) {
					this.$set(t);
				},
				_listFn: function(t, e) {
					var n = this;
					this.getData(t, function() {
						n.$dataCallback.apply(n, arguments);
						n.$set("dataloaded", true);
						e && e();
					});
				},
				filter: function(v) {
					var ls = [], me = this;
					$.each(this.list, function(index, item){
						if(item[me.valueField].indexOf(v) != -1){
							ls.push(item);
						}
					});
					this.$replace("_list", ls);
					this._selectIndex = -1;
				},
				getData: function() {

				},
				clear: function() {
					this.$set("dataloaded", false);
					this.list = [];
					this._list = [];
					this.$set("selected", null);

				},
				getValue: function() {
					return this.$get("selected");
				},
				setValue: function(v) {
					var me = this, s = null;
					$.each(this.list, function(index, item){
						if(item[me.valueField] == v){
							s = item;
							return false;
						}
					});
					return this.$set("selected", s);
				},
				$events: {
					"click [input-handler]": function() {
						var t = this;

						var fn = function(){
							t.$replace("_list", t.list);
							t._selectIndex = 0;
							t.popup ? t.close() : t.open();
						};
						if(this.mode == "remote"
							&& !this.$get("dataloaded")){
							this._listFn(null, fn);
						}else{
							fn();
						}
					},
					"click [data-item]": function(t) {
						this.select(t.currentTarget);
					},
					"click .dropdown-list-mask": function() {
						this.close()
					},
					"keydown [input-handler]": function(e){
						var me = this;
						if(e.keyCode == 8){
							var v = $(e.target).val(),
							    found = false;
							$.each(this.list, function(index, item){
								if(item[me.displayField] == v){
									found = true;
									return false;
								}
							});
							if(found){
								$(e.target).val("");
								this.$replace("_list", this.list);
							}
						}else if(e.keyCode == 40 || e.keyCode == 38){
							var x = this._selectIndex + (e.keyCode == 40 ? 1 : -1),
							    l = this._list.length;

							this._selectIndex = x >= l ? 0 : (x < 0 ? l - 1 : x);
							this.$replace("selected", this._list[this._selectIndex]);
							e.preventDefault();
						}
					},
					/*
					"keypress [input-handler]": function(e){
						var me = this,
						    v = $(e.target).val() + String.fromCharCode(e.keyCode),
						    ls = [];
						    v = v.toLowerCase();
						this.filter(v);
					},
					*/
					"keyup [input-handler]": function(e){
						this.filter($(e.target).val());
					}
				}
			},
			{
				defaults: r
			});
			e.exports = a
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		3 : [function(t, e) {
			"use strict";
			function i(t, e, i) {
				var n, r = $(e),
				a = r.outerHeight(),
				s = r.offset();
				return n = t < s.top ? -1 : t > s.top + a ? 2 : i > 0 ? (t - s.top) / a: (s.top + a - t) / a
			}
			var n = '<div data-role="grid-editor" b-style="style" b-on="events">\n<div class="tc-15-table-panel tc-15-table-panel-edit" style="position:relative" b-on="$events">\n  <div data-grid-head class="tc-15-table-fixed-head">\n    <table b-ref="head" class="tc-15-table-box">\n      <colgroup>\n        <col b-if="dragable" style="width: 50px">\n        <col b-repeat="col in shownColums" b-style="{width: col.width || \'auto\'}">\n      </colgroup>\n      <thead>\n        <tr>\n          <th b-if="dragable">\n            <div></div>\n          </th>\n          <th b-repeat="col in shownColums">\n            <div>\n              {{> _getHeadContent(col) }}\n            </div>\n            <i class="resize-line-icon" data-role="resizer"\n              b-if="canResizeColum && $index < shownColums.length - 1"></i>\n          </th>\n        </tr>\n      </thead>\n    </table>\n  </div>\n  <div data-grid-body class="tc-15-table-fixed-body">\n    <table b-ref="body" class="tc-15-table-box tc-15-table-rowhover">\n      <colgroup>\n          <col b-if="dragable" style="width: 40px;">\n          <col b-repeat="col in shownColums" b-style="{width: col.width || \'auto\'}">\n      </colgroup>\n      <tbody>\n      <tr data-tips b-if="_tips">\n        <td class="text-center" colspan="{{countCols(colums)}}">\n            <div>{{> _tips }}</div>\n        </td>\n      </tr>\n      <tr data-index="{{$index}}" track-by="{{trackKey}}" b-ref="list" b-repeat="item in list"\n        b-attr="setTrAttr(trAttr, item)"\n        b-style="{visibility: item._target ? \'hidden\' : \'visible\'}"\n        class="{{selectedHighlight && item.$selected?\'current\':\'\'}} {{item.$disable || item._remove ? \'disable\': \'\'}}">\n\n          <td b-if="dragable" style="position:relative">\n              <div data-drag-handler>\n                  <i class="ico-drag"></i>\n              </div>\n              <span b-template b-if="insertBtn && !overMaxSize">\n                <i style="top:-8px" data-i="" b-on-click="insert($index)" class="ico-move-drag hover-icon"></i>\n                <i style="bottom:-8px" b-on-click="insert($index + 1)" class="ico-move-drag hover-icon"></i>\n              </span>\n          </td>\n          <td b-repeat="col in shownColums" b-style="{position: $index ? \'\' : \'relative\'}">\n              <div>\n                {{> _getCellContent(item[col.key], item, col) }}\n              </div>\n              <span b-template b-if="insertBtn && !dragable && !$index && !overMaxSize">\n                <i b-on-click="insert($parent.$index)" style="top:-8px" class="ico-move-drag hover-icon"></i>\n                <i b-on-click="insert($parent.$index + 1)" style="bottom:-8px" class="ico-move-drag hover-icon"></i>\n              </span>\n          </td>\n      </tr>\n  </tbody>\n  </table>\n  <!-- <i data-disable-line class="disabled-line"></i> -->\n  </div>\n</div>\n</div>\n',
			r = (t("beejs"), t("../grid-view")),
			a = t("deep-equal"),
			s = {
				dragable: !0,
				insertBtn: !0,
				newData: {},
				overlayRate: .3,
				maxSize: 0,
				minSize: 0,
				autoMaxHeight: !1,
				emptyTips: '列表为空 <a b-on-click="insert(0)" href="javascript:;">+新增</a>'
			},
			o = r.extend({
				$tpl: n,
				overMaxSize: !1,
				overMinSize: !1,
				actionTpl: '<span class="text-overflow">\n    <a href="javascript:;" class="links"\n      b-on-click="(item._remove ? restore : preRemove)($parent.$index)">{{item._remove ? "恢复删除" : "删除"}}\n    </a></span>',
				$afterInit: function() {
					o.__super__.$afterInit.call(this),
					this.$refsBody = $(this.$refs.body),
					this._$removeLine = this._$el.find("[data-disable-line]")
				},
				preRemove: function(t) {
					return this.overMinSize ? !1 : (a(this.list[t], this.newData) ? this.remove(t) : (this.updateItem(t, {
						_remove: !0
					}), this.checkSize()), !0)
				},
				remove: function(t) {
					this.list.splice(t, 1),
					this.checkSize()
				},
				removePreRemove: function() {
					for (var t = this.list.length - 1; t >= 0; t--) this.list[t]._remove && this.remove(t)
				},
				restore: function(t) {
					return this.overMaxSize ? !1 : (this.updateItem(t, {
						_remove: !1
					}), this.checkSize(), !0)
				},
				restoreAll: function() {
					var t = this;
					this.list.forEach(function(e, i) {
						e._remove && t.restore(i)
					})
				},
				insert: function(t, e) {
					return this.overMaxSize ? e = !1 : (e = $.extend({},
					e || this.newData), this.list.splice(t, 0, e), this.checkSize()),
					e
				},
				getSize: function() {
					return this.list.filter(function(t) {
						return ! t._remove
					}).length
				},
				checkSize: function() {
					var t = this.getSize();
					this.$set({
						overMaxSize: this.maxSize > 0 && t >= this.maxSize,
						overMinSize: this.minSize && t <= this.minSize
					}),
					this.$emit("sizeChange", {
						size: t,
						total: this.list.length
					})
				},
				getColByIndex: function(t) {
					return this.dragable && t--,
					this.shownColums[t]
				},
				_cloneTr: function(t) {
					var e = this.$refsBody.clone(),
					i = $(t).clone();
					return e.width(this.$refsBody.width()),
					e.find("tr").remove(),
					e.append(i),
					e.css($.extend({
						position: "absolute"
					},
					this._getTrPos(t))),
					this.$refsBody.after(e),
					e
				},
				_getTrPos: function(t) {
					var e = $(t).offset(),
					i = this.$refsBody.offsetParent().offset();
					return {
						left: e.left - i.left,
						top: e.top - i.top
					}
				},
				$events: $.extend({},
				r.prototype.$events, {
					"mousedown [data-drag-handler]": function(t) {
						if (!this._draging) {
							var e = $(t.target).closest("tr"),
							i = 1 * e.attr("data-index");
							this._$dragingTr = e,
							this._dragingIndex = i,
							this._$dragingItem = this._cloneTr(e),
							this._$dragingItem.find("tr").addClass("current"),
							this._initPos = this._getTrPos(e),
							this._initClientPos = {
								x: t.clientX,
								y: t.clientY
							},
							this._initRect = this.$el.getBoundingClientRect(),
							this._lastY = t.clientY,
							this._setTarget(i),
							this._dragStart(),
							t.preventDefault()
						}
					}
				}),
				_dragStart: function() {
					var t = this;
					this._draging = !0,
					$(document).on("mousemove.grid_drag",
					function(e) {
						if (t._draging) {
							t._dragintDir = e.clientY - t._lastY;
							var i = t.$el.getBoundingClientRect();
							t._$dragingItem.css({
								"z-index": 9999,
								top: t._initPos.top + e.clientY - t._initClientPos.y + t._initRect.top - i.top,
								left: t._initPos.left + e.clientX - t._initClientPos.x + t._initRect.left - i.left
							}),
							t._checkOverlay(t._dragintDir)
						}
						t._lastY = e.clientY
					}).on("mouseup.grid_drag",
					function() {
						$(document).off(".grid_drag"),
						t._dragDone(),
						t._draging = !1
					})
				},
				_setTarget: function(t) {
					"undefined" != typeof this._targetIndex && (this.updateItem(this._targetIndex, {
						_target: !1
					}), this._exchange(this._targetIndex, t)),
					this.$set("_targetIndex", t),
					this.updateItem(t, {
						_target: !0
					})
				},
				_exchange: function(t, e, i) {
					var n = this.list.splice(t, 1)[0],
					r = this;
					this.list.splice(e, 0, n);
					var a = this.$refsBody.find("tr[data-index]");
					if (this._$dragingTr = a.eq(e), i !== !1) {
						var s = a.eq(t),
						o = this._getTrPos(this._$dragingTr),
						l = this._getTrPos(s);
						this._exchange_animate && this._exchange_animate.stop();
						var c = this._cloneTr(s).css(o);
						if (this._exchange_animate = c.stop().animate({
							top: l.top
						},
						{
							duration: 100,
							always: function() {
								r._exchange_animate = null,
								r.updateItem(t, {
									_target: !1
								}),
								c.remove()
							}
						}), 2 == i) {
							var h = a.eq(e),
							d = this._cloneTr(h).css(l);
							this._exchange_animate2 = d.stop().animate({
								top: this._getTrPos(h).top
							},
							{
								duration: 100,
								always: function() {
									r._exchange_animate2 = null,
									r.updateItem(e, {
										_target: !1
									}),
									d.remove()
								}
							}),
							this.updateItem(e, {
								_target: !0
							})
						}
						this.updateItem(t, {
							_target: !0
						})
					}
				},
				_dragDone: function() {
					this.updateItem(this._targetIndex, {
						_target: !1
					}),
					this._$dragingItem.remove(),
					delete this._$dragingItem,
					delete this._targetIndex
				},
				_checkOverlay: function(t) {
					var e, n, r = this,
					a = this._$dragingItem.offset(),
					s = this._$dragingItem.outerHeight();
					t > 0 ? (e = this._$dragingTr.nextAll("tr").andSelf(), n = a.top + s) : 0 > t && (e = this._$dragingTr.prevAll("tr").andSelf(), n = a.top),
					e && e.each(function(e, a) {
						var s, o = i(n, a, t);
						o >= r.overlayRate && 1 >= o && (s = 1 * $(a).attr("data-index"), s !== r._targetIndex && r._setTarget(s))
					})
				}
			},
			{
				defaults: s
			});
			e.exports = o
		},
		{
			"../grid-view": 5,
			beejs: 28,
			"deep-equal": 24
		}],
		4 : [function(t, e) {
			"use strict";
			var i = '<div>\n    <span class="tc-15-filtrate-btn{{ filterResult ? \' current\' : \'\'}}" b-on="{ click: _togglePopup }" title="{{_getFilterTitle(filterResult)}}">\n        <span>{{col.name}}</span>\n        <i class="filtrate-icon"></i>\n    </span>\n\n  <div class="tc-15-filtrateu" b-style="{\n    display: ui.popup ? \'block\' : \'none\',\n    width: enableClear ? \'200px\' : null,\n    right: col.pull == \'right\' ? \'10px\' : null\n  }" b-on="{ click: _stopPropagation }">\n\n    <div class="tc-15-search" b-if="search" style="float: none; width: auto; margin: 10px 10px 5px;">\n      <input data-input class="tc-15-search-words" placeholder="搜索{{col.name}}" b-model="keyword" type="text" style="width: 120px" />\n      <button data-search class="tc-15-btn weak m search"></button>\n    </div>\n\n\n    <ul class="tc-15-filtrate-menu" role="menu">\n      <li role="presentation" class="tc-15-optgroup">\n        <label class="tc-15-checkbox-wrap" title="全选/全不选" style="position: relative">\n          <input type="checkbox"\n                 class="tc-15-checkbox"\n                 b-model="allChecked"\n                 b-on-change="enabled && _checkAllChange(allChecked)"\n                 disabled?="!enabled">\n          (全选)\n          <span b-if="hasChecked && !allChecked" style="background: rgb(38, 134, 214); width: 6px; height: 6px; position: absolute; left: 15px;top: 12px; border-radius: 2px;"></span>\n        </label>\n      </li>\n      <li role="presentation" class="tc-15-optgroup" b-repeat="option in _searchOptions(filterOptions, keyword)">\n        <label class="tc-15-checkbox-wrap" title="{{option.label}}">\n          <input type="checkbox"\n                 class="tc-15-checkbox"\n                 b-model="option.checked"\n                 b-on-change="enabled && _filterOptionChange()"\n                 disabled?="!enabled || option.disabled">\n          {{option.label}}\n        </label>\n      </li>\n    </ul>\n\n    <div class="tc-15-filtrate-ft" b-if="response == \'confirm\'">\n      <button class="tc-15-btn m{{enabled ? \'\' : \' disabled\'}}" b-on-click="enabled && _confirmFilter()">确定</button>\n      <button class="tc-15-btn m weak{{enabled ? \'\' : \' disabled\'}}" b-if="enableClear" b-on-click="enabled && _clearFilter()">清空</button>\n      <button class="tc-15-btn m weak" b-on-click="_cancelFilter()">取消</button>\n    </div>\n  </div>\n\n</div>',
			n = (t("beejs"), t("../componentBase")),
			r = {
				filterOptions: [],
				filterResult: null,
				change: null,
				ready: null,
				enableClear: !1,
				enabled: !0,
				response: "confirm",
				search: !1,
				ui: {
					popup: !1
				}
			},
			a = n.extend({
				$tpl: i,
				$valuekey: "filterResult",
				$afterInit: function() {
					var t = this;
					this.change && this.$watch("filterResult",
					function() {
						return t.change(t.filterResult)
					}),
					this.setFilterResult(this.filterResult || this._calcFilterResult()),
					$(document).on("click", this._docClickHandler = function() {
						return t.popupLocked || t._popup(!1)
					}),
					this.ready && this.ready(this)
				},
				$afterDestroy: function() {
					$(document).off("click", this._docClickHandler)
				},
				_calcFilterResult: function() {
					if (this.filterOptions) {
						var t = [];
						if (this.filterOptions.forEach(function(e) {
							e.checked && t.push(e.value)
						}), t.length) return t
					}
					return null
				},
				_updateCheckAllState: function() {
					var t = arguments.length <= 0 || void 0 === arguments[0] ? [] : arguments[0];
					if (this.filterOptions) {
						var e = t && t.length > 0,
						i = t && this.filterOptions.length == t.length;
						this.$replace("hasChecked", e),
						this.$replace("allChecked", i)
					}
				},
				_checkAllChange: function(t) {
					var e = this.filterOptions;
					if (e) for (var i = 0; i < e.length; i++) e.$set(i, {
						checked: t
					});
					this._filterOptionChange()
				},
				_filterOptionChange: function() {
					var t = this._calcFilterResult();
					"immediate" == this.response && this.setFilterResult(t),
					this._updateCheckAllState(t)
				},
				_confirmFilter: function() {
					this.setFilterResult(this._calcFilterResult()),
					this._popup(!1)
				},
				_cancelFilter: function() {
					this.setFilterResult(this.filterResult),
					this._updateCheckAllState(this.filterResult),
					this._popup(!1)
				},
				_clearFilter: function() {
					this.setFilterResult(null),
					this._popup(!1)
				},
				_popup: function(t) {
					this.$set("ui.popup", t)
				},
				_stopPropagation: function(t) {
					t.stopPropagation()
				},
				_togglePopup: function() {
					var t = this;
					this._popup(!this.ui.popup),
					this.popupLocked = !0,
					setTimeout(function() {
						return t.popupLocked = !1
					},
					1)
				},
				_getFilterTitle: function() {
					var t = [];
					return this.filterOptions.forEach(function(e) {
						e.checked && t.push(e.label)
					}),
					t.length ? this.col.name + "：" + t.join("、") : this.col.name + "：点击筛选"
				},
				_isSameArray: function(t, e) {
					return JSON.stringify(t) == JSON.stringify(e)
				},
				_searchOptions: function(t, e) {
					return e = e && e.toLowerCase(),
					this.search && e ? t.filter(function(t) {
						return t.label && t.label.toLowerCase().indexOf(e) > -1
					}) : t
				},
				setFilterResult: function(t) {
					var e = this.filterOptions;
					if (e) for (var i = 0; i < e.length; i++) {
						var n = t ? t.indexOf(e[i].value) > -1 : !1;
						e.$set(i, {
							checked: n
						})
					}
					this._isSameArray(this.filterResult, t) || this.$replace("filterResult", t)
				}
			},
			{
				defaults: r
			});
			e.exports = a
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		5 : [function(t, e) {
			"use strict";
			var i = '<div data-role="grid-view" b-style="style" b-on="events">\r\n  <div data-grid-panel class="tc-15-table-panel" b-on="$events">\r\n    <div data-grid-head class="tc-15-table-fixed-head" style="width:auto"\r\n      b-style="{paddingRight: _hasYScroll ? scrollBarSize : 0}">\r\n      <table b-ref="head" class="tc-15-table-box" style="min-width: 100%">\r\n        <colgroup>\r\n          <col b-if="hasFirst" b-style="{width: firstColWith}">\r\n          <col b-repeat="col in shownColums"\r\n            data-locked-col?="col.locked"\r\n            b-style="{width: col.width || \'auto\', minWidth: col.minWidth}">\r\n        </colgroup>\r\n        <thead>\r\n          <tr>\r\n            <th b-if="hasFirst">\r\n              <div class="tc-15-first-checkbox">\r\n                <input type="checkbox" b-model="ischeckAll" data-check-all class="tc-15-checkbox">\r\n              </div>\r\n            </th>\r\n            <th b-repeat="col in shownColums"\r\n                data-locked-th?="col.locked"\r\n                data-orderfield="{{col.orderField || col.key}}">\r\n              <div>\r\n                <span b-content="_getHeadContent(col)"></span>\r\n              </div>\r\n              <i class="resize-line-icon" data-role="resizer"\r\n                b-if="canResizeColum && $index < shownColums.length - lockedColums.length - 1"></i>\r\n            </th>\r\n          </tr>\r\n        </thead>\r\n      </table>\r\n    </div>\r\n    <div b-on-scroll="_synScroll()" data-grid-body class="tc-15-table-fixed-body"\r\n      b-style="{minHeight: minHeight,height:height, maxHeight: maxHeight}">\r\n      <table b-ref="body" style="min-width:100%" class="tc-15-table-box tc-15-table-rowhover">\r\n        <colgroup>\r\n          <col b-if="hasFirst" b-style="{width: firstColWith}">\r\n          <col b-repeat="col in shownColums" data-locked-col?="col.locked" b-style="{width: col.width || \'auto\'}">\r\n        </colgroup>\r\n        <tbody>\r\n          <tr b-if="canSelectTotal" style="display:none" data-select-total>\r\n            <td class="tc-15-news-tips-box" colspan="{{countCols(colums)}}">\r\n                <div b-if="!isSelectTotal" class="text-center"><span class="text">已勾选本页{{selectedNum}}项, </span><a data-select-total-toggle href="javascript:;">勾选全部页面共{{totalNum}}项</a></div>\r\n                <div b-if="isSelectTotal" class="text-center"><span class="text">勾选全部页面共{{totalNum}}项, </span><a data-select-total-toggle href="javascript:;">已勾选本页{{selectedNum}}项</a></div>\r\n            </td>\r\n          </tr>\r\n          <tr data-tips b-if="_tips">\r\n            <td class="text-center" colspan="{{countCols(colums)}}">\r\n                <div>{{> _tips }}</div>\r\n            </td>\r\n          </tr>\r\n          <tr data-search-tips b-if="searchKey">\r\n            <td class="text-center" colspan="{{countCols(colums)}}">\r\n                <div b-if="totalNum"><span class="text">搜索"{{searchKey}}"，找到{{totalNum}}条结果。</span><a data-restore href="javascript:;">返回原列表</a></div>\r\n                <div b-if="!totalNum"><span class="text">抱歉，没有找到相关{{ searchItemName }}，尝试其他搜索条件。</span><a data-restore href="javascript:;">返回原列表</a></div>\r\n            </td>\r\n          </tr>\r\n          <tr data-index="{{$index}}" track-by="{{trackKey}}" b-ref="list" b-repeat="item in list"\r\n            b-attr="setTrAttr(trAttr, item)"\r\n            class="item-row {{selectedHighlight && item.$selected ? \'current\' : \'\'}}\r\n              {{item.$disable ? \'disable\': \'\'}} {{item.$class || \'\'}}">\r\n            <td b-if="hasFirst">\r\n              <div class="tc-15-first-checkbox">\r\n                <i b-if="item.$loading" class="n-loading-icon"></i>\r\n                <input class="tc-15-checkbox" disabled?="item.$disable || item.$disableCheckbox"\r\n                  data-checkbox\r\n                  b-if="!item.$loading" type="checkbox" b-model="item.$selected">\r\n              </div>\r\n            </td>\r\n            <td b-repeat="col in shownColums">\r\n              <div>\r\n                <span b-content="_getCellContent(item[col.key], item, col)"></span>\r\n              </div>\r\n            </td>\r\n          </tr>\r\n        </tbody>\r\n      </table>\r\n    </div>\r\n\r\n    <!-- 固定列 -->\r\n      <div data-locked b-if="lockedColums.length" class="fixed-column"\r\n        b-class="{\'fixed-column-shadow\': \'_hasXScroll\'}"\r\n        style="opacity:1; right: 0px; top: 0px;"\r\n        b-style="{width: _hasYScroll ? (lockedWidth + scrollBarSize) : lockedWidth}">\r\n          <div data-grid-head class="tc-15-table-fixed-head" style="width: auto"\r\n            b-style="{paddingRight: _hasYScroll ? scrollBarSize : 0}">\r\n              <table class="tc-15-table-box">\r\n                <colgroup>\r\n                  <col b-repeat="col in lockedColums" b-style="{width: col.width || \'auto\'}">\r\n                </colgroup><thead>\r\n                  <tr>\r\n                      <th b-repeat="col in lockedColums"\r\n                          data-orderfield="{{col.orderField || col.key}}">\r\n                        <div>\r\n                          <span b-content="_getHeadContent(col)"></span>\r\n                        </div>\r\n                        <!-- <i class="resize-line-icon" data-role="resizer" b-if="canResizeColum && $index < lockedColums.length - 1"></i> -->\r\n                      </th>\r\n                  </tr>\r\n                </thead></table>\r\n          </div>\r\n          <!-- ie 8 的 max-height 包含了滚动条 -->\r\n          <div data-grid-body  b-on-scroll="__synScroll()" class="tc-15-table-fixed-body"\r\n            style="border-bottom: none;overflow-x:hidden"\r\n            b-style="{\r\n              minHeight: _hasXScroll && _ie != 8 ? minHeight - scrollBarSize : minHeight,\r\n              height: _hasXScroll && _ie != 8 ? height - scrollBarSize : height,\r\n              maxHeight: _hasXScroll && _ie != 8 ? maxHeight - scrollBarSize : maxHeight\r\n            }">\r\n              <table class="tc-15-table-box tc-15-table-rowhover">\r\n                <colgroup>\r\n                  <col b-repeat="col in lockedColums" b-style="{width: col.width || \'auto\'}">\r\n                </colgroup>\r\n                <tbody>\r\n                  <tr data-select-total b-if="canSelectTotal" style="display:none">\r\n                    <td class="tc-15-news-tips-box" colspan="{{lockedColums.length}}"></td>\r\n                  </tr>\r\n                  <tr data-tips b-if="_tips">\r\n                    <td class="text-center" colspan="{{lockedColums.length}}"></td>\r\n                  </tr>\r\n                  <tr data-search-tips b-if="searchKey">\r\n                    <td class="text-center" colspan="{{lockedColums.length}}"></td>\r\n                  </tr>\r\n                  <tr data-index="{{$index}}" track-by="{{trackKey}}" b-ref="lockedList" b-repeat="item in list"\r\n                    b-attr="setTrAttr(trAttr, item)"\r\n                    class="item-row {{selectedHighlight && item.$selected ? \'current\' : \'\'}}\r\n                      {{item.$disable ? \'disable\': \'\'}} {{item.$class || \'\'}}">\r\n                    <td b-repeat="col in lockedColums">\r\n                      <div>\r\n                        <span b-content="_getCellContent(item[col.key], item, col)"></span>\r\n                      </div>\r\n                    </td>\r\n                  </tr>\r\n              </tbody></table>\r\n          </div>\r\n      </div>\r\n  </div>\r\n\r\n  <div data-pager class="tc-15-page" b-if="showState || showPagination">\r\n    <div class="tc-15-page-state" b-if="showState">\r\n      <span class="tc-15-page-text"><span b-template b-if="hasFirst">已选<strong>{{selectedNum}}</strong>项，</span>共<strong>{{totalNum}}</strong>项</span>\r\n    </div>\r\n    <div b-tag=pagination b-ref="pager" b-if="showPagination" b-with=\'{listFn: listFn.bind(this), page: page, count: count, totalNum: totalNum, demo: demo, keyword: keyword,\r\n      pageInterval: pageInterval,\r\n      countInterval: countInterval,\r\n      minCount: minCount,\r\n      maxCount: maxCount,\r\n      loading: loading\r\n      }\'></div>\r\n  </div>\r\n</div>\r\n',
			n = t("beejs"),
			r = t("../componentBase"),
			a = (t("../pagination"), t("./lib/scroll-bar-size").getScrollBarSize),
			s = (t("./lib/scroll-bar-size").getWidthWithoutScroll, {
				hasFirst: !0,
				firstColWith: "50px",
				selectedHighlight: !0,
				canSelectTotal: !1,
				isSelectTotal: !1,
				canResizeColum: !0,
				colMinWidth: 100,
				maxHeight: "auto",
				height: "auto",
				minHeight: 350,
				autoMaxHeight: !0,
				maxHeightOffset: 1,
				orderField: "",
				order: 1,
				showPagination: !0,
				count: 20,
				page: 1,
				totalNum: 0,
				showState: !0,
				shownColums: [],
				colums: [],
				list: [],
				trackKey: "",
				trAttr: {},
				emptyTips: "列表为空",
				searchKey: "",
				searchItemName: "结果",
				searchEmptyTips: "",
				initGetData: !0,
				loading: !1,
				scrollBaseSize: 0,
				_ie: n.utils.ie
			}),
			o = r.extend({
				$tpl: i,
				$afterInit: function() {
					var t = this;
					o.__super__.$afterInit.call(this),
					this._$el = $(this.$el),
					this.$gridHead = this._$el.find("[data-grid-head]"),
					this.$gridBody = this._$el.find("[data-grid-body]"),
					this.$set("scrollBarSize", a("def-scoll")),
					this.bindEvent(),
					this.autoMaxHeight && this.setMaxHeight(),
					setTimeout(function() {
						return t.initGetData && t.listFn()
					},
					0)
				},
				actionKey: "_action",
				actionTpl: '<span class="text-overflow"><a href="javascript:;" class="links">删除</a></span>',
				extraParam: {},
				offsetHeight: 0,
				countCols: function(t) {
					var e = t.filter(function(t) {
						return ! t.hide
					}).length;
					return e + !!this.$root.hasFirst
				},
				setTrAttr: function(t, e) {
					var i = {};
					for (var n in t) i[n] = e[t[n]];
					return i
				},
				getData: function() {},
				refresh: function(t) {
					t = t ||
					function() {},
					this.listFn(this.latestParam, t)
				},
				listFn: function(t, e) {
					var i = $.extend({},
					this.$data, t),
					n = this;
					e = e ||
					function() {},
					this.loading || (this.$set("loading", !0), this.latestParam = $.extend({},
					this.extraParam, {
						orderField: i.orderField,
						order: i.order,
						page: i.page,
						count: i.count,
						searchKey: i.searchKey
					}), this.getData(this.latestParam,
					function() {
						n.$dataCallback.apply(n, arguments),
						n.$set("loading", !1),
						e()
					}))
				},
				setExtraParam: function(t) {
					this.extraParam = t || {}
				},
				setData: function(t) {
					this.$checkAll(!1),
					this.list.forEach(function(t, e, i) {
						i.$set(e, {
							$selected: !1
						})
					});
					var e = $.extend(!0, {
						loading: !1
					},
					this.latestParam, t);
					this.hideTips(),
					e.searchKey || e.list.length || this.showTips(this.emptyTips),
					this.$set(e),
					this.autoMaxHeight && this.setMaxHeight()
				},
				setColums: function(t) {
					this.$replace("colums", t)
				},
				updateItem: function(t, e) {
					this.$refs.list[t].$set(e),
					this.$refs.lockedList && this.$refs.lockedList[t].$set(e)
					this.$emit("rowselect", this, t, this.$refs.list[t]);
				},
				removeItem: function(t) {
					this.list.splice(t, 1)
				},
				_getHeadContent: function(t) {
					var e;
					return e = this.$root.getHeadContent(t) || t.thTpl,
					e || (e = '<span b-if="col.order" data-order class="tc-15-th-sort-btn {{orderField === (col.orderField || col.key) ? \'current\': \'\'}}">\n          <span class="text-overflow">{{col.name}}</span>\n          <i class="{{orderField === (col.orderField || col.key) ? (order == 0 ? \'down-sort-icon\' : \'up-sort-icon\') : \'sort-icon\'}}"></i>\n        </span>\n        <span b-if="!col.order" class="text-overflow">{{col.name}}</span>'),
					e
				},
				getHeadContent: function() {},
				_getCellContent: function(t, e, i) {
					var n = this.$root.getCellContent(t, e, i) || i.tdTpl;
					return n || (n = i.key === this.actionKey ? "function" == typeof this.actionTpl ? this.actionTpl(e, i) : this.actionTpl: '<span class="text-overflow" title="{{col.name}}：{{item[col.key]}}">\n         {{{(typeof item[col.key] === "undefeind" || item[col.key] === "") ? "-" : item[col.key]}}}</span>'),
					n
				},
				getCellContent: function() {},
				showLoading: function(t, e) {
					t = t || "加载中",
					this.showTips('<i class="n-loading-icon"></i> <span class="text">' + t + "</span>"),
					e && $(this.$el).find("tr.item-row").css({
						opacity: .65,
						"pointer-events": "none"
					})
				},
				hideLoading: function() {
					$(this.$el).find("tr[data-tips] i.n-loading-icon").length && this.hideTips(),
					$(this.$el).find("tr.item-row").css({
						opacity: 1,
						"pointer-events": "all"
					})
				},
				showTips: function(t) {
					this.$set("_tips", t)
				},
				hideTips: function() {
					this.$set("_tips", "")
				},
				showSelectAllTips: function(t) {
					$(t).show()
				},
				hideSelectAllTips: function(t) {
					$(t).hide()
				},
				getSelected: function() {
					return this.list.filter(function(t) {
						return t.$selected
					})
				},
				setMaxHeight: function() {
					var t = this._$el.find("[data-pager]"),
					e = $(window).height() - (this.$gridHead.outerHeight() + t.outerHeight() + 40) - this.$gridHead.offset().top - this.maxHeightOffset;
					this._$el.filter(":visible").length && (this.$set({
						maxHeight: e
					}), this._$el.find("[data-grid-panel]").css("height", this.$gridBody.outerHeight() + this.$gridHead.outerHeight()), this.$set({
						_hasYScroll: this.$gridBody[0].scrollHeight > this.$gridBody[0].clientHeight,
						_hasXScroll: this.$gridBody[0].scrollWidth > this.$gridBody[0].clientWidth
					}))
				},
				checkWidth: function() {
					var t = !1;
					this.$gridHead.find("col").each(function() {
						"auto" == this.style.width && (t = !0)
					}),
					t || this.$lastCol.width("auto"),
					$(this.$refs.head).add($(this.$refs.body)).width(""),
					this.checkCellWidth()
				},
				checkCellWidth: function() {
					var t, e = this,
					i = this.$gridHead.find("th");
					if (this._$el.is(":visible")) {
						i.each(function(t, i) {
							var n = $(i),
							r = n.width();
							if (!e.hasFirst || 0 != t) {
								var a = e.getColByIndex(t),
								s = a.minWidth || e.colMinWidth;
								s > r && e.setCellWidth(t, r)
							}
						}),
						t = $(this.$refs.head).width(),
						t > this.$gridHead.width() && ($(this.$refs.head).width(t), $(this.$refs.body).width(t));
						var n = 0;
						i.filter("[data-locked-th]").each(function(t, e) {
							var i = $(e).width();
							n += i
						}),
						this.$set("lockedWidth", n)
					}
				},
				resize: function() {
					this.checkCellWidth(),
					this.autoMaxHeight && this._$el.is(":visible") && this.setMaxHeight(),
					this.resizeAutoWidth && this.$lastCol.width("auto")
				},
				backList: function() {
					this.listFn({
						page: 1,
						count: this.count,
						order: this.order,
						orderField: this.orderField,
						searchKey: !1
					})
				},
				bindEvent: function() {
					var t = this;
					this.$watch("colums",
					function() {
						var t = this.colums.filter(function(t) {
							return ! t.hide
						});
						this.$set({
							shownColums: t,
							lockedColums: t.filter(function(t) {
								return t.locked
							})
						}),
						this.$locked = this._$el.find("[data-locked]"),
						this.$lockedHead = this.$locked.find("[data-grid-head]"),
						this.$lockedBody = this.$locked.find("[data-grid-body]"),
						this._setLastCol(),
						this.checkWidth(),
						this.autoMaxHeight && this.setMaxHeight()
					},
					!0),
					this.$watch("list",
					function() {
						return t.$checkAll()
					}),
					this.$watch("list.length",
					function(e) {
						t.searchKey || (e ? t._tips == t.emptyTips && t.hideTips() : t.showTips(t.emptyTips))
					}),
					this.$watch("getSelected(list).length",
					function(t) {
						t = this.getSelectedLength ? this.getSelectedLength() : t,
						this.$set("selectedNum", t)
					}),
					this.$watch("ischeckAll",
					function(t) {
						t || this.$set("isSelectTotal", !1)
					},
					!0),
					$(window).on("resize",
					function() {
						t.resize()
					}),
					this._$el.on("mouseenter mouseleave", "[data-grid-body]>table>tbody>tr, [data-locked] [data-grid-body]>table>tbody>tr",
					function(e) {
						if (t.lockedColums.length) {
							var i = $(e.currentTarget),
							n = i.index(),
							r = "mouseenter" === e.type ? "addClass": "removeClass";
							t._$el.find("[data-grid-body]>table>tbody>tr").eq(n)[r]("tr-hover"),
							t._$el.find("[data-locked] [data-grid-body]>table>tbody>tr").eq(n)[r]("tr-hover")
						}
					})
				},
				$events: {
					"click th [data-order]": function(t) {
						var e, i = $(t.currentTarget).closest("th").attr("data-orderfield");
						e = i === this.orderField ? 1 - this.order: 1,
						this.listFn({
							orderField: i,
							order: e
						})
					},
					"mousedown [data-role=resizer]": function(t) {
						var e = $(t.currentTarget).closest("th").index();
						this.__draging = !0,
						this.__dragingIndex = e,
						this.__$col = $(this.$el).find("[data-grid-body] col").eq(e).add($(this.$el).find("[data-grid-head] col").eq(e)),
						this.__originlWidth = $(t.currentTarget).closest("th").width(),
						this.__lastWidth = this.__originlWidth,
						this.__originalX = t.clientX,
						t.preventDefault(),
						this._dragEventBind(),
						$("body").css("cursor", "e-resize")
					},
					"change [data-check-all]": function(t) {
						var e = this,
						i = t.target.checked;
						if (this.list.forEach(function(t, n) {
							t.$disable || t.$loading || t.$disableCheckbox || e.updateItem(n, {
								$selected: i
							})
						}), !this.list.filter(function(t) {
							return t.$disable || t.$loading || t.$disableCheckbox
						}).length) {
							var n = this._$el.find("[data-select-total]");
							i ? this.showSelectAllTips(n) : this.hideSelectAllTips(n)
						}
					},
					"click input:checkbox[data-checkbox]": function(t) {
						t.stopPropagation();
					},
					"change input:checkbox[data-checkbox]": function(t) {
						if (this.lockedColums.length) {
							var e = $(t.target).closest("tr").attr("data-index"),
							i = t.target.selected;
							this.updateItem(e, {
								$selected: i
							})
						}
					},
					"click a[data-restore]": function() {
						this.backList()
					},
					"click [data-select-total-toggle]": function() {
						var t = !this.isSelectTotal;
						this.$set("isSelectTotal", t)
					},
					"click tr[data-index]": function(t){
						var e = $(t.target).closest("tr").attr("data-index"),
						    i = this.list[e];

						if(!i.$disable && !i.$loading && !i.$disableCheckbox){
							if(!i.$selected && this.singleSelect){
								var me = this;
								this.list.forEach(function(t, n) {
									t.$disable || t.$loading || t.$disableCheckbox ||
									me.updateItem(n, {
										$selected: false
									})
								});
							}
							this.updateItem(e, {
								$selected: !i.$selected
							})
						}
					}
				},
				_synScroll: function() {
					$(this.$refs.head).css({
						left: -this.$gridBody[0].scrollLeft
					}),
					this.lockedColums.length && (this.$lockedBody[0].scrollTop = this.$gridBody[0].scrollTop)
				},
				__synScroll: function() {
					this.$gridBody[0].scrollTop = this.$lockedBody[0].scrollTop
				},
				_dragEventBind: function() {
					var t = this;
					$(document).off("mouseup.grid_view").on("mouseup.grid_view",
					function() {
						t.__draging && (t.__draging = !1, $(this).off("mousemove.grid_view"), $("body").css("cursor", ""), delete t.__$col, delete t.__lastWidth, delete t.__dragingIndex, t.autoMaxHeight && t.setMaxHeight())
					}).on("mousemove.grid_view",
					function(e) {
						var i, n;
						t.__draging && (i = e.clientX - t.__originalX, n = 1 * t.__originlWidth + i, t.setCellWidth(t.__dragingIndex, n), e.preventDefault())
					})
				},
				setCellWidth: function(t, e) {
					var i = this.getColByIndex(t),
					n = i.minWidth || this.colMinWidth,
					r = this.shownColums[this.shownColums.length - this.lockedColums.length - 1].minWidth || this.colMinWidth;
					n > e && (e = n);
					var a = $(this.$refs.body).width(),
					s = this.__$col || this.$gridHead.find("col").eq(t).add(this.$gridBody.find("col").eq(t)),
					o = this.__lastWidth,
					l = e - o,
					c = this.$gridHead.find("th:not([data-locked-th]):last").width();
					0 > l && $(this.$refs.head).width() > this.$gridHead.width() || l > 0 && r >= c - l ? ($(this.$refs.head).width(a + l), $(this.$refs.body).width(a + l)) : (0 > l || c - l > r) && this.$lastCol.width(c - l),
					s.width(e),
					this.__lastWidth && (this.__lastWidth = e)
				},
				getColByIndex: function(t) {
					return this.hasFirst && t--,
					this.shownColums[t]
				},
				$checkAll: function(t) {
					var e, i = this.$get("list");
					"boolean" != typeof t && (t = !i.filter(function(t) {
						return t.$selected && (e = !0),
						!(t.$selected || t.$disable || t.$loading || t.$disableCheckbox)
					}).length && e),
					this.$set("ischeckAll", t),
					t || this.$root.hideSelectAllTips(this.$root.$refs.selectedAllTips)
				},
				$dataCallback: function(t, e) {
					t || this.setData(e)
				},
				$getNoDataHtml: function() {
					var t = this.keyword ? this.searchNoData: this.filterNoData;
					return t
				},
				_setLastCol: function() {
					this.$lastCol = this.$gridHead.find("col:not([data-locked-col]):last").add(this.$gridBody.find("col:not([data-locked-col]):last"))
				}
			},
			{
				defaults: s
			});
			e.exports = o
		},
		{
			"../componentBase": 1,
			"../pagination": 8,
			"./lib/scroll-bar-size": 6,
			beejs: 28
		}],
		6 : [function(t, e, i) {
			"use strict";
			i.getScrollBarSize = function(t) {
				var e = document.createElement("p");
				e.style.width = "100%",
				e.style.height = "200px";
				var i = document.createElement("div");
				i.style.position = "absolute",
				i.style.top = "0px",
				i.style.left = "0px",
				i.style.visibility = "hidden",
				i.style.width = "200px",
				i.style.height = "150px",
				i.style.overflow = "hidden",
				i.className = t || "",
				i.appendChild(e),
				document.body.appendChild(i);
				var n = e.offsetWidth;
				i.style.overflow = "scroll";
				var r = e.offsetWidth;
				return n == r && (r = i.clientWidth),
				document.body.removeChild(i),
				n - r
			}
		},
		{}],
		7 : [function(t, e) {
			"use strict";
			var i = '<div data-role="input-slider"  class="num" b-on="$events" style="display:inline-block" b-style="style">\n  <span class="number-input-decoration">\n    <input b-ref="input" data-input b-model="value" class="tc-input-text" type="text">\n    <span class="arrows">\n        <a href="javascript:;" data-down>\n            <i class="sequence"></i>\n        </a>\n        <i class="line"></i>\n        <a href="javascript:;" data-up>\n            <i class="sequence desc"></i>\n        </a>\n    </span>\n  </span>\n  <div b-ref=\'slider\' class="ui_progress" style="display:none">\n    <div class="progress_area">\n        <div b-ref="sliderBar" class="progress_bar">\n            <div class="progress_bg">\n                <div class="progress_in"\n                  b-style="{width: Math.max(0, Math.min(100, ((value - min) / (max - min)) * 100)) + \'%\'}">\n                </div>\n                <a data-handler href="javascript:;" class="btn_drag"\n                   b-style="{left: Math.max(0, Math.min(100, ((value - min) / (max - min)) * 100)) + \'%\' }"></a>\n            </div>\n        </div>\n    </div>\n  </div>\n</div>\n',
			n = (t("beejs"), t("../slider-range")),
			r = n.extend({
				$tpl: i,
				showSlider: function() {
					$(this.$refs.slider).show()
				},
				hideSlider: function() {
					$(this.$refs.slider).hide()
				},
				$events: {
					"click [data-input]": function(t) {
						this.showSlider(),
						t.target.select()
					},
					"click [data-up]": function() {
						this.stepUp()
					},
					"click [data-down]": function() {
						this.stepDown()
					},
					keydown: function(t) {
						37 == t.keyCode || 40 == t.keyCode ? (this.stepDown(), t.preventDefault()) : (38 == t.keyCode || 39 == t.keyCode) && (this.stepUp(), t.preventDefault())
					}
				},
				$afterInit: function() {
					r.__super__.$afterInit.call(this);
					var t = this,
					e = $("body");
					e.on("click.slider_" + this.guid,
					function(e) {
						e.target === t.$refs.slider || $(t.$refs.slider).find(e.target).length || e.target === t.$refs.input || t.hideSlider()
					})
				}
			});
			e.exports = r
		},
		{
			"../slider-range": 20,
			beejs: 28
		}],
		8 : [function(t, e) {
			"use strict";
			var i = '<div data-role="pagination" class="tc-15-page-operate" b-on="$events">\n    <div b-template b-if="totalNum">\n    <span class="tc-15-page-text">每页显示行</span>\n    <div class="tc-15-page-select" data-page-select>\n        <a class="indent" href="javascript:;">{{count}}<span class="ico-arrow"></span></a>\n        <ul data-list class="tc-15-simulate-option tc-15-def-scroll">\n            <li data-count="{{c}}" b-repeat="c in setCountList(totalNum)">{{c}}</li>\n        </ul>\n    </div>\n    <a data-page="1" class="tc-15-page-first {{page<=1?\'disable\':\'\'}}" title="第一页" href="javascript:;"></a>\n    <a data-page="{{page-1}}" class="tc-15-page-pre {{page<=1?\'disable\':\'\'}}" title="上一页" href="javascript:;"></a>\n    <div class="tc-15-page-select" data-page-select disable?=\'lastPage==1\'>\n        <a class="tc-15-page-num" href="javascript:;">{{page}}/{{lastPage}}<span b-if="lastPage>1" class="ico-arrow"></span></a>\n        <ul class="tc-15-simulate-option tc-15-def-scroll">\n            <li title="前往第{{p}}页" data-page="{{p}}" b-repeat="p in setPageList(totalNum, count)">{{p}}</li>\n        </ul>\n    </div>\n    <a data-page="{{page*1+1}}" class="tc-15-page-next {{page==lastPage?\'disable\':\'\'}}" title="下一页" href="javascript:;"></a>\n    <a data-page="{{lastPage}}" class="tc-15-page-last {{page==lastPage?\'disable\':\'\'}}" title="最后一页" href="javascript:;"></a>\n    </div>\n</div>\n',
			n = (t("beejs"), t("../componentBase")),
			r = n.extend({
				constructor: function() {
					n.apply(this, arguments),
					this.bindEvent()
				},
				$beforeInit: function() {
					r.__super__.$beforeInit.call(this),
					this.originalCount = this.count
				},
				$tpl: i,
				$data: {
					pageInterval: 1,
					countInterval: 5,
					minCount: 10,
					maxCount: 50,
					totalNum: 0,
					page: 1,
					count: 20,
					lastPage: 1,
					demo: !1
				},
				selectedClass: "tc-15-page-selected",
				listFn: function() {
					var t = arguments.length <= 0 || void 0 === arguments[0] ? {}: arguments[0];
					console.log(t),
					console.log("实现接口接受翻页参数")
				},
				_listFn: function(t) {
					var e = this;
					this.loading || (this.loading = !0, this.listFn(t,
					function() {
						e.loading = !1
					}))
				},
				listToggle: function(t, e) {
					e !== !1 && (e = !t.hasClass(this.selectedClass)),
					e ? (t.addClass(this.selectedClass), t.children("[data-list]").show()) : (t.removeClass(this.selectedClass), t.children("[data-list]").hide())
				},
				setPageList: function(t, e) {
					for (var i = 1,
					n = [], r = Math.ceil(t / e); r >= i;) n.push(i),
					i += this.pageInterval;
					return this.$set({
						lastPage: r,
						page: Math.min(this.page || 1, r)
					}),
					n.reverse()
				},
				setCountList: function(t) {
					for (var e = [], i = 1 * this.minCount; i <= Math.max(1 * this.minCount, Math.min(1 * this.maxCount, 1 * t + 1 * this.countInterval - 1), this.originalCount);) e.push(i),
					i += 1 * this.countInterval;
					return e.reverse()
				},
				bindEvent: function() {
					var t = this;
					$(document).on("click",
					function(e) {
						var i = $(t.$el).find("[data-page-select]");
						t.listToggle(i.not(e.target).not($(e.target).closest("[data-page-select]")), !1)
					})
				},
				$events: {
					"click [data-page-select]:not([disable]) a": function(t) {
						this.listToggle($(t.currentTarget).parent())
					},
					"click [data-page]": function(t) {
						var e, i = $(t.target);
						i.hasClass("disable") || (e = 1 * i.attr("data-page") || this.page, this.demo && this.$set({
							page: e
						}), this.listToggle($(t.target).closest("[data-page-select]")), this._listFn({
							page: e,
							count: this.count
						}))
					},
					"click [data-count]": function(t) {
						var e = 1 * $(t.target).attr("data-count");
						this.demo && this.$set("count", e),
						this.listToggle($(t.target).closest("[data-page-select]")),
						this._listFn({
							page: 1,
							count: e
						})
					}
				}
			});
			e.exports = r
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		9 : [function(t, e) {
			"use strict";
			var i = '<div data-role="qc-popover" style="display:none;" b-style="style" class="tc-15-confirm-popout {{_getPosClass(position)}}">\n    <div class="tc-15-confirm-popout-bd">\n        <p class="tc-15-msg"><strong>{{title}}</strong>\n          <br b-if="content">\n          {{> content }}\n        </p>\n    </div>\n    <div class="tc-15-confirm-popout-ft">\n        <button class="tc-15-btn m" b-on-click="hide(true)">{{confirmKey}}</button>\n        <button class="tc-15-btn m weak" b-on-click="hide()">{{cancelKey}}</button>\n    </div>\n</div>\n',
			n = (t("beejs"), t("../qc-popover")),
			r = {
				top: "tc-15-confirm-popout-bottom",
				bottom: "tc-15-confirm-popout-top",
				"top left": "tc-15-confirm-popout-bottom align-end",
				"top right": "tc-15-confirm-popout-bottom align-start",
				"bottom left": "tc-15-confirm-popout-top align-end",
				"bottom right": "tc-15-confirm-popout-top align-start"
			},
			a = n.extend({
				$tpl: i,
				_getPosClass: function(t) {
					return r[t] || ""
				},
				hide: function(t) {
					var e = this,
					i = t ? this.onConfirm() : this.onCancel();
					i !== !1 && (i && i.then ? i.then(function() {
						a.__super__.hide.call(e)
					}) : a.__super__.hide.call(this))
				},
				onConfirm: function() {},
				onCancel: function() {}
			},
			{
				defaults: {
					availablePos: ["top left", "top right", "top", "bottom left", "bottom right", "bottom"],
					trigger: "click",
					arrowPad: 30,
					confirmKey: "确定",
					cancelKey: "取消",
					style: "width: auto",
					position: "bottom left"
				}
			});
			a.bootFromAttr("popup-confirm"),
			e.exports = a
		},
		{
			"../qc-popover": 15,
			beejs: 28
		}],
		10 : [function(t, e) {
			"use strict";
			var i = "<button\n  b-on=\"$events\"\n  class=\"tc-15-btn m{{className ? ' ' + className : ''}}{{disabled ? ' disabled' : ''}}\"\n  tabindex=\"0\" b-attr=\"attr\">{{label}}\n</button>\n",
			n = (t("beejs"), t("../componentBase")),
			r = (t("beejs/addons/event"), n.extend({
				$tpl: i,
				$events: {
					click: function() {
						this._executeAction()
					}
				},
				_executeAction: function() {
					this.disabled || ("function" == typeof this.action && this.action(this), this.$emit("action", this.$data))
				},
				setEnable: function(t) {
					this.$set("disabled", !t)
				},
				enable: function() {
					this.setEnable(!0)
				},
				disable: function() {
					this.setEnable(!1)
				}
			},
			{
				defaults: {
					disabled: !1,
					attr: {}
				}
			}));
			e.exports = r
		},
		{
			"../componentBase": 1,
			beejs: 28,
			"beejs/addons/event": 27
		}],
		11 : [function(t, e) {
			"use strict"; {
				var i = '<div class="tc-15-action-panel action-panel-root" b-on="handle()">\n  <div\n    b-repeat="widget in widgets"\n    data-widget-type="{{widget.type}}"\n    data-widget-name="{{widget.name}}"\n    b-style="{ float: widget.float || \'left\'}">\n\n    <!-- widget type: date-picker -->\n    <div b-tag="qc-date-picker" b-if="widget.type == \'date-picker\'" b-with="widget"></div>\n\n    <!-- widget type: action -->\n    <div b-tag="qc-action-button" b-if="widget.type == \'action\'" b-with="widget">{{widget.label}}</div>\n\n    <!-- widget type: action-list -->\n    <div b-tag="qc-dropdown-list" b-if="widget.type == \'action-list\'" b-with="widget"></div>\n\n    <!-- widget type: seperator -->\n    <div b-if="widget.type == \'seperator\'" class="tc-15-v-sep" role="separator"></div>\n\n    <!-- widget type: filter-expander -->\n    <button\n      b-if="widget.type == \'filter-expander\'"\n      class="tc-15-btn weak m for-select{{widget.expand ? \' show\' : \'\'}}">{{widget.label}}\n    </button>\n\n    <!-- widget type: search -->\n    <div b-tag="qc-search" b-if="widget.type == \'search\'" b-with="widget"></div>\n\n    <!-- widget type: filter-panel -->\n    <div\n      b-if="widget.type == \'filter-panel\'"\n      b-style="{ display: widget.expand ? \'block\' : \'none\' }"\n      class="tc-15-action-select-panle">\n\n      <div class="param-line" b-repeat="param in widget.params" data-param="{{param.key}}">\n        <strong>{{param.label}}</strong>\n        <p>\n          <span class="param-option" data-role="select-all">\n            <label>\n              <input type="checkbox" class="tc-15-checkbox" b-model="param.all" />{{param.allLabel || \'全部\'}}\n            </label>\n          </span>\n          <span class="param-option" b-repeat="option in param.options">\n            <label>\n              <input type="checkbox" class="tc-15-checkbox" b-model="option.checked" />{{option.label}}\n            </label>\n          </span>\n        </p>\n      </div>\n\n      <div class="tc-15-action-select-panle-btns">\n        <button class="tc-15-btn m" data-role="accept">确定</button>\n        <button class="tc-15-btn m weak" data-role="cancel">取消</button>\n      </div>\n    </div>\n\n    <!-- widget type: filter-result-tag-list -->\n    <div\n      b-if="widget.type == \'filter-result-tag-list\' && widget.visible && widget.result.length"\n      class="tc-15-tag-list">\n      <div class="tc-15-tag" tabindex="0"\n        b-repeat="param in widget.result"\n        data-clear-param="{{param.key}}">{{param.label}}：{{param.optionsText}}\n        <span class="tc-15-btn-close"></span>\n      </div>\n      <div class="tc-15-tag-clear" data-role="clear-options" role="button" tabindex="0" b-if="widget.result.length">清空筛选项</div>\n    </div>\n  </div>\n</div>\n',
				n = (t("beejs"), t("../componentBase"));
				t("beejs/addons/event")
			}
			t("../qc-action-button"),
			t("../qc-date-picker"),
			t("../qc-dropdown-list"),
			t("../qc-search");
			var r = {},
			a = n.extend({
				$tpl: i,
				$data: {
					widgets: []
				},
				findWidgetByName: function(t) {
					var e = $(this.$el).find('div[data-widget-name="' + t + '"]'),
					i = e.children(),
					n = i.prop("bee");
					return n || e.prop("bee")
				},
				handle: function s() {
					var t = {},
					e = {
						"action-list-expand": 'click div[data-widget-type="action-list"] button.tc-15-simulate-select',
						"action-list-execute": 'click div[data-widget-type="action-list"] ul.tc-15-simulate-option li',
						"action-list-mask": "click div.popup-mask",
						search: 'click div[data-widget-type="search"] button.search',
						"filter-expand": 'click div[data-widget-type="filter-expander"]',
						"filter-option-change": 'change div[data-widget-type="filter-panel"] span.param-option',
						"filter-accept": 'click div[data-widget-type="filter-panel"] button[data-role="accept"]',
						"filter-cancel": 'click div[data-widget-type="filter-panel"] button[data-role="cancel"]',
						"filter-param-clear": 'click div[data-widget-type="filter-result-tag-list"] .tc-15-tag',
						"filter-clear": 'click div[data-widget-type="filter-result-tag-list"] div[data-role="clear-options"]'
					},
					i = this,
					n = function(t) {
						return t.currentTarget ? $(t.currentTarget).closest("div[data-widget-type]").prop("bee") : "string" == typeof t ? $(i.$el).find('div[data-widget-type="' + t + '"]').prop("bee") : void 0
					},
					s = function(i, n) {
						t[e[i]] = n
					},
					a = function(t) {
						var e = t.result = {};
						t.params.forEach(function(t) {
							var i = e[t.key] = {};
							i.all = !!t.all,
							i.selected = [],
							t.options.forEach(function(t) {
								t.checked && i.selected.push(t.value)
							})
						})
					},
					o = function(t, e) {
						t.$replace("param.options", t.options.map(function(t) {
							return t = JSON.parse(JSON.stringify(t)),
							t.checked = e,
							t
						})),
						t.$replace("param.all", e)
					},
					l = function(t) {
						var e = n("filter-expander"),
						i = n("filter-panel"),
						r = n("filter-result-tag-list");
						e && e.$replace("widget.expand", t),
						i && i.$replace("widget.expand", t),
						r && n("filter-result-tag-list").$replace("widget.visible", !t)
					},
					c = function(t) {
						return JSON.parse(JSON.stringify(t))
					},
					h = function(t, e) {
						return JSON.stringify(t) == JSON.stringify(e)
					},
					d = function(t) {
						var e = n("filter-result-tag-list"),
						i = [],
						r = t.params.slice();
						r.sort(function(t, e) {
							return t.modifyTime - e.modifyTime
						}),
						r.forEach(function(t) {
							var e = [];
							t.options.forEach(function(t) {
								t.checked && e.push(t.label)
							}),
							e.length && i.push({
								label: t.label,
								key: t.key,
								optionsText: e.join(", ")
							})
						}),
						e.$replace("widget.result", i)
					},
					u = function(t) {
						t.sessionKey && t.lastState && (r[t.sessionKey] = c(t.lastState))
					},
					p = function(t) {
						return t.sessionKey && r[t.sessionKey] ? r[t.sessionKey] : t.params
					},
					f = function(t) {
						h(t.lastState, t.params) || (t.lastState = c(t.params), a(t), t.change && t.change.call(t, t), d(t)),
						u(t)
					},
					g = function(t) {
						var e = p(t);
						t.reset = function() {
							this.$replace("widget.params", c(e)),
							a(this),
							d(this)
						},
						t.reset()
					},
					m = function(t) {
						if (t) {
							var e = c(t.$data);
							t.reset = function() {
								this.$set(c(e))
							}
						}
					},
					v = function(t) {
						return h(t.lastState, t.params) ? !1 : (t.$replace("widget.params", c(t.lastState)), !0)
					};
					return this.$afterInit = function() {
						var t = n("filter-panel");
						t && (l(!1), g(t), f(t)),
						m(i.findWidgetByName("search")),
						m(i.findWidgetByName("date-picker"))
					},
					s("filter-expand",
					function(t) {
						var e = n(t).$get("widget.expand");
						l(!e)
					}),
					s("filter-option-change",
					function(t) {
						var e, i = $(t.currentTarget),
						n = i.closest(".param-line").prop("bee");
						if ("select-all" == i.data("role")) e = n.$get("param.all"),
						o(n, e);
						else {
							e = !0;
							for (var r = 0; r < n.options.length; r++) n.options[r].checked || (e = !1);
							n.$replace("param.all", e)
						}
						n.$replace("param.modifyTime", +new Date)
					}),
					s("filter-accept",
					function(t) {
						var e = n(t);
						f(e),
						l(!1)
					}),
					s("filter-cancel",
					function(t) {
						var e = n(t);
						v(e) && a(e),
						l(!1)
					}),
					s("filter-param-clear",
					function(t) {
						var e = $(t.currentTarget).data("clear-param"),
						i = $(t.delegateTarget).find('.param-line[data-param="' + e + '"]').prop("bee");
						o(i, !1),
						f(n("filter-panel"))
					}),
					s("filter-clear",
					function(t) {
						var e;
						$(t.delegateTarget).find(".param-line[data-param]").each(function(t, i) {
							o(i.bee, !1),
							i.bee.$replace("param.all", !1),
							e = e || i.bee
						}),
						f(n("filter-panel"))
					}),
					t
				}
			});
			e.exports = a
		},
		{
			"../componentBase": 1,
			"../qc-action-button": 10,
			"../qc-date-picker": 12,
			"../qc-dropdown-list": 13,
			"../qc-search": 16,
			beejs: 28,
			"beejs/addons/event": 27
		}],
		12 : [function(t, e) {
			"use strict";
			function i(t) {
				var e, i = /^\s*(\d{4})-(\d\d)-(\d\d)\s*/,
				n = new Date(0 / 0),
				r = i.exec(t);
				return r && (e = +r[2], n.setFullYear(r[1], e - 1, r[3]), e != n.getMonth() + 1 && n.setTime(0 / 0)),
				n
			}
			function n(t) {
				return t ? ("string" == typeof t && (t = i(t)), 1e4 * t.getFullYear() + 100 * (t.getMonth() + 1) + t.getDate()) : 0
			}
			function r(t) {
				function e(t) {
					var e = String(t);
					return 1 === e.length && (e = "0" + e),
					e
				}
				return "number" == typeof t ? String(t).replace(/(\d\d\d\d)(\d\d)(\d\d)/, "$1-$2-$3") : [t.getFullYear(), e(t.getMonth() + 1), e(t.getDate())].join("-")
			}
			function a(t, e, i) {
				var n = t[e];
				t[e] = t[i],
				t[i] = n
			}
			function s(t) {
				if (/^(\d{4})[-\s\.,\/]*(\d\d)[-\s\.,\/]*(\d\d)\s*$/.test(t)) {
					var e = RegExp.$1,
					i = RegExp.$2,
					n = RegExp.$3;
					return [e, i, n].join("-")
				}
				return null
			}
			function o(t) {
				return ! isNaN( + i(t))
			}
			function l(t, e) {
				return t = new Date(t),
				t.setDate(t.getDate() + e),
				t
			}
			var c = '<div class="tc-15-calendar-select-wrap tc-15-calendar{{selectRange ? \'2\' : \'1\'}}-hook">\n\n  <div class="mask" b-if="calPopup" b-on-click="this.cancelPick()" style="position: fixed; left: 0; top: 0; bottom: 0; right: 0; z-index: 99; background: transparent; opacity: 0">\n  </div>\n\n  <div role="tablist" b-if="tabs">\n    <span b-repeat="tab in tabs" role="tab" tabindex="0"\n          class="{{tab.current ? \'current\' : \'\'}}"\n          data-from="{{tab.from}}"\n          data-to="{{tab.to}}"\n          b-on="{ click: handleTabSelect }">{{tab.label}}</span>\n  </div>\n\n  <div class="tc-15-calendar-select{{calPopup ? \' show\' : \'\'}}" b-if="showCalendar">\n    <button class="tc-15-simulate-select m{{calPopup ? \' show\' : \'\'}}" b-on="{ mousedown: handlePickButtonDown }">{{displayCalendarText(value)}}</button>\n\n    <div class="tc-15-calendar-triangle-wrap"></div>\n\n    <div class="tc-15-calendar-triangle"></div>\n\n    <div class="tc-15-calendar tc-15-calendar{{selectRange ? \'2\' : \'1\'}}" b-on="{ click: handleDateClick }">\n      <div class="tc-15-calendar-cont" style="font-size: 0;">\n        <table class="{{month.className}}" cellspacing="0" b-repeat="month in months">\n          <caption>{{month.display}}</caption>\n          <thead>\n            <tr>\n              <th b-repeat="weekday in langs[lang].weekdays">{{weekday}}</th>\n            </tr>\n          </thead>\n          <tbody>\n            <tr>\n              <td colspan="7">\n                <i class="tc-15-calendar-i-pre-m{{month.hasPrev ? \'\' : \' disabled\'}}" tabindex="0"\n                   b-if="$index == 0"\n                   b-on="{ click: prevMonth }">\n                  <b>\n                    <span b-if="month.hasPrev">{{langs[lang].prev_month}}</span>\n                    <span b-if="!month.hasPrev">{{langs[lang].prev_month_disabled}}</span>\n                  </b>\n                </i>\n                <i class="tc-15-calendar-i-next-m{{month.hasNext ? \'\' : \' disabled\'}}" tabindex="0"\n                   b-if="$index == months.length - 1"\n                   b-on="{ click: nextMonth }">\n                  <b>\n                    <span b-if="month.hasNext">{{langs[lang].next_month}}</span>\n                    <span b-if="!month.hasNext">{{langs[lang].next_month_disabled}}</span>\n                  </b>\n                </i>\n              </td>\n            </tr>\n            <tr b-repeat="week in month.weeks">\n              <td b-repeat="day in week.days" class="{{day.className}}" data-date="{{day.date}}">\n                {{day.display}}\n              </td>\n            </tr>\n          </tbody>\n        </table>\n      </div>\n      <div class="tc-15-calendar-footer">\n        <div class="tc-15-calendar-input" b-if="selectRange">\n          <div class="tc-15-input-text-wrap m">\n            <input type="text" class="tc-15-input-text" data-role="date-from" value="{{value.tab.display || selected.from}}" b-on="{ keyup: parseDateInput, blur: validateDateInput }">\n          </div>\n          <span role="separator">{{langs[lang].to}}</span>\n          <div class="tc-15-input-text-wrap m">\n            <input type="text" class="tc-15-input-text" data-role="date-to" value="{{value.tab.display || selected.to}}" b-on="{ keyup: parseDateInput, blur: validateDateInput }">\n          </div>\n          <!--<div b-if="formatError" class="tc-15-calendar-error">格式错误，应为YY-MM-DD</div>-->\n        </div>\n        <div class="tc-15-calendar-btns" b-style="{width: selectRange ? \'auto\' : \'100%\'}">\n          <button class="tc-15-btn m" b-on="{ click: acceptPick }" b-if="selectRange">{{langs[lang].ok}}</button>\n          <button class="tc-15-btn m weak" b-on="{ click: cancelPick }" b-if="selectRange">{{langs[lang].cancel}}</button>\n        <button class="tc-15-btn m pull-left" b-on="{ click: pickToday }" b-if="!selectRange">{{langs[lang].today}}</button>\n        <button class="tc-15-btn m weak pull-right" b-on="{ click: clearPick }" b-if="!selectRange">{{langs[lang].clear}}</button>\n        </div>\n      </div>\n      <div class="tc-15-calendar-for-style"></div>\n    </div>\n  </div>\n</div>\n',
			h = (t("beejs"), t("../componentBase")),
			d = t("beejs/addons/event");
			t("beejs/src/es5-bee-shim");
			var u = "tc-15-calendar-first",
			p = "tc-15-calendar-current",
			f = "tc-15-calendar-last",
			g = "tc-15-calendar-today",
			m = "tc-15-calendar-dis",
			v = "tc-15-calendar-left",
			y = "tc-15-calendar-right",
			b = {
				months: [],
				selected: {
					from: null,
					to: null
				},
				value: {
					from: null,
					to: null
				},
				range: {
					min: null,
					max: null,
					maxLength: 0
				},
				today: r(new Date),
				selectRange : false,
				focusDate: null,
				showCalendar: !0,
				calPopup: !1,
				lang: "zh-cn",
				langs: {
					"zh-cn": {
						caption_year: "年",
						caption_month: "月",
						weekdays: ["日", "一", "二", "三", "四", "五", "六"],
						to: "至",
						ok: "确定",
						cancel: "取消",
						today: "今天",
						clear: "清空",
						prev_month: "转到上个月",
						next_month: "转到下个月",
						prev_month_disabled: "之前时间不可选",
						next_month_disabled: "之后时间不可选"
					},
					"en-us": {
						caption_year: "/",
						caption_month: "",
						weekdays: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
						to: "To",
						ok: "OK",
						cancel: "Cancel",
						today: "Today",
						clear: "Clear",
						prev_month: "Previous Month",
						next_month: "Next Month",
						prev_month_disabled: "Invalid for date before",
						next_month_disabled: "Invalid for date after"
					}
				}
			},
			x = h.extend({
				constructor: function() {
					h.apply(this, arguments),
					this._update(),
					this._updateValue()
				},
				getState: function() {
					var t = this.selected;
					if (!this.selectRange) return "range";
					return t.from && t.to && o(t.from) && o(t.to) ? t.from == t.to ? "single": "range": "empty"
				},
				$mixins: [d],
				$tpl: c,
				_getLangText: function(t) {
					return this.$data.langs[this.$data.lang][t]
				},
				_getClassNameMapper: function() {
					var t = this,
					e = {
						from: n(this.$data.selected.from),
						to: n(this.$data.selected.to)
					},
					r = {
						min: n(this.$data.range.min),
						max: n(this.$data.range.max)
					};
					e.to < e.from && a(e, "from", "to"),
					r.max < r.min && a(r, "min", "max");
					var o = this.$data.range.maxLength;
					if (o && e.from == e.to) {
						var c = i(s(e.from)),
						h = i(s(e.from)),
						d = l(c, -o),
						v = l(h, +o);
						d = n(d),
						v = n(v),
						(!r.min || d > r.min) && (r.min = d),
						(!r.max || v < r.max) && (r.max = v)
					}
					return function(i) {
						i = n(i);
						var a = [];
						return "empty" != t.getState() && i >= e.from && i <= e.to && a.push(i == e.from && i == e.to ? g: i == e.from ? u: i == e.to ? f: p),
						(r.min && i < r.min || r.max && i > r.max) && a.push(m),
						a.join(" ")
					}
				},
				_buildMonth: function(t, e) {
					var i, a = t.getMonth(),
					s = [],
					o = this._getClassNameMapper(),
					l = null,
					c = null,
					h = function(t) {
						if (t.getMonth() == (a + 1) % 12) return ! 1;
						for (var i = [], n = 0; 7 > n; n++) {
							if (t.getMonth() == a) {
								var s = {
									display: t.getDate(),
									date: r(t),
									className: o(t)
								};
								i.push(s),
								l = l || new Date(t),
								c = new Date(t)
							} else i.push({
								className: m
							});
							t.setDate(t.getDate() + 1)
						}
						return {
							days: i,
							className: e
						}
					},
					d = new Date(t);
					for (d.setDate(1 - d.getDay()); i = h(d);) s.push(i);
					return {
						weeks: s,
						display: t.getFullYear() + this._getLangText("caption_year") + (a + 1) + this._getLangText("caption_month"),
						hasPrev: !this.$data.range.min || n(l) > n(this.$data.range.min),
						hasNext: !this.$data.range.max || n(c) < n(this.$data.range.max)
					}
				},
				_resolveDate: function(t) {
					var e = this.today;
					if (!t) return null;
					if (/%TODAY([+-]\d+)?/.test(t)) {
						var n = parseInt(RegExp.$1, 10) || 0,
						a = i(e);
						a.setDate(a.getDate() + n),
						t = r(a)
					}
					return t
				},
				_resolveRange: function(t) {
					return t.from && (t.from = this._resolveDate(t.from)),
					t.to && (t.to = this._resolveDate(t.to)),
					t.min && (t.min = this._resolveDate(t.min)),
					t.max && (t.max = this._resolveDate(t.max)),
					t
				},
				_update: function() {
					this.$replace("selected", this._resolveRange(this.selected)),
					this.$replace("range", this._resolveRange(this.range));
					var t = this.focusDate;
					t || (t = this.selected.to ? i(this.selected.to) : new Date, isNaN(t) && (t = new Date), this.focusDate = t);
					var e = [],
					n = new Date(t);
					n.setDate(1),
					e.unshift(this._buildMonth(n, v));
					if(this.selectRange){
						n.setMonth(n.getMonth() - 1);
						e.unshift(this._buildMonth(n, y));
					}
					this.$replace("months", e)
				},
				_updateTabs: function(t) {
					var e = this.$data.tabs;
					if (e) for (var i = 0; i < e.length; i++) {
						var n = this._resolveRange(e[i]),
						r = n.from == t.from && n.to == t.to;
						e.$set(i, {
							current: r
						})
					}
				},
				_jumpMonth: function(t, e) {
					$(t.target).closest("i").hasClass("disabled") || (this.focusDate.setMonth(this.focusDate.getMonth() + e), this._update())
				},
				nextMonth: function(t) {
					this.$root._jumpMonth(t, 1)
				},
				prevMonth: function(t) {
					this.$root._jumpMonth(t, -1)
				},
				handlePickButtonDown: function() {
					this.$replace("calPopup", !this.$data.calPopup)
				},
				handleDateClick: function(t) {
					var e = $(t.target);
					if (!e.hasClass(m)) {
						var i = e.data("date");
						if (i) {
							for (var r = this; ! (r instanceof x);) r = r.$parent;
							var a = r.$data.selected;
							switch (r.getState()) {
							case "empty":
								a.from = a.to = i;
								break;
							case "single":
								var s = n(a.from),
								o = n(i);
								if (s == o) break;
								s > o ? a.from = i: a.to = i;
								break;
							case "range":
								a.from = a.to = i
							}
							r._update();
							!this.selectRange && this.acceptPick();
						}
					}
				},
				parseDateInput: function(t) {
					var e = $(t.target).val(),
					a = s(e);
					if (a) {
						var o, c, h = $(t.target).data("role"),
						d = this.selected,
						u = this.range;
						if ("date-from" == h ? (o = n(a), c = n(d.to) || o) : "date-to" == h && (c = n(a), o = n(d.from) || c), o || c) {
							if (o > c) {
								var p = o;
								o = c,
								c = p
							}
							if (u.min && (o = Math.max(n(u.min), o)), u.max && (c = Math.min(n(u.max), c)), this.range.maxLength) {
								var f = l(i(d.from), this.range.maxLength),
								g = l(i(d.to), -this.range.maxLength);
								f = n(f),
								g = n(g),
								"date-to" == h && c > f && (c = f),
								"date-from" == h && g > o && (o = g)
							}
							isNaN(o) || (d.from = r(o)),
							isNaN(c) || (d.to = r(c));
							var m = this.focusDate;
							"date-from" == h && (o = i(d.from), (o.getMonth() < m.getMonth() - 1 || o.getMonth() > m.getMonth()) && (o.setMonth(o.getMonth() + 1), this.focusDate = o)),
							"date-to" == h && (c = i(d.to), (c.getMonth() < m.getMonth() - 1 || c.getMonth() > m.getMonth()) && (this.focusDate = c)),
							this._update();
							var v = "date-from" == h ? d.from: d.to;
							v != $(t.target).val() && $(t.target).val(v)
						}
					}
				},
				validateDateInput: function(t) {
					var e = $(t.target).val(),
					i = s(e);
					if (!i && !this.value.tab && !this.value.tab.display) {
						var n = this.$data.selected;
						$(t.target).val(n[$(t.target).data("role").split("-").pop()])
					}
				},
				_updateValue: function() {
					var t = this.selected;
					this._updateTabs(this.selected);
					for (var e = {
						from: t.from,
						to: t.to
					},
					i = this.tabs, n = 0; i && n < i.length; n++) {
						var r = i[n];
						if (r.from == e.from && r.to == e.to) {
							e.tab = r;
							break
						}
					}
					return this.$replace("value", e),
					e
				},
				displayCalendarText: function(t) {
					return t && t.tab && t.tab.display ? t.tab.display:
					(!this.selectRange ? t.from :[t.from, this.langs[this.lang].to, t.to].join(" "))
				},
				acceptPick: function() {
					var t = this._updateValue(),
					e = i(this.selected.to);
					isNaN( + e) || (this.focusDate = e),
					this._update(),
					this.$replace("calPopup", !1),
					this.$emit("datepick", t)
				},
				cancelPick: function() {
					var t = this.$data.selected,
					e = this.$data.value;
					t.from = e.from || t.from,
					t.to = e.to || t.to;
					var n = i(t.to);
					isNaN( + n) || (this.focusDate = n),
					this._update(),
					this.$replace("calPopup", !1)
				},
				pickToday: function(){
					var t = r(new Date),
					    o = this.$data.selected;
					o.from = o.to = t;
					this._update();
					!this.selectRange && this.acceptPick();
				},
				clearPick: function(){
					var o = this.$data.selected;
					o.from = o.to = null;
					this._update();
					!this.selectRange && this.acceptPick();
				},
				handleTabSelect: function(t) {
					var e = $(t.target);
					if (!e.hasClass("current")) {
						var i = e.data("from"),
						n = e.data("to"),
						r = e.text();
						this.$root.setSelectedRange(i, n, r),
						this.$root.acceptPick()
					}
				},
				setSelectedRange: function(t, e, n) {
					if (!t || !e) throw new Error("请设置选择范围");
					this.$data.selected.from = this._resolveDate(t),
					this.$data.selected.to = this._resolveDate(e),
					this.$data.selected.label = n,
					this._updateValue();
					var r = i(e);
					isNaN( + r) || (this.focusDate = r),
					this._update()
				},
				setAllowRange: function(t, e, i) {
					this.$data.range.min = this._resolveDate(t),
					this.$data.range.max = this._resolveDate(e),
					this.$data.range.maxLength = i,
					this._update()
				},
				getValue: function(v){
					if(this.selectRange){
						return this._updateValue();
					}else{
						return this.selected.from;
					}
				},
				setValue: function(v1, v2, label){
					if(!v1 && !v2 && !this.selectRange){
						var o = this.$data.selected;
						o.from = o.to = null;
						this._update();
						return;
					}
					this.setSelectedRange(v1, v2 || v1, label);
				}
			},
			{
				defaults: b
			});
			e.exports = x
		},
		{
			"../componentBase": 1,
			beejs: 28,
			"beejs/addons/event": 27,
			"beejs/src/es5-bee-shim": 46
		}],
		13 : [function(t, e) {
			"use strict";
			var i = '<div b-on="$events" data-role="qcSelect" class="tc-15-simulate-select-wrap">\n	<button data-handler class="tc-15-simulate-select m{{popup ? \' show\' : \'\'}}">{{simulateSelect ? (selected ? selected.label : label) : label}}</button>\n  <div class="dropdown-list-mask" style="left: 0; right: 0; bottom: 0; top: 0; position: fixed; background: transparent; z-index: 999;" b-style="{display: popup ? \'block\' : \'none\'}"></div>\n	<ul data-list class="tc-15-simulate-option" style="z-index: 1000;" b-style="{ display: popup ? \'block\' : \'none\'}">\n		<span b-content="listTpl"></span>\n	</ul>\n</div>\n',
			n = (t("beejs"), t("../componentBase")),
			r = {
				popup: !1,
				simulateSelect: !1,
				label: "更多",
				list: []
			},
			a = n.extend({
				$tpl: i,
				listTpl: '<li data-item b-repeat="item in list" tabindex="0">{{item.label}}</li>',
				constructor: function() {
					var t = this;
					n.apply(this, arguments);
					var e = this.selected || this.list[0];
					this.$set("selected", e),
					this.popup ? this.open() : this.close(),
					$(window).on("click.qc-dropdown-list",
					function(e) {
						$(e.target).parents().is(t.$el) || t.close()
					})
				},
				$beforeDestroy: function() {
					$(window).off("click.qc-dropdown-list")
				},
				open: function() {
					this.$set("popup", !0)
				},
				close: function() {
					this.$set("popup", !1)
				},
				select: function(t) {
					var e;
					"object" == typeof t ? e = this.list[t.$index] || t: isNaN(1 * t) || (e = this.list[t]),
					e && (this.close(), this.$replace("selected", e), this.$emit("selected", e), "function" == typeof e.action && e.action.call(e, e))
				},
				$events: {
					"click [data-handler]": function() {
						this.popup ? this.close() : this.open()
					},
					"click [data-item]": function(t) {
						this.select(t.currentTarget)
					},
					"click .dropdown-list-mask": function() {
						this.close()
					}
				}
			},
			{
				defaults: r
			});
			e.exports = a
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		14 : [function(t, e) {
			"use strict";
			function i(t) {
				if (!t) return {};
				var e, i, n;
				if (t = String(t), "current" == t) e = (new Date).getFullYear(),
				i = (new Date).getMonth() + 1;
				else {
					if (! (n = a.exec(t))) throw new RangeError("日期格式不正确，请使用 yyyymm 的格式");
					e = parseInt(n[1], 10),
					i = parseInt(n[2], 10)
				}
				return {
					year: e,
					month: i,
					value: 100 * e + i
				}
			}
			var n = '<div class="tc-15-calendar-select-wrap tc-15-calendar2-hook">\r\n  <div class="tc-15-calendar-select tc-15-calendar-month show">\r\n    <button class="tc-15-simulate-select m{{state.popup ? \' show\' : \'\'}}" b-on-click="_togglePopup()">{{state.year}} 年 {{state.month}} 月</button>\r\n    <div class="tc-15-calendar-triangle-wrap" b-if="state.popup"></div>\r\n    <div class="tc-15-calendar-triangle" b-if="state.popup"></div>\r\n    <div class="tc-15-calendar tc-15-calendar2" b-if="state.popup" b-on="{click: _stopPropagation}">\r\n      <div class="tc-15-calendar-cont">\r\n        <table class="tc-15-calendar-mm" cellspacing="0">\r\n          <caption>\r\n            {{state.year}}年\r\n          </caption>\r\n          <tbody>\r\n          <tr>\r\n            <td colspan="2">\r\n              <i class="tc-15-calendar-i-pre-m{{state.prevYearExcceed ? \' disabled\' : \'\'}}"\r\n                 tabindex="0" b-on-click="_setYear(state.year - 1)">\r\n                <b><span>{{state.prevYearExcceed ? texts.prevYearDisabled : texts.prevYear}}</span></b>\r\n              </i>\r\n            </td>\r\n            <td colspan="2">\r\n              <i class="tc-15-calendar-i-next-m{{state.nextYearExcceed ? \' disabled\' : \'\'}}"\r\n                 tabindex="0" b-on-click="_setYear(state.year + 1)">\r\n                <b><span>{{state.nextYearExcceed ? texts.nextYearDisabled : texts.nextYear}}</span></b>\r\n              </i>\r\n            </td>\r\n          </tr>\r\n          <tr b-repeat="monthRow in [0, 1, 2]">\r\n            <td b-repeat="monthCol in [1, 2, 3, 4]" class="{{_getMonthClass(state.year, monthRow * 4 + monthCol, selected)}}"\r\n                b-on-click="_pickMonth(monthRow * 4 + monthCol)">\r\n              {{monthRow * 4 + monthCol}}月\r\n            </td>\r\n          </tr>\r\n          </tbody>\r\n        </table>\r\n      </div>\r\n      <div class="tc-15-calendar-for-style"></div>\r\n    </div>\r\n  </div>\r\n</div>',
			r = (t("beejs"), t("../componentBase")),
			a = /^(\d{4})(\d{2})$/,
			s = {
				mode: "single",
				minValue: null,
				maxValue: "current",
				state: {
					popup: !1,
					year: (new Date).getFullYear(),
					month: (new Date).getMonth() + 1
				},
				texts: {
					prevYear: "转到上一年",
					prevYearDisabled: "上一年不可用",
					nextYear: "转到下一年",
					nextYearDisabled: "下一年不可用"
				}
			},
			o = r.extend({
				$tpl: n,
				$afterInit: function() {
					var t = this;
					this.value && this._updateValue(this.value),
					this._updateState(),
					this._updateSelected(),
					this.$watch("value", this._setValue),
					$(document).on("click", this._globalClickHandler = function() {
						return t.toggling || t.$set("state.popup", !1)
					})
				},
				$destroy: function() {
					$(document).off("click", this._globalClickHandler)
				},
				$valuekey: "value",
				_stopPropagation: function(t) {
					t.stopPropagation()
				},
				_setValue: function(t) {
					var e = i(t);
					e.year && !this._monthExceed(e.year, e.month) && (this.$set("state", $.extend(this.state, {
						year: e.year,
						month: e.month
					})), this._updateState(), this._updateSelected())
				},
				_togglePopup: function() {
					var t = this;
					this.toggling = !0,
					this.$set("state.popup", !this.state.popup),
					setTimeout(function() {
						return t.toggling = !1
					})
				},
				_updateState: function() {
					this.$set("state", $.extend(this.state, {
						prevYearExcceed: this._yearExceed(this.state.year - 1),
						nextYearExcceed: this._yearExceed(this.state.year + 1)
					}))
				},
				_updateSelected: function() {
					this.$replace("selected", {
						year: this.state.year,
						month: this.state.month,
						toString: function() {
							return String(100 * this.year + this.month)
						}
					});
					var t = this.selected.toString();
					this.value != t && this.$set("value", t)
				},
				_yearExceed: function(t) {
					var e = i(this.minValue).year,
					n = i(this.maxValue).year;
					return e && e > t || n && t > n
				},
				_monthExceed: function(t, e) {
					var n = 100 * t + e,
					r = i(this.minValue).value,
					a = i(this.maxValue).value;
					return r && r > n || a && n > a
				},
				_getMonthClass: function(t, e) {
					return this._monthExceed(t, e) ? "tc-15-calendar-dis": this.selected.year == this.state.year && this.selected.month == e ? "tc-15-calendar-mm-select": void 0
				},
				_setYear: function(t) {
					this._yearExceed(t) || (this.$set("state", $.extend(this.state, {
						year: t
					})), this._updateState())
				},
				_pickMonth: function(t) {
					this._monthExceed(this.state.year, t) || (this.$set("state", $.extend(this.state, {
						month: t
					})), this._updateSelected(), this.$set("state", $.extend(this.state, {
						popup: !1
					})))
				}
			},
			{
				defaults: s
			});
			e.exports = o
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		15 : [function(t, e) {
			"use strict";
			function i(t, e) {
				var i = (e[0], e.offset() || {
					left: 0,
					top: 0
				}),
				n = e.scrollTop(),
				r = e.scrollLeft();
				return {
					top: t.top + n - i.top,
					left: t.left + r - i.left
				}
			}
			var n = '<div data-role="qc-popover" style="display:none;z-index:999" class="tc-15-bubble {{_getPosClass(position)}}" b-style="style">\n    <div class="tc-15-bubble-inner" b-style="_getLeft(position)">\n        {{> content }}\n    </div>\n</div>\n',
			r = (t("beejs"), t("../componentBase")),
			a = t("../../lib/box"),
			s = {
				top: "tc-15-bubble-bottom",
				left: "tc-15-bubble-right",
				bottom: "tc-15-bubble-top",
				right: "tc-15-bubble-left",
				"top left": "tc-15-bubble-bottom",
				"top right": "tc-15-bubble-bottom",
				"bottom left": "tc-15-bubble-top",
				"bottom right": "tc-15-bubble-top"
			},
			o = {
				position: "bottom",
				auto: !0,
				content: "",
				offset: {
					top: 0,
					left: 0
				},
				arrowOffset: 8,
				arrowPad: 14,
				trigger: "hover",
				hideDelay: 300,
				hideDestroy: !1,
				availablePos: ["top", "left", "bottom", "right", "top left", "top right", "bottom left", "bottom right"]
			},
			l = {
				hover: ["mouseenter", "mouseleave"],
				click: ["click", "click"],
				focus: ["focusin", "focusout"]
			},
			c = [],
			h = r.extend({
				$tpl: n,
				$afterInit: function() {
					h.__super__.$afterInit.call(this),
					this._$el = $(this.$el),
					this.handler ? this.$handler = $(this.handler) : (this.$handler = $(this.$content).children(), this.handler = this.$handler[0], this._$el.before(this.$handler)),
					this.target ? this.$target = $(this.target) : (this.target = this.handler, this.$target = this.$handler),
					"function" == typeof this.attachEl ? this.attachEl(this.$el) : (this.attachEl ? $(this.attachEl) : this.$target).after(this.$el),
					this.$handler.data("qc-popover", this),
					this.$box = $(this.box || a.getBox(this.$el)),
					this.bindEvent(),
					c.push(this)
				},
				$afterDestroy: function() {
					h.__super__.$afterDestroy.call(this);
					var t = c.indexOf(this);
					t > -1 && c.splice(t, 1),
					this.$handler.removeData("qc-popover")
				},
				target: null,
				handler: null,
				attachEl: null,
				reposition: function(t) {
					var e = this._offset(t),
					i = this.auto && this.suggested(t, e);
					if (i && i !== t && (t = i, e = this._offset(t)), t && -1 == this.availablePos.indexOf(t)) throw new Error('invalid position "' + t + '"');
					this.$set("position", t),
					this._$el.css(e)
				},
				show: function() {
					this._$el.fadeIn("fast"),
					this.state = !0,
					this.reposition(this.position)
				},
				hide: function() {
					this.state = !1,
					this._$el.hide(),
					this.hideDestroy && this.$destroy(!0)
				},
				suggested: function(t) {
					{
						var e, i, n = this.$box,
						r = this.$target,
						a = this.arrowOffset,
						s = r.offset(),
						o = n.offset() || {
							top: 0,
							left: 0
						},
						l = (s.left, s.top, r.outerWidth()),
						c = r.outerHeight(),
						h = this._$el.outerWidth() + a,
						d = this._$el.outerHeight() + a;
						n[0]
					}
					e = n.innerWidth(),
					i = n.innerHeight();
					var u = {
						top: !0,
						bottom: !0,
						left: !0,
						right: !0
					};
					s.top + c + d > o.top + i && (u.bottom = !1),
					s.top - o.top < d && (u.top = !1),
					s.left - o.left < h && (u.left = !1),
					s.left + l + h > o.left + e && (u.right = !1);
					var p = t.split(/\s+/);
					if (u[p[0]] && (p[1] ? u[p[1]] : !0) && this.availablePos.indexOf(t) > -1) return t;
					for (var f, g = 0; f = this.availablePos[g]; g++) if (p = f.split(/\s+/), u[p[0]] && (p[1] ? u[p[1]] : !0)) return f;
					return this.availablePos[0]
				},
				_offset: function(t) {
					var e = this.arrowOffset,
					n = this.arrowPad,
					r = this._$el.outerWidth(),
					a = this._$el.outerHeight(),
					s = this.$target.offset();
					if (!s) throw new Error("could not get bounding client rect of `target`");
					var o, l = this.$target.outerWidth(),
					c = this.$target.outerHeight(),
					h = i(s, this._$el.offsetParent());
					if (!h) throw new Error("could not determine page offset of `target`");
					switch (t) {
					case "top":
						o = {
							top: h.top - a - e,
							left: h.left + l / 2 - r / 2
						};
						break;
					case "bottom":
						o = {
							top: h.top + c + e,
							left: h.left + l / 2 - r / 2
						};
						break;
					case "right":
						o = {
							top: h.top + c / 2 - a / 2,
							left: h.left + l + e
						};
						break;
					case "left":
						o = {
							top: h.top + c / 2 - a / 2,
							left: h.left - r - e
						};
						break;
					case "top left":
						o = {
							top: h.top - a - e,
							left: h.left + l / 2 - r + n
						};
						break;
					case "top right":
						o = {
							top: h.top - a - e,
							left: h.left + l / 2 - n
						};
						break;
					case "bottom left":
						o = {
							top: h.top + c + e,
							left: h.left + l / 2 - r + n
						};
						break;
					case "bottom right":
						o = {
							top: h.top + c + e,
							left: h.left + l / 2 - n
						};
						break;
					default:
						throw new Error('invalid position "' + t + '"')
					}
					return o.top += this.offset.top,
					o.left += this.offset.left,
					o
				},
				_getPosClass: function(t) {
					return s[t] || ""
				},
				_getLeft: function(t) {
					return /\s+right$/.test(t) ? {
						left: 12
					}: /\s+left$/.test(t) ? {
						left: this._$el.width() - 12
					}: void 0
				},
				bindEvent: function() {
					var t = this;
					if (this.trigger) {
						var e = this.$handler.add(this.$el);
						e.on(l[this.trigger][1],
						function(i) {
							"hover" === t.trigger && ($.contains(t.$el, i.toElement) || $.contains(t.$handler[0], i.toElement) || e.is(i.toElement)) || (clearTimeout(t._delay), t._delay = setTimeout(function() {
								t.state && t.hide()
							},
							t.hideDelay))
						}).on(l[this.trigger][0],
						function() {
							clearTimeout(t._delay)
						}),
						this.$handler.on(l[this.trigger][0],
						function() {
							t.show()
						})
					}
				}
			},
			{
				defaults: o,
				hide: function() {
					c.forEach(function(t) {
						return t.hide()
					})
				},
				hideExcept: function(t) {
					c.forEach(function(e) {
						return t !== e && e.hide()
					})
				}
			}),
			d = ".qc_popover";
			h.bootFromAttr = function(t) {
				var e = this;
				$(document).on("mouseenter" + d + " click" + d + " focusin" + d, "[" + t + "]",
				function(i) {
					var n, r, a, s = $(this);
					s.data("qc-popover") || (a = s.data(), r = a.trigger || e.defaults.trigger, i.type === l[r][0] && (n = new e({
						$data: $.extend({},
						a, {
							handler: this,
							content: s.attr(t),
							position: s.attr(t + "-position"),
							style: s.attr(t + "-style")
						})
					}), n.show()))
				})
			},
			$(document).on("click",
			function(t) {
				var e, i = $(t.target);
				return "qc-popover" === i.attr("data-role") || i.parents("[data-role=qc-popover]").length ? void 0 : (e = i.parents().data("qc-popover") || i.data("qc-popover")) ? void h.hideExcept(e) : void h.hide()
			}),
			h.bootFromAttr("qc-popover"),
			e.exports = h
		},
		{
			"../../lib/box": 22,
			"../componentBase": 1,
			beejs: 28
		}],
		16 : [function(t, e) {
			"use strict";
			var i = '<div b-on="$events" data-role="qc-search" class="tc-15-search {{multiple ? \'tc-15-multi-search\' : \'\'}}" b-style="style">\n	<textarea data-input class="tc-15-search-words" placeholder="{{placeholder}}" b-if="multiple" b-model="keyword"></textarea>\n  <input data-input class="tc-15-search-words" placeholder="{{placeholder}}" b-if="!multiple" b-model="keyword" type="text" />\n	<button data-search class="tc-15-btn weak m search"></button>\n</div>\n',
			n = (t("beejs"), t("../componentBase")),
			r = {
				keyword: "",
				searchEmpty: !1,
				multiple: !1,
				placeholder: "请输入关键字"
			},
			a = n.extend({
				$tpl: i,
				$events: {
					"click [data-search]": function() {
						this._search()
					},
					"keydown [data-input]": function(t) {
						var e;
						13 == t.keyCode && (e = this.multiple ? t.ctrlKey: !0),
						e && this._search()
					}
				},
				_search: function() {
					var t = this.keyword.trim(); ("" !== t || this.searchEmpty) && (this.search(t), this.onSearch(t), this.$el.querySelector("[data-input]").blur(), $(this.$el).trigger("search", [t]), this.$emit("search", t))
				},
				getKeyword: function() {
					return this.$get("keyword")
				},
				search: function(t) {
					console.log(t)
				},
				onSearch: function() {}
			},
			{
				defaults: r
			});
			e.exports = a
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		17 : [function(t, e) {
			"use strict";
			var i = '<div b-on="$events" class="tc-15-dropdown tc-15-dropdown-in-hd tc-15-menu-{{popup ? \'active\' : \'\'}}">\n    <a data-handler href="javascript:;" class="tc-15-dropdown-link">{{simulateSelect ? (selected ? selected.label : label) : label}}<i class="caret"></i></a>\n    <ul data-list class="tc-15-dropdown-menu" role="menu">\n    	<span b-content="listTpl"></span>\n    </ul>\n</div>\n',
			n = (t("beejs"), t("../qc-dropdown-list")),
			r = n.extend({
				$tpl: i,
				$valuekey: "selected",
				listTpl: '<li data-item role="presentation" b-repeat="item in list" class="{{selected == item ? \'selected\' : \'\'}}">\n              <a role="menuitem" href="javascript:;">{{item.label}}</a>\n            </li>'
			});
			r.defaults = $.extend({},
			n.defaults, {
				simulateSelect: !0
			}),
			e.exports = r
		},
		{
			"../qc-dropdown-list": 13,
			beejs: 28
		}],
		18 : [function(t, e) {
			"use strict";
			var i = '<div data-role="qc-tabs">\n  <div class="tc-15-tab">\n      <ul class="tc-15-tablist" role="tablist">\n          <li class="{{$index == activeIndex ? \'tc-cur\': \'\'}}" b-repeat="tab in list">\n            <a b-on-click="$set(\'activeIndex\', $index)" role="tab" title="{{tab.label}}" href="javascript:;">{{tab.label}}</a>\n          </li>\n      </ul>\n  </div>\n  <div data-tab-pane b-repeat="tab in list" b-style="{display: $index == activeIndex ? \'block\': \'none\'}">\n    {{> tab.content }}\n  </div>\n</div>\n',
			n = (t("beejs"), t("../componentBase")),
			r = n.extend({
				$tpl: i,
				$afterInit: function() {
					r.__super__.$afterInit.call(this),
					this.$watch("activeIndex",
					function(t) {
						this.$emit("tabchange", t),
						this.onChange(t)
					})
				},
				onChange: function() {}
			},
			{
				defaults: {
					activeIndex: 0
				}
			});
			e.exports = r
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		19 : [function(t, e) {
			"use strict";
			var i, n = t("../componentBase"),
			r = '<div class="tc-15-bubble" data-role="qc-title" data-state="{{state}}" b-style=\'{left:x, top: y, display: state ? "" : "none", overflow: "hidden", maxWidth: maxWidth, maxHeight: maxHeight, width: width, height: height, zIndex: zIndex}\'>\n    <div class="tc-15-bubble-inner">{{> content || $content }}</div>\n</div>\n',
			a = t("../../lib/box"),
			s = n.extend({
				$tpl: r,
				$afterInit: function() {
					s.__super__.$afterInit.call(this),
					i && i.$destroy(!0),
					i = this
				},
				$afterDestroy: function() {
					s.__super__.$afterDestroy.call(this),
					i = null
				},
				setPosition: function(t, e) {
					var i = this.reposition({
						x: t + this.offsetX,
						y: e + this.offsetY
					});
					this.$set(i)
				},
				reposition: function(t) {
					var e = {},
					i = $(this.$el),
					n = $(a.getBox(this.$el)),
					r = n.offset() || {
						left: 0,
						top: 0
					},
					s = i.width(),
					o = i.height(),
					l = n.width(),
					c = n.height();
					return e.x = Math.min(t.x, l - s + r.left),
					e.y = Math.min(t.y, c - o + r.top),
					e
				}
			},
			{
				defaults: {
					state: !0,
					offsetX: 8,
					offsetY: 1,
					zIndex: 9999,
					maxWidth: 360,
					maxHeight: "",
					width: "",
					height: ""
				}
			});
			s.config = function(t) {
				$(document).off(".qc_title").on("mouseenter.qc_title click.qc_title", "[" + t + "]",
				function(e) {
					var i = $(this),
					n = i.attr(t),
					r = i.data();
					if (n) {
						var a = i.data("qcTitle");
						a && a.$destroy(!0);
						var o = new s({
							$data: $.extend({},
							r, {
								target: this,
								content: n
							})
						}),
						l = i.add(o.$el);
						l.on("mouseleave.qc_title",
						function(t) {
							$.contains(o.$el, t.toElement) || (l.off(".qc_title").removeData("qcTitle"), o.$destroy(!0))
						}),
						i.add(o.$el).data("qcTitle", o),
						document.body.appendChild(o.$el),
						o.setPosition(e.clientX, e.clientY)
					}
				}).on("mousemove.qc_title",
				function(t) {
					if (i) {
						var e = $(i.target),
						n = e.offset(),
						r = {
							width: e.outerWidth(),
							height: e.outerHeight()
						};
						t.clientX < n.left || t.clientX > n.left + r.width || t.clientY < n.top || t.clientY > n.top + r.height ? (e.add(i.$el).off(".qc_title").removeData("qcTitle"), i.$destroy(!0)) : i.setPosition(t.clientX, t.clientY)
					}
				})
			},
			s.config("data-title"),
			e.exports = s
		},
		{
			"../../lib/box": 22,
			"../componentBase": 1
		}],
		20 : [function(t, e) {
			"use strict";
			var i = '<div class="tc-15-slider-wrap" b-on="$events" b-style="style">\n  <div class="tc-15-slider-range" b-ref="sliderBar">\n    <div class="tc-15-slider-for-vis"\n        b-style="{width: Math.max(0, Math.min(100, ((value - min) / (max - min)) * 100)) + \'%\'}"></div>\n    <div class="tc-15-slider" data-handler style="margin-left: -6px" role="slider" tabindex="0"\n        b-style="{left: Math.max(0, Math.min(100, ((value - min) / (max - min)) * 100)) + \'%\' }">\n      <div class="tc-15-slider-inner"></div>\n    </div>\n    <div class="tc-15-slider-valuemin">{{min}}{{unit}}</div>\n    <div class="tc-15-slider-valuemax">{{max}}{{unit}}</div>\n  </div>\n  <div class="tc-15-input-text-wrap m" b-if="showInput">\n    <input type="text" data-input b-model="value" class="tc-15-input-text shortest"> {{unit}}\n  </div>\n  <div b-if="tips" class="tc-15-slider-tips">{{tips}}</div>\n</div>\n',
			n = t("../componentBase"),
			r = (t("beejs"), 0),
			a = n.extend({
				$tpl: i,
				$valuekey: "value",
				$afterInit: function() {
					a.__super__.$afterInit.call(this);
					var t = this,
					e = $("body");
					this.guid = r++,
					e.on("mouseup.slider_" + t.guid,
					function() {
						t._sliding && (t._sliding = !1, e.off("mousemove.slider_" + t.guid))
					}),
					$(t.$el).on("mousedown.slider_" + this.guid, "[data-handler]",
					function(i) {
						t._sliding = !0;
						var n = $(t.$refs.sliderBar).width(),
						r = i.clientX,
						a = 1 * t.value;
						e.on("mousemove.slider_" + t.guid,
						function(e) {
							if (t._sliding) {
								var i = (t.max - t.min) * (e.clientX - r) / n;
								i = Math.round(i / t.step) * t.step,
								t.setValue(a + i),
								e.preventDefault()
							}
						}),
						i.preventDefault()
					}),
					$(t.$refs.sliderBar).on("click.slider_" + t.guid,
					function(e) {
						var i = $(this).offset().left,
						n = $(t.$refs.sliderBar).width(),
						r = (t.max - t.min) * (e.clientX - i) / n + 1 * t.min;
						r = Math.round(r / t.step) * t.step,
						t.setValue(r)
					}),
					t.$watch("value",
					function() {
						this._checkValue()
					}),
					t.$watch("min",
					function() {
						this._checkValue()
					}),
					t.$watch("max",
					function() {
						this._checkValue()
					})
				},
				_checkValue: function() {
					var t = this,
					e = t._lastValue,
					i = t.value,
					n = 1 * t.min,
					r = 1 * t.max;
					r >= n && (i > r ? i = r: n > i && (i = n)),
					isNaN(i) && (i = e),
					t._lastValue = i,
					t.$set("value", i)
				},
				$beforeDestroy: function() {
					$("body").off(".slider_" + this.guid)
				},
				getValue: function() {
					return this.$get("value")
				},
				setValue: function(t) {
					var e = (this.min || 0 === this.min) && this.max ? Math.max(this.min, Math.min(this.max, t)) : t;
					return isNaN(e) ? !1 : (this.$set("value", e), !0)
				},
				stepUp: function() {
					this.setValue(1 * this.value + 1 * this.step)
				},
				stepDown: function() {
					this.setValue(1 * this.value - 1 * this.step)
				},
				$events: {
					"click [data-input]": function(t) {
						t.target.select()
					},
					keydown: function(t) {
						37 == t.keyCode || 40 == t.keyCode ? (this.stepDown(), t.preventDefault()) : (38 == t.keyCode || 39 == t.keyCode) && (this.stepUp(), t.preventDefault())
					}
				}
			},
			{
				defaults: {
					step: 1,
					min: 0,
					max: 100,
					value: 50,
					showInput: !0
				}
			});
			e.exports = a
		},
		{
			"../componentBase": 1,
			beejs: 28
		}],
		21 : [function(t, e) {
			var i = t("beejs");
			t("beejs/src/es5-bee-shim"),
			t("./components/qc-title"),
			i.tag("input-slider", t("./components/input-slider")),
			i.tag("qc-combo", t("./components/combo")),
			i.tag("pagination", t("./components/pagination")),
			i.tag("grid-view", t("./components/grid-view")),
			i.tag("grid-view-header-filter", t("./components/grid-view-header-filter")),
			i.tag("qc-date-picker", t("./components/qc-date-picker")),
			i.tag("qc-dropdown-list", t("./components/qc-dropdown-list")),
			i.tag("qc-select", t("./components/qc-select")),
			i.tag("qc-search", t("./components/qc-search")),
			i.tag("qc-action-button", t("./components/qc-action-button")),
			i.tag("qc-action-panel", t("./components/qc-action-panel")),
			i.tag("slider-range", t("./components/slider-range")),
			i.tag("qc-popover", t("./components/qc-popover")),
			i.tag("qc-tabs", t("./components/qc-tabs")),
			i.tag("popup-confirm", t("./components/popup-confirm")),
			i.tag("grid-editor", t("./components/grid-editor")),
			i.tag("qc-month-picker", t("./components/qc-month-picker")),
			e.exports = i
		},
		{
			"./components/combo": 2,
			"./components/grid-editor": 3,
			"./components/grid-view": 5,
			"./components/grid-view-header-filter": 4,
			"./components/input-slider": 7,
			"./components/pagination": 8,
			"./components/popup-confirm": 9,
			"./components/qc-action-button": 10,
			"./components/qc-action-panel": 11,
			"./components/qc-date-picker": 12,
			"./components/qc-dropdown-list": 13,
			"./components/qc-month-picker": 14,
			"./components/qc-popover": 15,
			"./components/qc-search": 16,
			"./components/qc-select": 17,
			"./components/qc-tabs": 18,
			"./components/qc-title": 19,
			"./components/slider-range": 20,
			beejs: 28,
			"beejs/src/es5-bee-shim": 46
		}],
		22 : [function(t, e, i) {
			"use strict";
			i.getBox = function(t) {
				for (var e = t,
				i = $(t).offsetParent(); t = t.parentNode;) if (e = t, e === document || "visible" !== $(e).css("overflow") && (i.is(e) || $.contains(i[0], e) || $.contains(e, i[0]))) return e;
				return e
			}
		},
		{}],
		23 : [function() {},
		{}],
		24 : [function(t, e) {
			function i(t) {
				return null === t || void 0 === t
			}
			function n(t) {
				return t && "object" == typeof t && "number" == typeof t.length ? "function" != typeof t.copy || "function" != typeof t.slice ? !1 : t.length > 0 && "number" != typeof t[0] ? !1 : !0 : !1
			}
			function r(t, e, r) {
				var c, h;
				if (i(t) || i(e)) return ! 1;
				if (t.prototype !== e.prototype) return ! 1;
				if (o(t)) return o(e) ? (t = a.call(t), e = a.call(e), l(t, e, r)) : !1;
				if (n(t)) {
					if (!n(e)) return ! 1;
					if (t.length !== e.length) return ! 1;
					for (c = 0; c < t.length; c++) if (t[c] !== e[c]) return ! 1;
					return ! 0
				}
				try {
					var d = s(t),
					u = s(e)
				} catch(p) {
					return ! 1
				}
				if (d.length != u.length) return ! 1;
				for (d.sort(), u.sort(), c = d.length - 1; c >= 0; c--) if (d[c] != u[c]) return ! 1;
				for (c = d.length - 1; c >= 0; c--) if (h = d[c], !l(t[h], e[h], r)) return ! 1;
				return typeof t == typeof e
			}
			var a = Array.prototype.slice,
			s = t("./lib/keys.js"),
			o = t("./lib/is_arguments.js"),
			l = e.exports = function(t, e, i) {
				return i || (i = {}),
				t === e ? !0 : t instanceof Date && e instanceof Date ? t.getTime() === e.getTime() : "object" != typeof t && "object" != typeof e ? i.strict ? t === e: t == e: r(t, e, i)
			}
		},
		{
			"./lib/is_arguments.js": 25,
			"./lib/keys.js": 26
		}],
		25 : [function(t, e, i) {
			function n(t) {
				return "[object Arguments]" == Object.prototype.toString.call(t)
			}
			function r(t) {
				return t && "object" == typeof t && "number" == typeof t.length && Object.prototype.hasOwnProperty.call(t, "callee") && !Object.prototype.propertyIsEnumerable.call(t, "callee") || !1
			}
			var a = "[object Arguments]" ==
			function() {
				return Object.prototype.toString.call(arguments)
			} ();
			i = e.exports = a ? n: r,
			i.supported = n,
			i.unsupported = r
		},
		{}],
		26 : [function(t, e, i) {
			function n(t) {
				var e = [];
				for (var i in t) e.push(i);
				return e
			}
			i = e.exports = "function" == typeof Object.keys ? Object.keys: n,
			i.shim = n
		},
		{}],
		27 : [function(t, e) {
			var i = {
				$on: function(t, e, i) {
					var n = i || this;
					n._handlers = n._handlers || {},
					n._handlers[t] = n._handlers[t] || [],
					n._handlers[t].push({
						handler: e,
						context: i,
						ctx: n
					})
				},
				$one: function(t, e, i) {
					return e && (e.one = !0),
					this.$on(t, e, i)
				},
				$off: function(t, e, i) {
					var n = i || this,
					r = n._handlers;
					if (t && r[t]) if ("function" == typeof e) for (var a = r[t].length - 1; a >= 0; a--) r[t][a].handler === e && r[t].splice(a, 1);
					else r[t] = []
				},
				$emit: function(t) {
					var e = [].slice.call(arguments, 1),
					i = this._handlers && this._handlers[t];
					if (i) for (var n, r = 0; n = i[r]; r++) n.handler.apply(this, e),
					n.handler.one && (i.splice(r, 1), r--)
				}
			};
			e.exports = i
		},
		{}],
		28 : [function(t, e) {
			"use strict";
			function i(t) {
				t && (this.prefix = t)
			}
			function n(t, e) {
				y(t) ? e = t: (e = e || {},
				t && (e.$tpl = t));
				var i = {
					$data: w(!0, {},
					this.constructor.defaults),
					$refs: {},
					$mixins: [],
					$el: this.$el || null,
					$tpl: this.$tpl || "<div>{{> $content }}</div>",
					$content: this.$content || null,
					$isReplace: !1,
					$parent: null,
					$root: this,
					$context: null,
					_watchers: {},
					_assignments: null,
					_relativePath: [],
					__links: [],
					_isRendered: !1
				},
				n = [i].concat(this.$mixins).concat(e.$mixins).concat([e]);
				n.forEach(function(t) {
					var e;
					for (var i in t) t.hasOwnProperty(i) && (i in _ && v(t[i]) ? (e = w({},
					this[i], t[i]), this[i] = w(t[i], e)) : this[i] = i in C ? o.afterFn(this[i], t[i]) : t[i])
				}.bind(this)),
				w(this, this.$data),
				a.call(this),
				this.$beforeInit(),
				this.$el.bee = this,
				this.__links = this.__links.concat(f.walk.call(this, this.$el)),
				this._isRendered = !0,
				this.$afterInit()
			}
			function r(t, e) {
				var i;
				this.$beforeUpdate(this.$data),
				1 === arguments.length ? e = t: i = [t],
				i || (i = v(e) ? Object.keys(e) : ["$data"]);
				for (var n, r = 0; n = i[r]; r++) this.$update(n, !0);
				this.$afterUpdate(this.$data)
			}
			function a() {
				var t, e = this.$el,
				i = this.$content,
				n = this.$tpl;
				i = e && e.childNodes ? e.childNodes: i,
				e && (i = e.childNodes),
				i && (this.$content = p.createContent(i)),
				o.isObject(n) ? (t = n, n = t.outerHTML) : t = p.createContent(n).childNodes[0],
				e ? this.$isReplace ? (e.parentNode && e.parentNode.replaceChild(t, e), e = t) : e.appendChild(t) : e = t,
				this.$el = e
			}
			var s = t("./env.js").document,
			o = t("./utils.js"),
			l = t("./class.js"),
			c = t("./directive.js"),
			h = t("./component.js"),
			d = t("./watcher.js"),
			u = t("./directives"),
			p = t("./dom-utils.js"),
			f = t("./check-binding.js"),
			g = t("./scope"),
			m = c.Directive,
			v = o.isObject,
			y = o.isPlainObject,
			b = o.parseKeyPath,
			x = o.deepSet,
			w = o.extend,
			k = o.create,
			_ = {
				$data: 1
			},
			C = {
				$beforeInit: o.noop,
				$afterInit: o.noop,
				$beforeUpdate: o.noop,
				$afterUpdate: o.noop,
				$beforeDestroy: o.noop,
				$afterDestroy: o.noop
			};
			w(n, {
				extend: o.afterFn(l.extend, o.noop,
				function(t, e) {
					var i = e[1] || {};
					t.directives = w(k(this.directives), i.directives),
					t.components = w(k(this.components), i.components),
					t.filters = w(k(this.filters), i.filters),
					t.defaults = w(!0, {},
					this.defaults, i.defaults)
				}),
				utils: o
			},
			m, h, {
				setPrefix: i,
				directive: c.directive,
				prefix: "",
				doc: s,
				directives: {},
				components: {},
				defaults: {},
				filters: {
					json: function(t, e, i) {
						return JSON.stringify(t, e, i)
					}
				},
				filter: function(t, e) {
					this.filters[t] = e
				},
				mount: function(t, e) {
					var i, n, r, a = t.nodeType ? t: s.getElementById(t),
					o = c.getDirs(a, this);
					return r = o.filter(function(t) {
						return "tag" === t.type || "component" === t.type
					})[0],
					r && (n = this.getComponent(r.path)),
					e = e || {},
					n ? (e.$data = w(p.getAttrs(a), e.$data), i = new n(w({
						$el: a,
						$isReplace: !0,
						__mountcall: !0
					},
					e))) : i = new this(a, e),
					i
				}
			}),
			n.setPrefix("b-");
			for (var T in u) n.directive(T, u[T]);
			w(n.prototype, C, {
				$get: function(t) {
					var e = new m("$get", {
						path: t,
						watch: !1
					});
					return e.parse(),
					e.getValue(this, !1)
				},
				$set: function(t, e) {
					var i = this;
					1 === arguments.length ? (v(t) ? (w(this.$data, t), w(this, t)) : this.$data = t, r.call(i, t)) : this.$replace(t, e)
				},
				$replace: function(t, e) {
					var i, n, a, s, o = !1,
					l = this;
					1 === arguments.length ? (e = t, s = "$data", i = [s]) : (o = !0, a = g.reformScope(this, t), s = a.path, l = a.vm, i = b(s)),
					n = l.$get(s),
					"$data" === i[0] ? "$data" === s ? (v(this.$data) && Object.keys(this.$data).forEach(function(t) {
						delete this[t]
					}.bind(this)), w(l, e)) : x(i.shift().join("."), e, l) : x(s, e, l.$data),
					x(s, e, l),
					o ? r.call(l, s, w({},
					n, e)) : r.call(l, w({},
					n, e))
				},
				$update: function(t, e) {
					e = e !== !1;
					for (var i, n, r = b(t.replace(/^\$data\./, "")); i = r.join(".");) {
						n = this._watchers[i] || [];
						for (var a = 0,
						s = n.length; s > a; a++) n[a] && n[a].update();
						if (!e) break;
						r.pop(),
						r.length || "$data" === i || r.push("$data")
					}
					d.getWatchers(this, t).forEach(function(t) {
						t.update()
					}.bind(this)),
					e && this.$parent && this._relativePath.forEach(function(t) {
						this.$parent.$update(t)
					}.bind(this))
				},
				$watch: function(t, e, i) {
					if (e) {
						var n = e.bind(this);
						return n._originFn = e,
						d.addWatcher.call(this, new m("$watch", {
							path: t,
							update: n,
							immediate: !!i
						}))
					}
				},
				$unwatch: function(t, e) {
					d.unwatch(this, t, e)
				},
				$destroy: function(t) {
					this.$beforeDestroy(),
					this.__links.forEach(function(t) {
						t.unwatch()
					}),
					t !== !1 && this.$el.parentNode && this.$el.parentNode.removeChild(this.$el),
					this.__links = [],
					this.$afterDestroy()
				}
			}),
			n.version = "0.5.3",
			e.exports = n
		},
		{
			"./check-binding.js": 29,
			"./class.js": 30,
			"./component.js": 31,
			"./directive.js": 32,
			"./directives": 38,
			"./dom-utils.js": 44,
			"./env.js": 45,
			"./scope": 50,
			"./utils.js": 52,
			"./watcher.js": 53
		}],
		29 : [function(t, e) {
			"use strict";
			function i(t) {
				var e, a = [];
				if (t.nodeType === u.FRAGMENT && (t = t.childNodes), "length" in t && c.isUndefined(t.nodeType)) {
					for (var s = 0; s < t.length; s++) a = a.concat(i.call(this, t[s]));
					return a
				}
				switch (t.nodeType) {
				case u.ELEMENT:
					break;
				case u.COMMENT:
					return a;
				case u.TEXT:
					return a = a.concat(r.call(this, t))
				}
				if ("template" === t.nodeName.toLowerCase() && !t.content) for (t.content = h.createDocumentFragment(); t.childNodes[0];) t.content.appendChild(t.childNodes[0]);
				if (e = n.call(this, t), a = a.concat(e.watchers), e.terminal) return a;
				"template" === t.nodeName.toLowerCase() && (a = a.concat(i.call(this, t.content)));
				for (var o, l = t.firstChild; l;) o = l.nextSibling,
				a = a.concat(i.call(this, l)),
				l = o;
				return a
			}
			function n(t) {
				for (var e, i, n = this.constructor,
				r = d.getDirs(t, n, this.$context), s = [], o = {},
				l = 0, c = r.length; c > l && (e = r[l], e.dirs = r, !(i > e.priority)); l++) t.removeAttribute(e.nodeName),
				s = s.concat(a.call(this, e)),
				e.terminal && (o.terminal = !0, i = e.priority);
				return o.watchers = s,
				o
			}
			function r(t) {
				var e = [];
				if (l.hasToken(t.nodeValue)) {
					var i, n, s = l.parseToken(t.nodeValue),
					o = s.textMap,
					u = t.parentNode,
					f = this.constructor.directives;
					o.length > 1 ? (o.forEach(function(i) {
						var n = h.createTextNode(i);
						u.insertBefore(n, t),
						e = e.concat(r.call(this, n))
					}.bind(this)), u.removeChild(t)) : (i = s[0], p.test(i.path) ? (i.path = i.path.replace(p, ""), n = c.create(f.content), n.dirName = n.type, n.anchors = d.setAnchors(t, n.type)) : n = c.create(i.escape ? f.text: f.html), e = a.call(this, c.extend(n, i, {
						el: t
					})))
				}
				return e
			}
			function a(t) {
				var e;
				if (t.replace) {
					var i = t.el;
					t.node = c.isFunction(t.replace) ? t.replace() : h.createTextNode(""),
					t.el = t.el.parentNode,
					t.el.replaceChild(t.node, i)
				}
				return t.vm = this,
				t.link(),
				e = o.addWatcher.call(this, t),
				e ? [e] : []
			}
			function s(t) {
				t.forEach(function(t) {
					t.unwatch()
				})
			}
			var o = t("./watcher"),
			l = t("./token.js"),
			c = t("./utils"),
			h = t("./env.js").document,
			d = t("./directive"),
			u = {
				ELEMENT: 1,
				ATTR: 2,
				TEXT: 3,
				COMMENT: 8,
				FRAGMENT: 11
			};
			h.createElement("template");
			var p = /^>\s*/;
			e.exports = {
				walk: i,
				unBinding: s
			}
		},
		{
			"./directive": 32,
			"./env.js": 45,
			"./token.js": 51,
			"./utils": 52,
			"./watcher": 53
		}],
		30 : [function(t, e) {
			var i = t("./utils.js").extend,
			n = {
				extend: function(t, e) {
					t = t || {};
					var n = t.hasOwnProperty("constructor") ? t.constructor: function() {
						return r.apply(this, arguments)
					},
					r = this,
					a = function() {
						this.constructor = n
					},
					s = {
						__super__: r.prototype
					};
					return a.prototype = r.prototype,
					n.prototype = new a,
					i(n.prototype, s, t),
					i(n, r, s, e),
					n
				}
			};
			e.exports = n
		},
		{
			"./utils.js": 52
		}],
		31 : [function(t, e, i) {
			"use strict";
			function n(t, e, i) {
				var n = this.components = this.components || {};
				return this.doc.createElement(t),
				a.isObject(e) && (e = this.extend(e, i)),
				n[t] = e
			}
			function r(t, e) {
				var i = a.parseKeyPath(t),
				n = this;
				return i.forEach(function(t) {
					n = n && n.components[t]
				}),
				e && e.constructor && !n && (n = e.constructor.getComponent(t, e.$context)),
				n || null
			}
			var a = t("./utils.js");
			i.tag = i.component = n,
			i.getComponent = r
		},
		{
			"./utils.js": 52
		}],
		32 : [function(t, e) {
			"use strict";
			function i(t, e) {
				var i = this.directives = this.directives || {};
				return i[t] = new n(t, e)
			}
			function n(t, e) {
				this.type = t,
				o.extend(this, e)
			}
			function r(t, e, i) {
				var n, r, c, h, d, p = [],
				g = (t.parentNode, t.nodeName.toLowerCase()),
				m = e.directives,
				v = e.prefix;
				e.getComponent(g, i) && t.setAttribute(v + "component", g);
				for (var y = t.attributes.length - 1; y >= 0; y--) n = t.attributes[y],
				r = n.nodeName,
				c = r.slice(v.length),
				h = {
					el: t,
					node: n,
					nodeName: r,
					path: n.value
				},
				d = null,
				0 === r.indexOf(v) && (d = a(c, m)) ? d.dirName = c: l.hasToken(n.value) ? l.parseToken(n.value).forEach(function(t) {
					t.dirName = r,
					p.push(o.extend(u(m.attr), h, t))
				}) : f.test(r) && (d = o.extend(u(m.attr), {
					dirName: r.replace(f, ""),
					conditional: !0
				})),
				d && (d.anchor && (d.anchors = s(t, d.dirName)), p.push(o.extend(d, h)));
				return p.sort(function(t, e) {
					return e.priority - t.priority
				}),
				p
			}
			function a(t, e) {
				var i, n;
				for (var r in e) {
					if (t === r) {
						i = e[r];
						break
					}
					if (0 === t.indexOf(r + "-")) {
						i = e[r],
						i.sub ? n = t.slice(r.length + 1) : i = null;
						break
					}
				}
				return i && (i = u(i), i.subType = n),
				i
			}
			function s(t, e) {
				var i = t.parentNode,
				n = {};
				return n.start = c.createComment(e + " start"),
				i.insertBefore(n.start, t),
				n.end = c.createComment(e + " end"),
				t.nextSibling ? i.insertBefore(n.end, t.nextSibling) : i.appendChild(n.end),
				n
			}
			var o = t("./utils.js"),
			l = t("./token.js"),
			c = t("./env.js").document,
			h = t("./parse.js").parse,
			d = t("./eval.js"),
			u = (t("./dom-utils"), o.create),
			p = {};
			n.prototype = {
				priority: 0,
				type: "",
				subType: "",
				sub: !1,
				link: o.noop,
				unLink: o.noop,
				update: o.noop,
				tearDown: o.noop,
				terminal: !1,
				replace: !1,
				watch: !0,
				immediate: !0,
				anchor: !1,
				anchors: null,
				getNodes: function(t, e) {
					t = t || this.anchors.start,
					e = e || this.anchors.end;
					var i = [],
					n = t.nextSibling;
					if (this.anchor && n) {
						for (; n !== e;) i.push(n),
						n = n.nextSibling;
						return i
					}
				},
				parse: function() {
					var t = p[this.path];
					if (t && t._type === this.type) this.ast = t;
					else {
						"attr" == this.type && this.escape === !1 && (this.path = "{" + this.path + "}");
						try {
							this.ast = h(this.path, this.type),
							this.ast._type = this.type,
							p[this.path] = this.ast
						} catch(e) {
							this.ast = {},
							e.message = 'SyntaxError in "' + this.path + '" | ' + e.message,
							console.error(e)
						}
					}
				},
				getValue: function(t, e) {
					e = e !== !1;
					var i;
					try {
						i = d.eval(this.ast, t, this)
					} catch(n) {
						i = "",
						console.error(n)
					}
					return e && (o.isUndefined(i) || null === i) && (i = ""),
					i
				}
			};
			var f = /\?$/;
			e.exports = {
				Directive: n,
				directive: i,
				getDirs: r,
				setAnchors: s
			}
		},
		{
			"./dom-utils": 44,
			"./env.js": 45,
			"./eval.js": 47,
			"./parse.js": 49,
			"./token.js": 51,
			"./utils.js": 52
		}],
		33 : [function(t, e) {
			"use strict";
			function i(t, e, i) {
				a(this) ? t.bee.$set(s.hyphenToCamel(e), i) : r(t, e, i)
			}
			function n(t, e, i) {
				a(this) ? t.bee.$set(s.hyphenToCamel(e), i) : t.removeAttribute(e)
			}
			function r(t, e, i) {
				try { (e in t || "class" === e) && ("style" === e && t.style.setAttribute ? t.style.setAttribute("cssText", i) : "class" === e ? t.className = i: t[e] = "boolean" == typeof t[e] ? !0 : i)
				} catch(n) {}
				t.setAttribute(e, i)
			}
			function a(t) {
				var e = t.el.bee;
				return e && !e.__repeat && e != t.vm
			}
			var s = t("../utils.js");
			e.exports = {
				link: function() {
					this.dirName === this.type && this.nodeName !== this.dirName ? this.attrs = {}: this.update("")
				},
				update: function(t) {
					var e = this.el,
					r = {},
					a = this.textMap;
					if (this.attrs) {
						for (var s in t) i.call(this, e, s, t[s]),
						delete this.attrs[s],
						r[s] = !0;
						for (var s in this.attrs) n.call(this, e, s);
						this.attrs = r
					} else this.conditional ? t ? i.call(this, e, this.dirName, t) : n.call(this, e, this.dirName) : (a[this.position] = t, i.call(this, e, this.dirName, a.length > 1 ? a.join("") : a[0]))
				}
			}
		},
		{
			"../utils.js": 52
		}],
		34 : [function(t, e) {
			"use strict";
			e.exports = {
				link: function() {
					this.initClass = this.el.className || "",
					this.keys = {}
				},
				update: function(t) {
					var e, i = this.initClass,
					n = this.watcher;
					if ("string" == typeof t) t && (i += " " + t);
					else for (var r in t) e = t[r],
					this.keys[e] || (this.keys[e] = !0, this.vm.$watch(e,
					function() {
						n.update()
					})),
					this.vm.$get(e) && (i += " " + r);
					this.el.className = i
				}
			}
		},
		{}],
		35 : [function(t, e) {
			function i(t) {
				var e, i = t.textMap;
				return e = i && i.length > 1 ? i.join("") : i[0],
				n.isPlainObject(e) ? n.extend(!0, {},
				e) : e
			}
			var n = t("../utils.js"),
			r = t("../dom-utils"),
			a = t("../check-binding");
			e.exports = {
				priority: -1,
				watch: !1,
				unLink: function() {
					this.component && this.component.$destroy()
				},
				link: function() {
					var t, e, s = this.vm,
					o = this.el,
					l = s.constructor,
					c = {},
					h = l.getComponent(this.path, s.$context),
					d = {};
					if (h) {
						if (h === l && s.__mountcall || o.bee && o.bee === s) return;
						e = this.dirs.filter(function(t) {
							return "attr" == t.type || "with" == t.type
						}),
						e.forEach(function(e) {
							var r, a;
							r = e.path,
							"with" === e.type ? (n.extend(!0, c, s.$get(r)), s.$watch(r,
							function() {
								t && t.$set(n.extend({},
								s.$get(r)))
							})) : (a = n.hyphenToCamel(e.dirName), c[a] = i(e), e.el.removeAttribute(e.dirName))
						}),
						s.__links = s.__links.concat(a.walk.call(s, o.childNodes)),
						d = r.getAttrs(o);
						var u;
						for (var p in d) u = n.camelToHyphen(p),
						u = u.slice(s.constructor.prefix.length),
						u in s.constructor.directives && delete d[p];
						return this.component = t = new h({
							$el: o,
							$isReplace: !0,
							$context: s,
							$data: n.extend(!0, {},
							c, d)
						}),
						o.bee = t,
						t
					}
					console.error("Component: " + this.path + " not defined!")
				}
			}
		},
		{
			"../check-binding": 29,
			"../dom-utils": 44,
			"../utils.js": 52
		}],
		36 : [function(t, e) {
			"use strict";
			var i = t("../dom-utils"),
			n = t("../check-binding");
			e.exports = {
				replace: !0,
				anchor: !0,
				link: function() {
					this.watchers = []
				},
				unLink: function() {
					this.watchers.forEach(function(t) {
						t.unwatch()
					})
				},
				update: function(t) {
					var e = this.getNodes(),
					r = this.anchors.end.parentNode;
					e.forEach(function(t) {
						r.removeChild(t)
					}),
					this.unLink();
					var a = i.createContent(t);
					this.watchers = n.walk.call(this.vm, a),
					r.insertBefore(a, this.anchors.end)
				}
			}
		},
		{
			"../check-binding": 29,
			"../dom-utils": 44
		}],
		37 : [function(t, e) {
			"use strict";
			var i = t("../check-binding"),
			n = (t("../dom-utils"), t("../env").document);
			e.exports = {
				anchor: !0,
				priority: 900,
				terminal: !0,
				link: function() {
					this.watchers = [],
					this.el.content ? (this.frag = this.el.content, this.el.parentNode.removeChild(this.el)) : this.frag = n.createDocumentFragment(),
					this.remove()
				},
				update: function(t) {
					t ? this.state || this.add() : this.state && this.remove(),
					this.state = t
				},
				add: function() {
					var t = this.anchors.end;
					this.walked || (this.walked = !0, this.watchers = i.walk.call(this.vm, this.frag)),
					this.watchers.forEach(function(t) {
						t._hide = !1,
						t._needUpdate && (t.update(), t._needUpdate = !1)
					}),
					t.parentNode && t.parentNode.insertBefore(this.frag, t)
				},
				remove: function() {
					for (var t = this.getNodes(), e = 0, i = t.length; i > e; e++) this.frag.appendChild(t[e]);
					this.watchers.forEach(function(t) {
						t._hide = !0
					})
				}
			}
		},
		{
			"../check-binding": 29,
			"../dom-utils": 44,
			"../env": 45
		}],
		38 : [function(t, e) {
			"use strict";
			var i = t("../env.js").document,
			n = t("../utils.js"),
			r = (t("../check-binding"), {});
			r.text = {
				terminal: !0,
				replace: !0,
				update: function(t) {
					this.node.nodeValue = n.isUndefined(t) ? "": t
				}
			},
			r.html = {
				terminal: !0,
				replace: !0,
				link: function() {
					this.nodes = []
				},
				update: function(t) {
					var e = i.createElement("div");
					e.innerHTML = n.isUndefined(t) ? "": t;
					for (var r; r = this.nodes.pop();) r.parentNode && r.parentNode.removeChild(r);
					for (var a = e.childNodes; r = a[0];) this.nodes.push(r),
					this.el.insertBefore(r, this.node)
				}
			},
			r.template = {
				priority: 1e4,
				watch: !1,
				link: function() {
					for (var t = this.el.childNodes,
					e = i.createDocumentFragment(); t[0];) e.appendChild(t[0]);
					this.el.content = e
				}
			},
			r.src = {
				update: function(t) {
					this.el.src = t
				}
			},
			r["with"] = {},
			r["if"] = t("./if"),
			r.repeat = t("./repeat"),
			r.attr = t("./attr"),
			r.model = t("./model"),
			r.style = t("./style"),
			r.on = t("./on"),
			r.component = r.tag = t("./component"),
			r.content = t("./content"),
			r.ref = t("./ref"),
			r["class"] = t("./class.js"),
			e.exports = r
		},
		{
			"../check-binding": 29,
			"../env.js": 45,
			"../utils.js": 52,
			"./attr": 33,
			"./class.js": 34,
			"./component": 35,
			"./content": 36,
			"./if": 37,
			"./model": 39,
			"./on": 40,
			"./ref": 41,
			"./repeat": 42,
			"./style": 43
		}],
		39 : [function(t, e) {
			"use strict";
			var i = t("../utils.js"),
			n = t("../token.js").hasToken,
			r = t("../event-bind.js"),
			a = t("../check-binding");
			e.exports = {
				teminal: !0,
				priority: -2,
				link: function() {
					var t = this.path,
					e = this.vm;
					if (!t) return ! 1;
					var s, o = this.el,
					l = "change",
					c = s = "value",
					h = i.isUndefined(e.$get(t)),
					d = /\r\n/g,
					u = function(t) {
						0 === t && "checkbox" !== o.type && (t = "0");
						var e = (t || "") + "",
						t = o[s];
						t && t.replace && (t = t.replace(d, "\n")),
						e !== t && (o[s] = e)
					},
					p = function() {
						var i = o[c];
						i.replace && (i = i.replace(d, "\n")),
						e.$set(t, i)
					},
					f = function(t) {
						t && t.propertyName && t.propertyName !== s || p.apply(this, arguments)
					},
					g = i.ie;
					if (o.bee) o = o.bee,
					c = o.$valuekey,
					c && (u = function(t) {
						o.$replace(c, t)
					},
					p = function() {
						e.$replace(t, o.$get(c))
					},
					o.$watch(c,
					function(t, e) {
						t !== e && p()
					}), o.$set(c, e.$get(t)));
					else {
						switch (e.__links = e.__links.concat(a.walk.call(e, o.childNodes)), o.tagName) {
						default:
							c = s = "innerHTML";
						case "INPUT":
						case "TEXTAREA":
							switch (o.type) {
							case "checkbox":
								c = s = "checked",
								g && (l += " click");
								break;
							case "radio":
								s = "checked",
								g && (l += " click"),
								u = function(t) {
									o.checked = o.value === t + ""
								},
								h = o.checked;
								break;
							default:
								e.$lazy || ("oninput" in o && (l += " input"), g && (l += " keyup propertychange cut"))
							}
							break;
						case "SELECT":
							o.multiple && (p = function() {
								for (var i = [], n = 0, r = o.options.length; r > n; n++) o.options[n].selected && i.push(o.options[n].value);
								e.$replace(t, i)
							},
							u = function(t) {
								if (t && t.length) for (var e = 0,
								i = o.options.length; i > e; e++) o.options[e].selected = -1 !== t.indexOf(o.options[e].value)
							}),
							h = h && !n(o[c])
						}
						l.split(/\s+/g).forEach(function(t) {
							r.removeEvent(o, t, f),
							r.addEvent(o, t, f)
						}),
						o[c] && h && p()
					}
					this.update = u
				}
			}
		},
		{
			"../check-binding": 29,
			"../event-bind.js": 48,
			"../token.js": 51,
			"../utils.js": 52
		}],
		40 : [function(t, e) {
			"use strict";
			function i(t, e, i) {
				return function(n) {
					var a = n.target || n.srcElement,
					s = e ? r.toArray(t.el.querySelectorAll(e)) : [a];
					do
					if (s.indexOf(a) >= 0) return n.delegateTarget = a,
					i.call(t.vm, n);
					while (a = a.parentNode)
				}
			}
			var n = t("../event-bind.js"),
			r = t("../utils");
			e.exports = {
				watch: !1,
				sub: !0,
				priority: -3,
				immediate: !1,
				link: function() {
					var t = this;
					this.subType ? n.addEvent(this.el, this.subType,
					function() {
						t.vm.$get(t.path)
					}) : this.immediate = !0
				},
				update: function(t) {
					var e, r;
					for (var a in t) e = a.split(/\s+/),
					r = e.shift(),
					e = e.join(" "),
					n.addEvent(this.el, r, i(this, e, t[a]))
				}
			}
		},
		{
			"../event-bind.js": 48,
			"../utils": 52
		}],
		41 : [function(t, e) {
			var i = t("../utils");
			e.exports = {
				watch: !1,
				priority: -2,
				unLink: function() {
					i.isArray(this.ref) || (this.vm.$refs[this.path] = null)
				},
				link: function() {
					var t = this.vm;
					t.__repeat ? t.$index || (t.$parent.$refs[this.path] = t.__vmList) : t.$refs[this.path] = this.el.bee || this.el
				}
			}
		},
		{
			"../utils": 52
		}],
		42 : [function(t, e) {
			"use strict";
			function i(t, e) {
				var i = t.vmList[e];
				return i ? t.isRange ? i.__anchor: i.$el: t.anchors.end
			}
			function n(t, e) {
				var i = t.vmList,
				n = i[e].__anchor,
				r = i[e + 1];
				return [n].concat(t.getNodes(n, r && r.__anchor))
			}
			function r(t, e) {
				var i = o.createDocumentFragment();
				return t.isRange ? n(t, e).forEach(function(t) {
					i.appendChild(t)
				}) : i.appendChild(t.vmList[e].$el),
				i
			}
			function a(t, e, i) {
				var n = e.slice();
				return t.filter(function(t) {
					var e, r = s(t, n, i);
					return 0 > r ? e = !0 : n.splice(r, 1),
					e
				})
			}
			function s(t, e, i, n) {
				n = n || 0;
				var r = e.indexOf(t, n);
				if ( - 1 === r && i) for (var a, s = n; a = e[s]; s++) if (t[i] === a[i] && !l.isUndefined(t[i])) {
					r = s;
					break
				}
				return r
			}
			var o = t("../env.js").document,
			l = t("../utils.js"),
			c = t("../scope"),
			h = ["splice", "push", "pop", "shift", "unshift", "sort", "reverse"];
			e.exports = {
				priority: 1e3,
				anchor: !0,
				terminal: !0,
				unLink: function() {
					this.vmList.forEach(function(t) {
						t.$destroy()
					})
				},
				link: function() {
					var e = t("../bee");
					this.trackId = this.el.getAttribute("track-by"),
					this.el.removeAttribute("track-by"),
					this.cstr = e.extend({},
					this.vm.constructor),
					this.cstr.defaults = {},
					this.curArr = [],
					this.vmList = [],
					this.el.content ? (this.frag = this.el.content, this.isRange = !0) : this.frag = this.el,
					this.el.parentNode.removeChild(this.el)
				},
				update: function(t) {
					var e = this.curArr,
					d = this.anchors.end.parentNode,
					u = this,
					p = this.vmList,
					f = this.trackId,
					g = [];
					l.isArray(t) && (this.listPath = this.summary.paths.filter(function(t) {
						return ! l.isFunction(u.vm.$get(t))
					}), a(e, t, f).forEach(function(t) {
						var i = s(t, e, f);
						e.splice(i, 1),
						u.isRange ? n(u, i).forEach(function(t) {
							d.removeChild(t)
						}) : d.removeChild(p[i].$el),
						p[i].$destroy(),
						p.splice(i, 1)
					}), t.forEach(function(n, a) {
						var l, c, h, g = s(n, t, f, a),
						m = s(n, e, f, a);
						0 > m ? (c = this.frag.cloneNode(!0), this.isRange && (h = o.createComment(""), c.childNodes.length ? c.insertBefore(h, c.childNodes[0]) : c.appendChild(h)), l = new this.cstr(c, {
							$data: n,
							$index: g,
							$root: this.vm.$root,
							$parent: this.vm,
							$context: this.vm.$context,
							_assignments: this.summary.assignments,
							__repeat: !0,
							__anchor: h,
							__vmList: this.vmList
						}), d.insertBefore(l.$el, i(u, g)), p.splice(g, 0, l), e.splice(g, 0, n), l._relativePath = this.listPath) : g !== m && (d.insertBefore(r(u, m), i(u, g)), d.insertBefore(r(u, g), i(u, m + 1)), p[m] = [p[g], p[g] = p[m]][0], e[m] = [e[g], e[g] = e[m]][0], p[g].$index = g, p[g].$update("$index"))
					}.bind(this)), p.forEach(function(t, e) {
						t.$index = e,
						t.$el.$index = e,
						t.$update("$index", !1)
					}), this.listPath.forEach(function(t) {
						var e = u.vm.$get(t);
						l.isArray(e) && g.push(e)
					}), g.push(t), g.forEach(function(t) {
						var e = t.__dirs__;
						e || (l.extend(t, {
							$set: function(e, i) {
								t.splice(e, 1, l.isObject(i) ? l.extend({},
								t[e], i) : i)
							},
							$replace: function(e, i) {
								t.splice(e, 1, i)
							},
							$remove: function(e) {
								t.splice(e, 1)
							}
						}), h.forEach(function(i) {
							t[i] = l.afterFn(t[i],
							function() {
								e.forEach(function(t) {
									t.listPath.forEach(function(e) {
										var i = c.reformScope(t.vm, e);
										i.vm.$update(i.path)
									})
								})
							})
						}), e = t.__dirs__ = []),
						-1 === e.indexOf(u) && e.push(u)
					}))
				}
			}
		},
		{
			"../bee": 28,
			"../env.js": 45,
			"../scope": 50,
			"../utils.js": 52
		}],
		43 : [function(t, e) {
			"use strict";
			var i = t("../utils"),
			n = ["width", "height", "min-width", "min-height", "max-width", "max-height", "margin", "margin-top", "margin-right", "margin-left", "margin-bottom", "padding", "padding-top", "padding-right", "padding-bottom", "padding-left", "top", "left", "right", "bottom"];
			e.exports = {
				link: function() {
					this.initStyle = this.el.style.getAttribute ? this.el.style.getAttribute("cssText") : this.el.getAttribute("style")
				},
				update: function(t) {
					var e, r, a = this.el,
					s = this.initStyle ? this.initStyle.replace(/;?$/, ";") : "";
					if ("string" == typeof t) s += t;
					else for (var o in t) r = t[o],
					e = i.camelToHyphen(o),
					n.indexOf(e) >= 0 && i.isNumeric(r) && (r += "px"),
					i.isUndefined(r) || (s += e + ": " + r + "; ");
					a.style.setAttribute ? a.style.setAttribute("cssText", s) : a.setAttribute("style", s)
				}
			}
		},
		{
			"../utils": 52
		}],
		44 : [function(t, e) {
			"use strict";
			var i = t("./env.js").document,
			n = t("./utils");
			e.exports = {
				createContent: function(t) {
					var e, r = i.createDocumentFragment(),
					a = [];
					n.isObject(t) ? t.nodeName && t.nodeType ? r.appendChild(t) : "length" in t && (a = t) : (e = i.createElement("div"), e.innerHTML = (t + "").trim(), a = e.childNodes);
					for (; a[0];) r.appendChild(a[0]);
					return r
				},
				getAttrs: function(t) {
					for (var e = t.attributes,
					i = {},
					r = e.length - 1; r >= 0; r--) i[n.hyphenToCamel(e[r].nodeName)] = e[r].value;
					return i
				},
				hasAttr: function(t, e) {
					return t.hasAttribute ? t.hasAttribute(e) : !n.isUndefined(t[e])
				}
			}
		},
		{
			"./env.js": 45,
			"./utils": 52
		}],
		45 : [function(t, e, i) { !
			function(e) {
				"use strict";
				i.root = e,
				i.document = e.document || t("jsdom").jsdom()
			} (function() {
				return this
			} ())
		},
		{
			jsdom: 23
		}],
		46 : [function() {
			Array.prototype.forEach || (Array.prototype.forEach = function(t, e) {
				for (var i = 0,
				n = this.length; n > i; ++i) i in this && t.call(e, this[i], i, this)
			}),
			Array.isArray || (Array.isArray = function(t) {
				return "[object Array]" === {}.toString.call(t)
			}),
			String.prototype.trim || (String.prototype.trim = function() {
				return this.replace(/^\s+|\s+$/g, "")
			}),
			Array.prototype.indexOf || (Array.prototype.indexOf = function(t, e) {
				for (var i = e || 0; i < this.length; i++) if (this[i] === t) return i;
				return - 1
			}),
			"lastIndexOf" in Array.prototype || (Array.prototype.lastIndexOf = function(t, e) {
				for (void 0 === e && (e = this.length - 1), 0 > e && (e += this.length), e > this.length - 1 && (e = this.length - 1), e++; e-->0;) if (e in this && this[e] === t) return e;
				return - 1
			}),
			Array.prototype.filter || (Array.prototype.filter = function(t) {
				"use strict";
				if (void 0 === this || null === this) throw new TypeError;
				var e = Object(this),
				i = e.length >>> 0;
				if ("function" != typeof t) throw new TypeError;
				for (var n = [], r = arguments.length >= 2 ? arguments[1] : void 0, a = 0; i > a; a++) if (a in e) {
					var s = e[a];
					t.call(r, s, a, e) && n.push(s)
				}
				return n
			}),
			Array.prototype.map || (Array.prototype.map = function(t, e) {
				var i, n, r;
				if (null == this) throw new TypeError(" this is null or not defined");
				var a = Object(this),
				s = a.length >>> 0;
				if ("[object Function]" != {}.toString.call(t)) throw new TypeError(t + " is not a function");
				for (e && (i = e), n = new Array(s), r = 0; s > r;) {
					var o, l;
					r in a && (o = a[r], l = t.call(i, o, r, a), n[r] = l),
					r++
				}
				return n
			}),
			Function.prototype.bind || (Function.prototype.bind = function(t) {
				if ("function" != typeof this) throw new TypeError("Function.prototype.bind - what is trying to be bound is not callable");
				var e = Array.prototype.slice.call(arguments, 1),
				i = this,
				n = function() {},
				r = function() {
					return i.apply(this instanceof n && t ? this: t, e.concat(Array.prototype.slice.call(arguments)))
				};
				return n.prototype = this.prototype,
				r.prototype = new n,
				r
			}),
			Object.keys || (Object.keys = function(t) {
				if (t !== Object(t)) throw new TypeError("Object.keys called on a non-object");
				var e, i = [];
				for (e in t) Object.prototype.hasOwnProperty.call(t, e) && i.push(e);
				return i
			});
			var t = function() {};
			window.console || (window.console = {
				log: t,
				info: t,
				debug: t,
				warn: t,
				error: t
			})
		},
		{}],
		47 : [function(t, e, i) {
			"use strict";
			function n(t, e, i) {
				return t && t.then ? t.then(function(t) {
					return e.apply(d, [t].concat(i))
				}) : e.apply(d, [t].concat(i))
			}
			function r(t, e) {
				return p[t][e] ||
				function() {}
			}
			function a(t, e) {
				l = !0,
				t ? (d = t.$root, l = !1, s = {
					locals: t || {},
					filters: t.constructor.filters || {}
				}) : s = {
					filters: {},
					locals: {}
				},
				e && (h = e),
				o = {
					filters: {},
					paths: {},
					assignments: {}
				},
				c = ""
			}
			var s, o, l, c, h, d, u = t("./scope"),
			p = {
				unary: {
					"+": function(t) {
						return + t
					},
					"-": function(t) {
						return - t
					},
					"!": function(t) {
						return ! t
					},
					"[": function(t) {
						return t
					},
					"{": function(t) {
						for (var e = {},
						i = 0,
						n = t.length; n > i; i++) e[t[i][0]] = t[i][1];
						return e
					},
					"typeof": function(t) {
						return typeof t
					},
					"new": function(t) {
						return new t
					}
				},
				binary: {
					"+": function(t, e) {
						return t + e
					},
					"-": function(t, e) {
						return t - e
					},
					"*": function(t, e) {
						return t * e
					},
					"/": function(t, e) {
						return t / e
					},
					"%": function(t, e) {
						return t % e
					},
					"<": function(t, e) {
						return e > t
					},
					">": function(t, e) {
						return t > e
					},
					"<=": function(t, e) {
						return e >= t
					},
					">=": function(t, e) {
						return t >= e
					},
					"==": function(t, e) {
						return t == e
					},
					"!=": function(t, e) {
						return t != e
					},
					"===": function(t, e) {
						return t === e
					},
					"!==": function(t, e) {
						return t !== e
					},
					"&&": function(t, e) {
						return t && e
					},
					"||": function(t, e) {
						return t || e
					},
					",": function(t, e) {
						return e
					},
					".": function(t, e) {
						var i = this.first;
						return e && c && ("binary" !== i.arity || "[" !== i.value) && (c = c + "." + e),
						t[e]
					},
					"[": function(t, e) {
						return "undefined" != typeof e && c && (c = c + "." + e),
						t[e]
					},
					"(": function(t, e) {
						return t.apply(d, e)
					},
					"|": function(t, e) {
						return n(t, e, [])
					},
					"new": function(t, e) {
						return t === Date ? new Function("return new Date(" + e.join(", ") + ")")() : new(Function.prototype.bind.apply(t, [null].concat(e)))
					},
					"in": function(t, e) {
						return this.repeat ? e: t in e
					},
					catchby: function(t, e) {
						return t["catch"] ? t["catch"](e.bind(d)) : (l || console.error("catchby expect a promise"), t)
					}
				},
				ternary: {
					"?": function(t, e, i) {
						return t ? e: i
					},
					"(": function(t, e, i) {
						return t[e].apply(t, i)
					},
					"|": function(t, e, i) {
						return n(t, e, i)
					}
				}
			},
			f = ["first", "second", "third"],
			g = function(t) {
				for (var e, i, n = t.arity,
				a = t.value,
				h = [], d = 0; 3 > d; d++) if (e = t[f[d]]) if (Array.isArray(e)) {
					h[d] = [];
					for (var u = 0,
					p = e.length; p > u; u++) h[d].push("undefined" == typeof e[u].key ? g(e[u]) : [e[u].key, g(e[u])])
				} else h[d] = g(e);
				switch ("literal" !== n && (c && "." !== a && "[" !== a && (o.paths[c] = !0), "name" === n && (c = a)), n) {
				case "unary":
				case "binary":
				case "ternary":
					try {
						i = r(n, a).apply(t, h)
					} catch(v) { ! l && "(" == a && console.error(v)
					}
					break;
				case "literal":
					i = a;
					break;
				case "repeat":
					o.assignments[a] = !0;
					break;
				case "name":
					i = m(a, s.locals);
					break;
				case "filter":
					o.filters[a] = !0,
					i = s.filters[a];
					break;
				case "this":
					i = s.locals
				}
				return i
			},
			m = function(t, e) {
				var i = u.reformScope(e, t);
				return i.vm[i.path]
			};
			i.eval = function(t, e, i) {
				return a(e || {},
				i),
				g(t)
			},
			i.summary = function(t) {
				a(),
				g(t),
				c && (o.paths[c] = !0);
				for (var e in o) o[e] = Object.keys(o[e]);
				return o
			}
		},
		{
			"./scope": 50
		}],
		48 : [function(t, e, i) {
			"use strict";
			i.addEvent = function(t, e, i) {
				t.addEventListener ? t.addEventListener(e, i, !1) : t.attachEvent("on" + e, i)
			},
			i.removeEvent = function(t, e, i) {
				t.removeEventListener ? t.removeEventListener(e, i) : t.detachEvent("on" + e, i)
			}
		},
		{}],
		49 : [function(t, e, i) {
			"use strict";
			var n, r = Object.create ||
			function(t) {
				function e() {}
				return e.prototype = t,
				new e
			},
			a = function(t, e) {
				e = e || this;
				var i = t += " But found '" + e.value + "'" + (e.from ? " at " + e.from: "") + " in '" + n + "'",
				r = new Error(i);
				throw r.name = e.name = "SyntaxError",
				e.message = t,
				r
			},
			s = function(t, e, i) {
				var n, r, s, o, l, c = 0,
				h = t.length,
				d = [],
				u = function(t, e) {
					return {
						type: t,
						value: e,
						from: r,
						to: c
					}
				};
				if (t) {
					for (n = t.charAt(c); n;) if (r = c, " " >= n) c += 1,
					n = t.charAt(c);
					else if (n >= "a" && "z" >= n || n >= "A" && "Z" >= n || "$" === n || "_" === n) {
						for (l = n, c += 1; n = t.charAt(c), n >= "a" && "z" >= n || n >= "A" && "Z" >= n || n >= "0" && "9" >= n || "_" === n;) l += n,
						c += 1;
						d.push(u("name", l))
					} else if (n >= "0" && "9" >= n) {
						for (l = n, c += 1; n = t.charAt(c), !("0" > n || n > "9");) c += 1,
						l += n;
						if ("." === n) for (c += 1, l += n; n = t.charAt(c), !("0" > n || n > "9");) c += 1,
						l += n;
						if ("e" === n || "E" === n) {
							c += 1,
							l += n,
							n = t.charAt(c),
							("-" === n || "+" === n) && (c += 1, l += n, n = t.charAt(c)),
							("0" > n || n > "9") && a("Bad exponent", u("number", l));
							do c += 1,
							l += n,
							n = t.charAt(c);
							while (n >= "0" && "9" >= n)
						}
						n >= "a" && "z" >= n && (l += n, c += 1, a("Bad number", u("number", l))),
						s = +l,
						isFinite(s) ? d.push(u("number", s)) : a("Bad number", u("number", l))
					} else if ("'" === n || '"' === n) {
						for (l = "", o = n, c += 1; n = t.charAt(c), " " > n && (u("string", l), a("\n" === n || "\r" === n || "" === n ? "Unterminated string.": "Control character in string.", u("", l))), n !== o;) {
							if ("\\" === n) switch (c += 1, c >= h && a("Unterminated string", u("string", l)), n = t.charAt(c)) {
							case "b":
								n = "\b";
								break;
							case "f":
								n = "\f";
								break;
							case "n":
								n = "\n";
								break;
							case "r":
								n = "\r";
								break;
							case "t":
								n = "	";
								break;
							case "u":
								c >= h && a("Unterminated string", u("string", l)),
								n = parseInt(t.substr(c + 1, 4), 16),
								(!isFinite(n) || 0 > n) && a("Unterminated string", u("string", l)),
								n = String.fromCharCode(n),
								c += 4
							}
							l += n,
							c += 1
						}
						c += 1,
						d.push(u("string", l)),
						n = t.charAt(c)
					} else if (e.indexOf(n) >= 0) {
						for (l = n, c += 1;;) {
							if (n = t.charAt(c), c >= h || i.indexOf(n) < 0) break;
							l += n,
							c += 1
						}
						d.push(u("operator", l))
					} else c += 1,
					d.push(u("operator", n)),
					n = t.charAt(c);
					return d
				}
			},
			o = function(t) {
				t = t || {};
				var e, i, o, l, c = {},
				h = function() {
					return this
				},
				d = function(t) {
					return t.nud = h,
					t.led = null,
					t.std = null,
					t.lbp = 0,
					t
				},
				u = function(t) {
					var n, s, l, h;
					return t && e.id !== t && a("Expected '" + t + "'.", e),
					o >= i.length ? void(e = c["(end)"]) : (l = i[o], o += 1, h = l.value, n = l.type, ("operator" === n || "string" !== n) && h in c ? (s = c[h], s || a("Unknown operator.", l)) : "name" === n ? s = d(l) : "string" === n || "number" === n || "regexp" === n ? (s = c["(literal)"], n = "literal") : a("Unexpected token.", l), e = r(s), e.from = l.from, e.to = l.to, e.value = h, e.arity = n, e)
				},
				p = function(t) {
					var i, n = e;
					for (u(), i = n.nud(); t < e.lbp;) n = e,
					u(),
					i = n.led(i);
					return i
				},
				f = {
					nud: function() {
						a("Undefined.", this)
					},
					led: function() {
						a("Missing operator.", this)
					}
				},
				g = function(t, e) {
					var i = c[t];
					return e = e || 0,
					i ? e >= i.lbp && (i.lbp = e) : (i = r(f), i.id = i.value = t, i.lbp = e, c[t] = i),
					i
				},
				m = function(t, e) {
					var i = g(t);
					return i.nud = function() {
						return this.value = c[this.id].value,
						this.arity = "literal",
						this
					},
					i.value = e,
					i
				},
				v = function(t, e, i) {
					var n = g(t, e);
					return n.led = i ||
					function(t) {
						return this.first = t,
						this.second = p(e),
						this.arity = "binary",
						this
					},
					n
				},
				y = function(t, e, i) {
					var n = g(t, e);
					return n.led = i ||
					function(t) {
						return this.first = t,
						this.second = p(e - 1),
						this.arity = "binary",
						this
					},
					n
				},
				b = function(t, e) {
					var i = g(t);
					return i.nud = e ||
					function() {
						return this.first = p(70),
						this.arity = "unary",
						this
					},
					i
				};
				g("(end)"),
				g("(name)"),
				g(":"),
				g(")"),
				g("]"),
				g("}"),
				g(","),
				m("true", !0),
				m("false", !1),
				m("null", null),
				m("undefined"),
				m("Math", Math),
				m("Date", Date);
				for (var x in t) m(x, t[x]);
				return g("(literal)").nud = h,
				g("this").nud = function() {
					return this.arity = "this",
					this
				},
				v("?", 20,
				function(t) {
					return this.first = t,
					this.second = p(0),
					u(":"),
					this.third = p(0),
					this.arity = "ternary",
					this
				}),
				y("&&", 31),
				y("||", 30),
				y("===", 40),
				y("!==", 40),
				y("==", 40),
				y("!=", 40),
				y("<", 40),
				y("<=", 40),
				y(">", 40),
				y(">=", 40),
				v("in", 45,
				function(t) {
					return this.first = t,
					this.second = p(0),
					this.arity = "binary",
					"repeat" === l && (t.arity = "repeat", this.repeat = !0),
					this
				}),
				v("+", 50),
				v("-", 50),
				v("*", 60),
				v("/", 60),
				v("%", 60),
				v("(", 75,
				function(t) {
					var i = [];
					if ("." === t.id || "[" === t.id ? (this.arity = "ternary", this.first = t.first, this.second = t.second, this.third = i) : (this.arity = "binary", this.first = t, this.second = i, "unary" === t.arity && "function" === t.id || "name" === t.arity || "literal" === t.arity || "(" === t.id || "&&" === t.id || "||" === t.id || "?" === t.id || a("Expected a variable name.", t)), ")" !== e.id) for (;;) {
						if (i.push(p(1)), "," !== e.id) break;
						u(",")
					}
					return u(")"),
					this
				}),
				v(".", 80,
				function(t) {
					return this.first = t,
					"name" !== e.arity && a("Expected a property name.", e),
					e.arity = "literal",
					this.second = e,
					this.arity = "binary",
					u(),
					this
				}),
				v("[", 60,
				function(t) {
					return this.first = t,
					this.second = p(0),
					this.arity = "binary",
					u("]"),
					this
				}),
				v("|", 10,
				function(t) {
					var i;
					if (this.first = t, e.arity = "filter", this.second = p(10), this.arity = "binary", ":" === e.id) for (this.arity = "ternary", this.third = i = [];;) if (u(":"), i.push(p(10)), ":" !== e.id) break;
					return this
				}),
				v("catchby", 10),
				b("!"),
				b("-"),
				b("typeof"),
				b("(",
				function() {
					var t = p(0);
					return u(")"),
					t
				}),
				b("[",
				function() {
					var t = [];
					if ("]" !== e.id) for (;;) {
						if (t.push(p(1)), "," !== e.id) break;
						u(",")
					}
					return u("]"),
					this.first = t,
					this.arity = "unary",
					this
				}),
				b("{",
				function() {
					var t, i, n = [];
					if ("}" !== e.id) for (;;) {
						if (t = e, "name" !== t.arity && "literal" !== t.arity && a("Bad property name: ", e), u(), u(":"), i = p(1), i.key = t.value, n.push(i), "," !== e.id) break;
						u(",")
					}
					return u("}"),
					this.first = n,
					this.arity = "unary",
					this
				}),
				b("new",
				function() {
					var t = [];
					if (this.first = p(79), "(" === e.id) {
						for (u("("), this.arity = "binary", this.second = t;;) {
							if (t.push(p(1)), "," !== e.id) break;
							u(",")
						}
						u(")")
					} else this.arity = "unary";
					return this
				}),
				function(t, e) {
					n = t,
					i = s(t, "=<>!+-*&|/%^", "=<>&|"),
					o = 0,
					l = e,
					u();
					var r = p(0);
					return u("(end)"),
					r
				}
			};
			i.parse = o()
		},
		{}],
		50 : [function(t, e, i) {
			"use strict";
			var n = t("./utils"),
			r = function(t, e) {
				for (var i, r = n.parseKeyPath(e), a = t, s = r[0], o = a; a;) {
					if (o = a, i = a._assignments, a.__repeat) if (i && i.length) {
						if ("$index" === s || "$parent" === s) break;
						if (s === i[0]) {
							1 === r.length ? r[0] = "$data": r.shift();
							break
						}
					} else if (e in a) break;
					a = a.$parent
				}
				return {
					vm: o,
					path: r.join(".")
				}
			};
			i.reformScope = r
		},
		{
			"./utils": 52
		}],
		51 : [function(t, e, i) {
			function n(t) {
				return a.lastIndex = 0,
				t && a.test(t)
			}
			function r(t) {
				var e, i, n = [],
				r = [],
				s = 0;
				for (a.lastIndex = 0; e = a.exec(t);) a.lastIndex - s > e[0].length && r.push(t.slice(s, a.lastIndex - e[0].length)),
				i = {
					escape: !e[2],
					path: (e[2] || e[1]).trim(),
					position: r.length,
					textMap: r
				},
				n.push(i),
				r.push(e[0]),
				s = a.lastIndex;
				return t.length > s && r.push(t.slice(s, t.length)),
				n.textMap = r,
				n
			}
			var a = /{{({(.+?)}|.+?)}}/g;
			i.hasToken = n,
			i.parseToken = r
		},
		{}],
		52 : [function(t, e) {
			"use strict";
			function i(t) {
				return t.replace(s, "").split(a)
			}
			function n() {
				var t, e, i, r, a, s, o = arguments[0] || {},
				l = 1,
				c = arguments.length,
				h = !1;
				for ("boolean" == typeof o && (h = o, o = arguments[l] || {},
				l++), "object" == typeof o || u.isFunction(o) || (o = {}); c > l; l++) if (null != (t = arguments[l])) for (e in t) if ("prototype" !== e) if (i = o[e], r = t[e], h && r && (u.isPlainObject(r) || (a = u.isArray(r)))) {
					if (o === r) continue;
					a ? (a = !1, s = i && u.isArray(i) ? i: []) : s = i && u.isPlainObject(i) ? i: {},
					o[e] = n(h, s, r)
				} else u.isUndefined(r) || "string" == typeof o || (o[e] = r);
				return o
			}
			var r = t("./env.js").document,
			a = /(?:\.|\[)/g,
			s = /\]/g,
			o = Object.create ||
			function(t) {
				function e() {}
				return e.prototype = t,
				new e
			},
			l = /-(-?)([a-z])/gi,
			c = function(t) {
				return t.replace(l,
				function(t, e, i) {
					return e ? e + i: i.toUpperCase()
				})
			},
			h = /([A-Z])/g,
			d = function(t) {
				return t.replace(h,
				function(t) {
					return "-" + t.toLowerCase()
				})
			},
			u = {
				noop: function() {},
				ie: function() {
					for (var t, e = 3,
					i = r.createElement("div"), n = i.getElementsByTagName("i"); i.innerHTML = "<!--[if gt IE " + ++e + "]><i></i><![endif]-->", n[0];);
					return e > 4 ? e: t
				} (),
				isObject: function(t) {
					return "object" == typeof t && null !== t
				},
				isUndefined: function(t) {
					return "undefined" == typeof t
				},
				isFunction: function(t) {
					return "function" == typeof t
				},
				isArray: function(t) {
					return u.ie ? t && t.constructor + "" == Array + "": Array.isArray(t)
				},
				isNumeric: function(t) {
					return ! u.isArray(t) && t - parseFloat(t) + 1 >= 0
				},
				isPlainObject: function(t) {
					return ! t || "[object Object]" !== {}.toString.call(t) || t.nodeType || t === t.window ? !1 : !0
				},
				beforeFn: function(t, e, i) {
					return function() {
						var n = e.apply(this, arguments);
						return i && i.call(this, n, arguments) ? n: t.apply(this, arguments)
					}
				},
				afterFn: function(t, e, i) {
					return function() {
						var n = t.apply(this, arguments);
						return i && i.call(this, n, arguments) ? n: (e.apply(this, arguments), n)
					}
				},
				parseKeyPath: i,
				deepSet: function(t, e, r) {
					if (t) {
						var a = i(t),
						s = r;
						a.forEach(function(t, i) {
							i === a.length - 1 ? s[t] = e: s && s.hasOwnProperty(t) ? s = s[t] : (s[t] = {},
							s = s[t])
						})
					} else n(r, e);
					return r
				},
				extend: n,
				create: o,
				toArray: function(t) {
					var e = [];
					try {
						e = Array.prototype.slice.call(t)
					} catch(i) {
						for (var n = 0,
						r = t.length; r > n; n++) e[n] = t[n]
					}
					return e
				},
				hyphenToCamel: c,
				camelToHyphen: d
			};
			e.exports = u
		},
		{
			"./env.js": 45
		}],
		53 : [function(t, e) {
			"use strict";
			function i(t, e) {
				var i, n, r = t,
				a = [],
				o = h[e.path];
				e.watcher = this,
				this.state = 1,
				this.dir = e,
				this.vm = t,
				this.watchers = [],
				this.val = 0 / 0,
				e.parse(),
				o && o._type === e.type || (o = s.summary(e.ast), o._type = e.type, h[e.path] = o),
				e.summary = o;
				for (var l = 0,
				d = e.summary.paths.length; d > l; l++) i = c(t, e.summary.paths[l]),
				r = i.vm,
				n = i.path,
				e.watch ? (r._watchers[n] = r._watchers[n] || [], r._watchers[n].push(this), a = r._watchers[n]) : a = [this],
				this.watchers.push(a);
				e.immediate !== !1 && this.update()
			}
			function n(t, e, i) {
				var n;
				try {
					n = s.summary(l(e))
				} catch(r) {
					r.message = 'SyntaxError in "' + e + '" | ' + r.message,
					console.error(r)
				}
				n.paths.forEach(function(e) {
					for (var n, r = t._watchers[e] || [], a = r.length - 1; a >= 0; a--) n = r[a].dir.update,
					(n === i || n._originFn === i) && r[a].unwatch()
				})
			}
			function r(t) {
				return t.path ? new i(this, t) : void 0
			}
			function a(t) {
				var e = this.val;
				this.val = t,
				this.dir.update(t, e)
			}
			var s = t("./eval.js"),
			o = t("./utils.js"),
			l = t("./parse.js").parse,
			c = t("./scope").reformScope,
			h = {};
			i.unwatch = n,
			i.addWatcher = r,
			i.getWatchers = function(t, e) {
				var i, n = t._watchers,
				r = [];
				for (var a in n) i = a.charAt(e.length),
				0 === a.indexOf(e) && "." === i && (r = r.concat(n[a]));
				return r
			},
			o.extend(i.prototype, {
				update: function() {
					var t, e = this;
					return this._hide ? void(this._needUpdate = !0) : (t = this.dir.getValue(this.vm), void((t !== this.val || o.isObject(t)) && (t && t.then ? t.then(function(t) {
						a.call(e, t)
					}) : a.call(this, t))))
				},
				unwatch: function() {
					this.watchers.forEach(function(t) {
						for (var e = t.length - 1; e >= 0; e--) t[e] === this && (this.state && (t[e].dir.unLink(), this.state = 0), t.splice(e, 1))
					}.bind(this)),
					this.watchers = []
				}
			}),
			e.exports = i
		},
		{
			"./eval.js": 47,
			"./parse.js": 49,
			"./scope": 50,
			"./utils.js": 52
		}]
	},
	{},
	[21])(21)
}(window.jQuery);

/*

console.log(xyz.cmpmgr);
console.log(xyz.cmpmgr.getComponent)
var p = (1, 2);
console.log(p);

var c = xyz.cmpmgr;

var i = new(c.getComponent("qc-popover"))({
	$data: {
		trigger: "",
		hideDestroy: !0,
		content: "aa"
	},
	target: "pop-over",
	handlerx: this.btn
});
i.show()

var i = new(c.getComponent("qc-date-picker"))({
	$el: document.getElementById("pop-over")
});
console.log(i);
*/xyz.ns("xyz.widget");
xyz.widget.dialog = (function() {
	var i = $, //e("$"),
		r = xyz.util, //e("util"),
		o = "keydown.widget_dialog",
		//a = e("nmcConfig"),
		a = {
			dialogBtnTxt: {
				close: "关闭",
				submit: "确定",
				cancel: "取消",
				tips: "提示"
			}
		},
		s = {
			render_if: function() {
				l.mask || (l.mask = i("<div/>").css({
					position: "fixed",
					left: 0,
					top: 0,
					"z-index": "999",
					width: "100%",
					height: "100%",
					opacity: "0.5",
					"background-color": "#000"
				}).appendTo(i("body")))
			},
			show: function() {
				l.mask.show();
				l.mask.removeClass("mask-out").addClass("mask-in");
			},
			hide: function() {
				l.mask.hide();
				r.animationend(l.mask[0], function() {
					l.mask.hide()
				});
				l.mask.removeClass("mask-in").addClass("mask-out");
			}
		},
		l = {
			el: null,
			mainEl: null,
			contentEl: null,
			mask: null,
			create: function(html, t, n, option) {
				this.destroy();
				var l = this,
					u = {
						animation: !0,
						button: null,
						title: "",
						closeIcon: !0,
						mask: !0,
						"class": "dialog_layer_v2",
						isMaskClickHide: !0,
						defaultCancelBtn: !0,
						defaultCancelBtnTxt : null,
						defaultCancelCb: null,
						beforeButtonHtml: "",
						isFromConfirm: !1,
						buttonHighlight: [],
						buttonDisable: [],
						preventResubmit: !1,
						callback: function() {},
						onload: null,
						owner: "",
						esc: !0,
						time: ""
					},
					c = a.dialogBtnTxt,
					d = i("body");
				if (option = option || {}, option = this.option = i.extend({}, u, option), !this.el) {
					var f = i("<div/>").css({
						position: "fixed",
						display: "none",
						zIndex: "1000"
					}),
						p = i("<div/>").addClass("dialog_layer_main"),
						h = i("<div>loading...</div>");
					p.append(h), f.append(p), d.append(f), this.el = f, this.mainEl = p, this.contentEl = h
				}
				if (n = void 0 == n || null == n ? "" : n, t = void 0 == t || null == t ? "" : t, this.height = n, this.width = t, option.animation && (option["class"] += " modal-in"), this.el.attr("class", option["class"]), option.title || option.closeIcon) {
					var m = i("<div/>").addClass("dialog_layer_title");
					this.headerEl = m;
					if (this.mainEl.prepend(m), option.title && m.append("<h3>" + option.title + "</h3>"), option.closeIcon) {
						var g = i("<a/>").addClass("close").attr({
							title: c.close,
							href: "javascript:;"
						}).html("<i>×</i>");
						m.append(g);
						g.on("click", function() {
							l.defaultCancel()
						})
					}
					this.contentEl.addClass("dialog_layer_cont")
				}
				if (option.button) {
					var y = i("<div/>").addClass("dialog_layer_ft");
					this.footerEl = y;
					option.beforeButtonHtml && y.append(option.beforeButtonHtml).append(" ");
					var b = 0;
					for (var x in option.button) {
						var w = "btn";
						w += option.buttonHighlight[b] || void 0 == option.buttonHighlight[b] ? " btn_blue" : " btn_white_2", option.buttonDisable[b] && (w += " btn_unclick");
						var C = i('<a href="javascript:void(0);"/>').addClass(w).html("<span>" + x + "</span>"),
							T = option.button[x];
						!
						function(e, t) {
							e.on("click", function() {
								var n = i(this);
								n.hasClass("btn_unclick") || (option.preventResubmit && n.addClass("btn_unclick"), "function" == typeof t && t(e, l.el))
							})
						}(C, T), y.append(C).append(" "), b++
					}
					if (option.defaultCancelBtn) {
						var k = i('<a href="javascript:void(0);"/>').addClass("btn btn_white_2").html("<span>" + (option.defaultCancelBtnTxt || c.cancel) + "</span>");
						y.append(k), k.on("click", function() {
							l.defaultCancel()
						})
					}
					this.mainEl.append(y)
				}

				i(document).off(o).on(o, function(e) {
					27 === e.which && option.esc && (e.preventDefault(), l.defaultCancel())
				});
				if(option.mask){
					s.render_if();
					s.show();
					this.mask.off("click");
					if(option.isMaskClickHide){
						this.mask.on("click", function() {
							l.defaultCancel()
						});
					}
				}
				option.time && setTimeout(function() {
					l.hide();
				}, option.time);
				option.owner && (this.owner = option.owner)
				
				this.el.css({
					width: t,
					height: n
				}).show();
				var contentPadding = 20;
				var height = n - (this.headerEl ? this.headerEl.outerHeight() : 0) - (this.footerEl ? this.footerEl.outerHeight() : 0)  - contentPadding*2;
				this.contentEl.css("height", height);
				this.center();

				var me = this;
				if(typeof html == 'string' && html != ''){
					this.contentEl.html(html);
					option.onload && option.onload.call(this, this.el);
				}else if(option.url){
					var url = option.url;
					url += (url.indexOf('?') == -1 ? "?" : "&") + "t="  + Math.random();
					$.ajax({
						type: 'GET',
						url: url,
						dataType: 'text',
						success: function(data, status, xhr){
							me.contentEl.html(data);
							me.center();
							option.onload && option.onload.call(me, me.el);
						}
					});
				}

				//var v = this.el.find("iframe")[0];
				//v && (v.callback = option.callback); // ??
				//option.onload && option.onload.call(this, this.el);

				return this.el;
			},
			defaultCancel: function() {
				var e = this.option;
				this.hide();
				e.defaultCancelCb && e.defaultCancelCb();
			},
			hide: function() {
				if (this.el && !this.el.hasClass("modal-out")) {
					var e = this,
						t = this.option;
					this.mask && this.mask.off("click") && s.hide();
					t.animation ? (r.animationend(this.el[0], function() {
						e.destroy()
					}), this.el.removeClass("modal-in").addClass("modal-out")) : e.destroy()
				}
			},
			isShow: function() {
				return this.el && this.el.is(":visible")
			},
			freeze: function(e, t) {
				var n = "content-freeze-mask",
					r = "pointer-events",
					o = this,
					a = i(t || o.contentEl),
					s = a.siblings("." + n);
				return e ? (s.length || (s = i("<div></div>").css({
					position: "absolute",
					zIndex: 1001,
					backgroundColor: "gray",
					opacity: 0
				}).addClass(n).appendTo(a.parent())), s.show().offset(a.offset()).width(a.outerWidth()).height(a.outerHeight()), i(document.activeElement).blur(), a.css(r, "none")) : (s.hide(), a.css(r, "")), o
			},
			toggleBtnLoading: function(e, t) {
				t = t || 0;
				var n = t === +t ? this.getBtn(t) : i(t),
					r = n.find("i");
				e ? r.length || (r = i('<i class="n-loading-icon"></i>').prependTo(n)) : r.remove()
			},
			toggleBtnDisable: function(e, t) {
				t = t || 0;
				var n = this.getBtn(t);
				e ? n.addClass("btn_unclick") : n.removeClass("btn_unclick")
			},
			getBtn: function(e) {
				return this.el.find(".dialog_layer_ft").find(".btn").eq(e)
			},
			center: function() {
				var e = this.option,
					t = i(window),
					n = t.width(),
					r = t.height(),
					o = e.top || parseInt((r - (this.height || this.el.height())) / 2),
					a = e.left || parseInt((n - (this.width || this.el.width())) / 2);
				this.el.css({
					left: a,
					top: o,
					margin: "0"
				})
			},
			destroy: function() {
				this.el && (this.el.hide(), this.contentEl && this.contentEl.html("").attr("class", "").removeAttr("style"), this.mainEl.find("> .dialog_layer_title").remove(), this.mainEl.find("> .dialog_layer_ft").remove(), this.owner = null, i(document).off(o), this.freeze(!1))
			},
			/**
			 * confirm(text, okFn, cancelFn, title, width, okBtnName, cancelBtnName, hideIcon);
			 * confirm(text, okFn, cancelFn, {
					title : title,
					width: widith,
					mainBtnName : mainBtnName,
					defaultCancelBtn : defaultCancelBtn,
					hideIcon : hideIcon
			   });
			 * 
			 */
			confirm: function(e, t, n, i, r, o, s, u) {
				var c = {};
				"object" == typeof i && (c = i, i = c.title, r = c.width, o = c.mainBtnName, s = c.defaultCancelBtn, u = c.hideIcon);
				var d = u ? "" : '<td height="72" class="i"><i class="ico ico-warn mr10"></i></td>';
				e = '<div class="coin-alert"><table class="ui-popmsg"><tbody><tr>' + d + '<td height="72" class="t"><span class="info"><span class="tit">' + e + "</span></span></td></tr></tbody></table></div>";
				var f = a.dialogBtnTxt;
				s = void 0 == s ? !0 : s;
				var p = {
					title: i || f.tips,
					isMaskClickHide: 0,
					isFromConfirm: 1,
					preventResubmit: !0,
					button: {},
					defaultCancelBtn: s,
					defaultCancelCb: function() {
						n && n()
					}
				};
				o = o || f.submit, p.button[o] = function() {
					t && t(), l.hide()
				}, l.create(e, r, "", p)
			}
		};

	return l;

})();
xyz.cmpmgr.tag("x-grid-view", xyz.cmpmgr.getComponent("grid-view").extend({

	getData: function(ps, callback){
		var me = this,
			p = [this.showPagination ? this.buildQueryInfo(ps) : null];

		if(!this.queryParam){
			this.queryParam = this.buildParam(ps) || [];
		}
		p = p.concat(this.queryParam);

		/*
		$.ajax({
			type: 'POST',
			url: this.url,
			data: p,
			dataType: 'json',
			success: function(data, status, xhr){
				me.queryType = false;
				callback(null, me.processData(data));
			}
		});
		*/

		$.jsonRPC.request(this.url, {
			params: p,
			success: function(method, resp) {
				var RPCResult = xyz.data.RPCResult,
				    r = new RPCResult(resp);

				if(r.code == RPCResult.SUCCESS){
					var d = me.processData(r.data);
					if(me.queryType){
						me.totalNum = d.totalNum;
						me.queryType = false;
					}
					if(d.totalNum == -1){
						d.totalNum = me.totalNum;
					}
					callback(null, d);
				}
			},
			error: function(){

			}
		})
	},

	buildQueryInfo: function(lp){
		var queryInfo = {
			start: lp.count * (lp.page - 1),
			limit: lp.count,
			queryType: this.queryType ? 1 : 0,
			sortInfos: [{
				fieldName: lp.orderField,
				desc: !!lp.order
			}]
		};
		return queryInfo;
	},

	buildParam: function(lp){
		return null;
	},

	processData: function(data){
		var ds = xyz.data.DataSet.parse(data);
		return {
			totalNum: ds.totals,
			list : ds.data
		};
	},

	load: function(p, t){
		this.queryType = true;
		this.queryParam = p || this.buildParam(this.latestParam);
		this.listFn(this.queryParam, t);
	}

}, {
	defaults: {
		url: null,
		count: 10,
		initGetData: false
	}
}));

xyz.widget.GridView = xyz.cmpmgr.getComponent("x-grid-view");
xyz.widget.GridEditor = xyz.cmpmgr.getComponent("grid-editor");
xyz.widget.DatePicker = xyz.cmpmgr.getComponent("qc-date-picker");
xyz.data = {};

function RPCResult(o){
	var e;

	if(typeof o === 'string'){
		o = $.parseJSON(o);
	}else if(typeof o === 'object' && o.responseText){
		o = $.parseJSON(o.responseText);
	}
	o = o || {};
	e = o.error;
	this.id = o.id || null;
	this.data = typeof o.result === 'undefined' ? null : o.result;
	this.code = e ? e.errorCode : RPCResult.SUCCESS;
	this.message = e ? e.message : null;
}

RPCResult.SUCCESS = 0;
xyz.data.RPCResult = RPCResult;

function DataSet(data, fields, totals){
	this.fields = fields;
	this.data = data;
	this.count = data && data.length ? data.length : 0;
	this.totals = totals;
}

DataSet.parse = function(o){
	//�ֶ�
	var fields = o.fields || [],
	    rta = [];

	for (var i = 0, len = fields.length; i < len; i++) {
		rta.push({
			name : fields[i]["fieldName"],
			type : fields[i]["fieldType"],
		});
	}

	//���
	var results = o.data || [],
	    records = [];
	for (var i = 0, m = results.length; i < m; i++) {
		var row = results[i],
		    name = null,
		    values = {};

		for (var j = 0, n = rta.length; j < n; j++) {
			name = rta[j].name;
			values[name] = (row[j] == null || row[j] == undefined) ? '' : row[j];
		}
		records.push(values);
	}

	var meta = {
		fields : rta
	};

	return new DataSet(records, meta, o.totalRows);
};

xyz.data.DataSet = DataSet;
xyz.cmpmgr.tag("x-combo", xyz.cmpmgr.getComponent("qc-combo").extend({

	getData: function(p, callback){
		var me = this;

		/*
		$.ajax({
			type: 'POST',
			url: this.url,
			data: p,
			dataType: 'json',
			success: function(data, status, xhr){
				var d = me.processData(data);
				console.log(d);
				callback(null, d);
			}
		});
		*/
		$.jsonRPC.request(this.url, {
			params: p,
			success: function(method, resp) {
				var RPCResult = xyz.data.RPCResult,
				    r = new RPCResult(resp);
				if(r.code == RPCResult.SUCCESS){
					var d = me.processData(r.data);
					callback(null, d);
				}
			},
			error: function(){

			}
		})
	},

	buildParam: function(){
		return null;
	},

	processData: function(data){
		var ds = xyz.data.DataSet.parse(data);
		return {
			list : ds.data
		};
	},

	load: function(p, t){
		p = p || this.buildParam();
		this._listFn(p, t);
	}

}, {
	defaults: {
		url: null,
		initGetData: false
	}
}));

xyz.widget.Combo = xyz.cmpmgr.getComponent("x-combo");
xyz.widget.tips = function() {
	var jq = jQuery,
		loadingWord = "正在加载...",
		a = null,
		l = null,
		v = xyz.util,
		u = {
			enableLoading: 1,
			isLoading: 0,
			manualReqNum: 0,
			success: function(text, time) {
				this.flash(text, "success", time)
			},
			error: function(text, time) {
				this.flash(text, "error", time)
			},
			flash: function(text, t, time) {
				if (text) {
					var _this = this,
						cls = "";
					!time && (time = 4e3), cls = "success" === t ? "top-alert-icon-done" : "top-alert-icon-waring", _this.showFlash(text, cls), a = setTimeout(function() {
						_this.hideFlash(1)
					}, time)
				}
			},
			showFlash: function(text, iconCls) {
				clearTimeout(a), a = null;
				var $topalert = jq("#topAlert"),
					$flashmsg = jq("#flashMsg");
				$flashmsg.length || ($topalert = jq("<div/>").addClass("top-alert").attr("id", "topAlert").css({
					"z-index": 1100,
					"margin-left": "-200px"
				}), $flashmsg = jq("<span/>").attr("id", "flashMsg"), $topalert.append($flashmsg), $topalert.appendTo("body")), $topalert.show(), $flashmsg.html(text).show().attr("class", iconCls + " fade-in")
			},
			hideFlash: function(e) {
				var t = function() {
						a = null;
						var $topalert = jq("#topAlert"),
							$flashmsg = jq("#flashMsg");
						$flashmsg.length && !$flashmsg.hasClass("fade-out") && (v.animationend($flashmsg[0], function() {
							!a && $flashmsg.html("").hide()
						}), $flashmsg.removeClass("fade-in").addClass("fade-out"), $topalert.hide())
					};
				e ? t() : !a && t()
			},
			hideFlashNow: function() {
				jq("#flashMsg").hide().html(""), jqi("#topAlert").hide()
			},
			initLoading: function() {
				var e = this,
					t = jqi(document);
				t.ajaxStart(function() {
					e.ajaxLoading = 1, !e.manualReqNum && e._loadingStart()
				}), t.ajaxStop(function() {
					e.ajaxLoading = 0, !e.manualReqNum && e._loadingStop()
				})
			},
			_loadingStart: function() {
				var e = this,
					t = 300;
				e.enableLoading && (clearTimeout(s), e.isLoading = 1, s = setTimeout(function() {
					var t = i("#flashMsg");
					t.length && t.html() || e.isLoading && e.showLoading()
				}, t))
			},
			_loadingStop: function() {
				var e = this;
				setTimeout(function() {
					!e.enableLoading || e.manualReqNum || e.ajaxLoading || e.stopLoading()
				}, 0)
			},
			showLoading: function(text) {
				this.showFlash(text||loadingWord, "top-alert-icon-doing")
			},
			stopLoading: function() {
				this.isLoading = 0, this.hideFlash()
			},
			requestStart: function() {
				var e = this;
				this.manualReqNum++, 1 != this.manualReqNum || this.ajaxLoading || (this._loadingStart(), clearTimeout(l), l = setTimeout(function() {
					e.manualReqNum > 0 && (e.manualReqNum = 0, e._loadingStop())
				}, 5e3))
			},
			requestStop: function() {
				this.manualReqNum--, this.manualReqNum < 0 && (this.manualReqNum = 0), 0 != this.manualReqNum || this.ajaxLoading || this._loadingStop()
			},
			setLoading: function(e) {
				this.enableLoading = e
			}
		};
	return u
}();xyz.ns("xyz.validator");
/**
 * 表单校验辅助工具。
 * 所提供的验证方法仅适用于普通输入框,如text, password, number，textarea等.
 *
 */
xyz.validator.Utils = (function() {
	function hasAttr(field, attrName) {
		var attrVal = $(field).attr(attrName);
		return typeof(attrVal) == undefined ? false : true;
	}
	return{
		//有required属性且不为空，返回true.无reqired属性或有required属性但值为空都返回false.
		checkRequired : function(val, field) {
			return hasAttr(field, "required") && val != "";
		},
		checkMaxLength : function(val, field) {
			return hasAttr(field, "maxlength") && val.length <= parseInt($(field).attr("maxlength"));
		},
		checkMinLength : function(val, field) {
			return hasAttr(field, "minlength") && val.length >= parseInt($(field).attr("minlength"));
		}
	}
})();

/**
 * 表单校验器.
 *
 */
xyz.validator.Validator = function(options) {
	options = options || {}, $.extend(this, options), this._rules = $.extend({}, xyz.validator.rules, options.rules);
	
}
xyz.validator.Validator.prototype = {
	errClass: "error",
	typeAttr: "name",
	validateSelector: "[data-validate]",
	rules: null,
	//显示错误
	showErr: function(t, e, i) {
		i = i || {},i.noTips || this.showTips(t, e), $(t).parent().addClass(this.errClass)
	},
	hideErr: function(field) {
		this.hideTips(field), $(field).parent().removeClass(this.errClass)
	},
	showTips: function(field, text) {
		var $field = $(field);
		$field.siblings(".tc-15-input-tips:first").text(text);
	},
	hideTips: function(field) {
		$(field).siblings(".tc-15-input-tips:first").empty();
	},
	/**
	 * 表单元素校验提示，只针对单项的校验.
	 * @param field 表单元素
	 * @param options 可选参数,是一个json对象,options中可通过type属性指定判断规则
	 */
	validate: function(field, options) {
		options = options || {};
		var result, $element = $(field),
			val = options.value || field.value,
			type = options.type || $element.attr(this.typeAttr),
			rulesr = this._rules;
		if (rulesr[type]) {
			if (!field.disabled && (result = rulesr[type].call(this, val, field))) return (options.showErr || this.showErr).call(this, field, result, options), !1
		} else console.error("没有找到校验规则: " + type);
		return (options.hideErr || this.hideErr).call(this, field), !0
	},
	/**
	 * 单纯校验，不提示.
	 * @param selector 表单选择器表达式
	 */
	checkAll: function(selector) {
		for (var result, item, $field = $(selector), $elements = $field.find(this.validateSelector), isValid = !0, i = 0, len = $elements.length; len > i; i += 1) if (item = $elements[i], result = this.validate(item, {
			showErr: function(){},
			hideErr: function(){},
			noTips: !0
		}), !result) {
			isValid = !1;
			break
		}
		return isValid
	},
	/**
	 * 表单校验提示.
	 * @param selector 表单选择器表达式
	 */
	validateAll: function(selector) {
		var self = this, r = true, $pn = $(selector), $field, name, $fields = $pn.find(this.validateSelector);
		return $fields.each(function() {
			name = $(this).attr(self.typeAttr),
			val = $(this).val(),
			o = {value: val, type: name};
			return !self.validate(this, o)  ? (r = false, !1) : void 0;
			
		}), r;
	}
}
xyz.base = function() {
	return {
		/**
		 * 生成唯一的ID
		 * @method guid
		 * @grammar Base.guid() => String
		 * @grammar Base.guid( prefx ) => String
		 */
		guid : (function() {
			var counter = 0;

			return function( prefix ) {
				var guid = (+new Date()).toString( 32 ),
					i = 0;

				for ( ; i < 5; i++ ) {
					guid += Math.floor( Math.random() * 65535 ).toString( 32 );
				}

				return (prefix || 'wu_') + guid + (counter++).toString( 32 );
			};
		})(),
		getContextPath : function() {  
			var pathName = window.document.location.pathname, 
				//获取带"/"的项目名，如：/pb   
				projectName = pathName.substring(0, pathName.substr(1).indexOf('/') + 1);  
			return projectName; 
		},  
		formatSize : function( size, pointLength, units ) {
			var unit;

			units = units || [ 'B', 'K', 'M', 'G', 'TB' ];

			while ( (unit = units.shift()) && size > 1024 ) {
				size = size / 1024;
			}
			return (unit === 'B' ? size : size.toFixed( pointLength || 2 )) +
					unit;
		}
	}
}();
/** 
 * xyz.widget.uploader  文件上传器
 */	
xyz.widget.uploader = function(opts) {
	var me = this;

	opts = me.options = $.extend( true, {}, xyz.widget.uploader.options, opts || {} );
	if(!opts.view)
		throw new Error('cannot found property view');
	if(!opts.btn)
		throw new Error('cannot found property btn');
	if(!opts.url)
		throw new Error('cannot found property url');
	if (!WebUploader.Uploader.support()) {
		alert( 'Web Uploader 不支持您的浏览器！如果你使用的是IE浏览器，请尝试升级 flash 播放器');
		throw new Error( 'WebUploader does not support the browser you are using.' );
	}
	var $view = $(opts.view),
		$btn = $(opts.btn),
		pick_id = xyz.base.guid("pick_"),
		$pickBtn = $('<div style="display: none;"></div>').attr("id", pick_id).appendTo("body"),//直实的文件链接
		// 添加的文件数量
		fileCount = 0,
		// 添加的文件总大小
		fileSize = 0,
		// 所有文件的进度信息，key为file id
		percentages = {},
		completeFiles = [], //已成功上传附件
		supportTransition = (function(){
			var s = document.createElement('p').style,
				r = 'transition' in s ||
					  'WebkitTransition' in s ||
					  'MozTransition' in s ||
					  'msTransition' in s ||
					  'OTransition' in s;
			s = null;
			return r;
		})(),
		handleError = function(code) {
			switch(code ) {
				case 'exceed_size':
					text = '文件大小超出';
					break;

				case 'interrupt':
					text = '上传暂停';
					break;

				default:
					text = '上传失败，请重试';
					break;
			}
			me.options.showError(text);
		},
		// 当有文件添加进来时执行，负责view的创建
		addFile = function(file) {
			var ext = file.ext,
				iconCls = "att-ico-file32-" + ext,
				$item = $('<div class="att g-col-3" id="' + file.id + '">' +
							'	<div class="att-inner">' +
							'		<div class="att-ico att-ico-file32 '+ iconCls +'"></div>' +
							'		<div class="att-title">' + file.name + '</div>' +
							'		<div class="att-remove"><a href="javascript:void(0)" class="nui-txt-link">删除</a></div>' +
							'		<div class="att-des"></div>' +
							'	</div>' +
							'</div>'),
				$infobar = $item.find('.att-des'),//实时信息显示
				$delbtn = $item.find('.att-remove > a'), //文件删除链接
				//进度条
				$prgress = $('<div class="att-progress">' +			
							'	<span class="att-progress-bar">' +
							'		<span class="att-progress-bar-inner"></span>' +
							'	</span>' +
							'	<span class="att-progress-text"></span>' +
							'</div>').appendTo($infobar);
		   
			if (file.getStatus() === 'invalid') {
				handleError(file.statusText);
			} else {
				percentages[ file.id ] = [ file.size, 0 ];
				file.rotation = 0;
			}
			file.on('statuschange', function(cur, prev) {
				if (prev === 'progress' ) {
					$prgress.hide().find(".att-progress-bar-inner").css("width", "0");
				}
				// 成功
				if ( cur === 'error' || cur === 'invalid' ) {
					handleError(file.statusText);
					percentages[ file.id ][ 1 ] = 1;
				} else if ( cur === 'interrupt' ) {
					handleError('interrupt');
				} else if ( cur === 'queued' ) {
					percentages[ file.id ][ 1 ] = 0;
				} else if ( cur === 'progress' ) {//正在上传
					$prgress.css('display', 'block');
				} else if ( cur === 'complete' ) { //上传完成
					var size = xyz.base.formatSize(file.size);
					$infobar.append(size + " <span>上传完成</span>");
				}
			});
			$delbtn.click(function() {//删除文件
				uploader.removeFile( file );
			});
			$item.appendTo($view);
		},
		// 负责view的销毁
		removeFile = function(file) {
			var $item = $('#'+file.id), index = -1;;
			delete percentages[ file.id ];
			$item.off().find('.att-remove > a').off().end().remove();
			completeFiles && $.each(completeFiles, function(i, f) {
				if(f.id == file.id) {
					index = i;
					return false;
				}
			});
			index != -1 && completeFiles.splice(index, 1); //删除已上传附件
			me.options.onFileRemove && me.options.onFileRemove(file);//文件删除回调
		},
		// 实例化
		uploader = WebUploader.create({
			pick: {
				id: '#' + pick_id
			},
			// swf文件路径
			swf: xyz.base.getContextPath() + '/css/img/Uploader.swf',
			auto: this.options.auto, //自动上传
			chunked: this.options.chunked,//是否分块 
			chunkSize : this.options.chunkSize,
			server: this.options.url, //上传地址
			fileNumLimit: this.options.maxFiles, //文件数限制
			fileSizeLimit: this.options.maxSize, //文件总大小限制
			fileSingleSizeLimit: this.options.maxSingleSize //单个文件大小限制

		});

	//实时更新进度条
	uploader.onUploadProgress = function(file, percentage) {
		var $item = $('#'+file.id),
			$percent = $item.find('.att-progress .att-progress-bar-inner'),
			$percentView = $item.find('.att-progress .att-progress-text'),
			perText = parseInt(percentage*100) + "%";
		$percent.css('width', perText);
		$percentView.text(perText);
		percentages[file.id][ 1 ] = percentage;
	},
	//添加文件事件
	uploader.onFileQueued = function( file ) {
		fileCount++;
		fileSize += file.size; 
		
		addFile( file );
		//uploader.upload();
		//setState( 'ready' );
	   // updateTotalProgress();
	},
	//删除文件事件
	uploader.onFileDequeued = function( file ) {
		fileCount--;
		fileSize -= file.size;
		removeFile(file);
		//updateTotalProgress();

	},
	//错误事件
	uploader.onError = function(code) {
		var text = "", max = 0, file;
		switch(code ) {
			case 'F_DUPLICATE':
				file = arguments[1];
				text = '文件['+ file.name +']已选择，不能重复上传';
				break;
			case 'Q_EXCEED_NUM_LIMIT':
				max = arguments[1];
				text = '最多只能添加' + max + "个文件";
				break;
			case 'Q_EXCEED_SIZE_LIMIT':
				max = arguments[1];
				text = '文件总大小不能超过' + xyz.base.formatSize(max);
				break;
			case 'F_EXCEED_SIZE':
				max = arguments[1];
				text = '文件大小不能超过' + xyz.base.formatSize(max);
				break;
			default:
				text = '上传失败，请重试';
				break;
		}
		me.options.showError(text);
	},
	uploader.on('uploadSuccess', function( file ,response) {
		//一个文件上传成功时调用，若文件分块上传时只调用一次
		completeFiles.push(file); //添加已上传附件
		me.options.onUploadSuccess && me.options.onUploadSuccess(file, response.result || null);//记录每个上传文件返回的信息
	}),
	
	uploader.on('uploadError', function(file) {
		$('#'+file.id ).find('.att-des').text('上传出错');
	}),
	
	uploader.on('uploadComplete', function( file ) {
		$('#'+file.id).find('.att-progresss').fadeOut();
	}),
	//判断是否上传出错
	uploader.on('uploadAccept', function(obj, ret ) {
		if (ret.error) {
			me.options.showError(ret.error.message);
			return false;
		}
		me.options.onUploadAccept && me.options.onUploadAccept(obj, ret.result);//记录每个上传文件返回的信息
		return true;
	}),
	$btn.click(function() {
		$pickBtn.find("input[type=file]").click();
	});	
	return {
		upload : function() {
			uploader.upload();
		},
		getCompleteFiles : function() {
			return 	completeFiles;

		}
	}
}

xyz.widget.uploader.options = {
	view : '',
	btn : '',
	chunked: true, //是否分块 
	chunkSize : 5 * 1024 * 1024,
	url: null,
	auto : true,
	maxFiles : 10,
	maxSize : 500 * 1024 *1024, //所有文件最大200M
	maxSingleSize : 50 * 1024 * 1024, //单个文件最大50M
	onUploadSuccess : function() {},
	onUploadAccept : function() {},
	onFileRemove : function() {},
	showError : function() {}
};

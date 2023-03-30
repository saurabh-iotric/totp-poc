

var base32 = require('base32.js');
var crypto = require('crypto');
var url = require('url');
var util = require('util');

exports.generateASCIIFromSecret = (length, symbols) => {
    var bytes = crypto.randomBytes(length || 32);
    var set = 'ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz0123456789';
    if (symbols) {
      set += '!@#$%^&*()<>?/[]{},.:;';
    }
  
    var secret = '';
    for (var i = 0, l = bytes.length; i < l; i++) {
      secret += set[Math.floor(bytes[i] / 255.0 * (set.length - 1))];
    }
    return secret;
  };
exports.generateSecret = function generateSecret (options) {
    // options
    if (!options) options = {};
    var length = options.length || 32;
    var appName = options.app || 'SecretKey';
    var qrCodes = options.qrCodes || false;
    var googleAuthQr = options.googleAuthQr || false;
    var otpAuthUrl = options.otpAuthUrl != null ? options.otpAuthUrl : true;
    var symbols = true;
    var issuer = options.issuer;
  
    // turn off symbols only when explicity told to
    if (options.symbols !== undefined && options.symbols === false) {
      symbols = false;
    }
  
    // generate an ascii key
    var key = this.generateASCIIFromSecret(length, symbols);
  
    // return a SecretKey with ascii, hex, and base32
    var SecretKey = {};
    SecretKey.ascii = key;
    SecretKey.hex = Buffer(key, 'ascii').toString('hex');
    SecretKey.base32 = base32.encode(Buffer(key)).toString().replace(/=/g, '');
  
    // generate some qr codes if requested
    if (qrCodes) {
      console.warn('Speakeasy - Deprecation Notice - generateSecret() QR codes are deprecated and no longer supported. Please use your own QR code implementation.');
      SecretKey.qr_code_ascii = 'https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=' + encodeURIComponent(SecretKey.ascii);
      SecretKey.qr_code_hex = 'https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=' + encodeURIComponent(SecretKey.hex);
      SecretKey.qr_code_base32 = 'https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=' + encodeURIComponent(SecretKey.base32);
    }
  
    // add in the Google Authenticator-compatible otpauth URL
    if (otpAuthUrl) {
      SecretKey.otpauth_url = exports.otpauthURL({
        secret: SecretKey.ascii,
        label: appName ,
        issuer: issuer,
        email : options.email
      });
    }
  
    // generate a QR code for use in Google Authenticator if requested
    if (googleAuthQr) {
      console.warn('Speakeasy - Deprecation Notice - generateSecret() Google Auth QR code is deprecated and no longer supported. Please use your own QR code implementation.');
      SecretKey.google_auth_qr = 'https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=' + encodeURIComponent(exports.otpauthURL({ secret: SecretKey.base32, label: name }));
    }
  
    return SecretKey;
  };

  exports.otpauthURL = function otpauthURL (options) {
    // unpack options
    var secret = options.secret;
    var label = options.label;
    var issuer = options.issuer;
    var type = (options.type || 'totp').toLowerCase();
    var counter = options.counter;
    var algorithm = (options.algorithm || 'sha1').toLowerCase();
    var digits = options.digits || 6;
    var period = options.period || 30;
    var encoding = options.encoding || 'ascii';
    var userEmail = options.email || '';

    console.log("--label",label)
    console.log(userEmail)
  
    // validate type
    switch (type) {
      case 'totp':
      case 'hotp':
        break;
      default:
        throw new Error('Speakeasy - otpauthURL - Invalid type `' + type + '`; must be `hotp` or `totp`');
    }
  
    // validate required options
    if (!secret) throw new Error('Speakeasy - otpauthURL - Missing secret');
    if (!label) throw new Error('Speakeasy - otpauthURL - Missing label');
  
    // require counter for HOTP
    if (type === 'hotp' && (counter === null || typeof counter === 'undefined')) {
      throw new Error('Speakeasy - otpauthURL - Missing counter value for HOTP');
    }
  
    // convert secret to base32
    if (encoding !== 'base32') secret = new Buffer(secret, encoding);
    if (Buffer.isBuffer(secret)) secret = base32.encode(secret);
  
    // build query while validating
    var query = {secret: secret};
    if (issuer) query.issuer = issuer;
    if (type === 'hotp') {
      query.counter = counter;
    }
  
    // validate algorithm
    /*
    if (algorithm != null) {
      switch (algorithm.toUpperCase()) {
        case 'SHA1':
        case 'SHA256':
        case 'SHA512':
          break;
        default:
          console.warn('Speakeasy - otpauthURL - Warning - Algorithm generally should be SHA1, SHA256, or SHA512');
      }
      query.algorithm = algorithm.toUpperCase();
    }
    */

    /* validate digits
    if (digits != null) {
      if (isNaN(digits)) {
        throw new Error('Speakeasy - otpauthURL - Invalid digits `' + digits + '`');
      } else {
        switch (parseInt(digits, 10)) {
          case 6:
          case 8:
            break;
          default:
            console.warn('Speakeasy - otpauthURL - Warning - Digits generally should be either 6 or 8');
        }
      }
      query.digits = digits;
    }*/
  
    // validate period
    /*if (period != null) {
      period = parseInt(period, 10);
      if (~~period !== period) {
        throw new Error('Speakeasy - otpauthURL - Invalid period `' + period + '`');
      }
      query.period = period;
    }*/
  
    // return url
   /* const urlQr = `otpauth://totp/${label}:${userEmail}?secret=${secret}&issuer=${issuer}`
    return urlQr*/
   return url.format({
      protocol: 'otpauth',
      slashes: true,
      hostname: type,
      pathname: encodeURIComponent(`${label}:${userEmail}`),
      query: query
    });
  };
  

  exports.hotp = function hotpGenerate (options) {

    // verify secret and counter exists
    var secret = options.secret;
    var key = options.key;
    var counter = options.counter;
  
    if (key === null || typeof key === 'undefined') {
      if (secret === null || typeof secret === 'undefined') {
        throw new Error('Speakeasy - hotp - Missing secret');
      }
    }
  
    if (counter === null || typeof counter === 'undefined') {
      throw new Error('Speakeasy - hotp - Missing counter');
    }
  
    // unpack digits
    // backward compatibility: `length` is also accepted here, but deprecated
    var digits = (options.digits != null ? options.digits : options.length) || 6;
    if (options.length != null) console.warn('Speakeasy - Deprecation Notice - Specifying token digits using `length` is no longer supported. Use `digits` instead.');
  
    // digest the options
    var digest = options.digest || exports.digest(options);
   
    // compute HOTP offset
    var offset = digest[digest.length - 1] & 0xf;
  
    // calculate binary code (RFC4226 5.4)
    var code = (digest[offset] & 0x7f) << 24 |
      (digest[offset + 1] & 0xff) << 16 |
      (digest[offset + 2] & 0xff) << 8 |
      (digest[offset + 3] & 0xff);
  
    // left-pad code
    //[,,,,,,      ]0   000000 also converting the string code into base10String
    code = new Array(digits + 1).join('0') + code.toString(10);
  
    // return length number off digits
    return code.substr(-digits)
  };

  //exports.totp = function totpGenerate (options) {
  exports.totp = (options) => {
    // shadow options
    options = Object.create(options);
  
    // verify secret exists if key is not specified
    var key = options.key;
    var secret = options.secret;
    if (key === null || typeof key === 'undefined') {
      if (secret === null || typeof secret === 'undefined') {
        throw new Error('Speakeasy - totp - Missing secret');
      }
    }
  
    // calculate default counter value
    if (options.counter == null) options.counter = exports._counter(options);
    console.log("counter",options.counter)
    console.log(options)
  
    // pass to hotp
    return this.hotp(options);
  };

  exports._counter = function _counter (options) {
    var step = options.step || 30;
    var time = options.time != null ? (options.time * 1000) : Date.now();
  
    // also accepts 'initial_time', but deprecated
    var epoch = (options.epoch != null ? (options.epoch * 1000) : (options.initial_time * 1000)) || 0;
    if (options.initial_time != null) console.warn('Speakeasy - Deprecation Notice - Specifying the epoch using `initial_time` is no longer supported. Use `epoch` instead.');
  
    return Math.floor((time - epoch) / step / 1000);
  };

  exports.digest = function digest (options) {
    var i;
  
    // unpack options
    var secret = options.secret;
    var counter = options.counter;
    var encoding = options.encoding || 'ascii';
    var algorithm = (options.algorithm || 'sha1').toLowerCase();

  
    // Backwards compatibility - deprecated
    if (options.key != null) {
      console.warn('Speakeasy - Deprecation Notice - Specifying the secret using `key` is no longer supported. Use `secret` instead.');
      secret = options.key;
    }
  
    // convert secret to buffer
    if (!Buffer.isBuffer(secret)) {
      if (encoding === 'base32') { secret = base32.decode(secret); }
      secret = new Buffer(secret, encoding);
    }
  
    var secret_buffer_size;
    if (algorithm === 'sha1') {
      secret_buffer_size = 20; // 20 bytes
    } else if (algorithm === 'sha256') {
      secret_buffer_size = 32; // 32 bytes
    } else if (algorithm === 'sha512') {
      secret_buffer_size = 64; // 64 bytes
    } else {
      console.warn('Speakeasy - The algorithm provided (`' + algorithm + '`) is not officially supported, results may be different than expected.');
    }
  
    // The secret for sha1, sha256 and sha512 needs to be a fixed number of bytes for the one-time-password to be calculated correctly
    // Pad the buffer to the correct size be repeating the secret to the desired length
    if (secret_buffer_size && secret.length !== secret_buffer_size) {
      secret = new Buffer(Array(Math.ceil(secret_buffer_size / secret.length) + 1).join(secret.toString('hex')), 'hex').slice(0, secret_buffer_size);
    }
  
    // create an buffer from the counter
    var buf = new Buffer(8);
    var tmp = counter;
    for (i = 0; i < 8; i++) {
      // mask 0xff over number to get last 8
      buf[7 - i] = tmp & 0xff;
  
      // shift 8 and get ready to loop over the next batch of 8
      tmp = tmp >> 8;
    }
  
    // init hmac with the key
    var hmac = crypto.createHmac(algorithm, secret);
  
    // update hmac with the counter
    hmac.update(buf);
  
    // return the digest
    return hmac.digest();
  };
  exports.hotp.verifyDelta = function hotpVerifyDelta (options) {
    var i;
    // shadow options
    options = Object.create(options);
  
    // verify secret and token exist
    var secret = options.secret;
    var token = options.token;
    console.log("HOTP VERIFY SECRET",secret)
    if (secret === null || typeof secret === 'undefined') throw new Error('Speakeasy - hotp.verifyDelta - Missing secret');
    if (token === null || typeof token === 'undefined') throw new Error('Speakeasy - hotp.verifyDelta - Missing token');
  
    // unpack options
    var token = String(options.token);
    var digits = parseInt(options.digits, 10) || 6;
    var window = parseInt(options.window, 10) || 0;
    console.log(window,"____WINDDDDDDDDDDDDDOW______")
    var counter = parseInt(options.counter, 10) || 0;
  
    // fail if token is not of correct length
    if (token.length !== digits) {
      return;
    }
  
    // parse token to integer
    token = parseInt(token, 10);
  
    // fail if token is NA
    if (isNaN(token)) {
      return;
    }
  
    // loop from C to C + W inclusive
    console.log("___counter",counter)
    console.log("____________counter_________")
    for (i = counter; i <= counter + window; ++i) {

      options.counter = i;
      console.log(counter)
      // domain-specific constant-time comparison for integer codes
      const otp = exports.hotp(options)
      console.log(otp)
      if (parseInt(otp) === token) {
        // found a matching code, return delta
        return {delta: i - counter};
      }
    }
  
    // no codes have matched
  };

  exports.totp.verifyDelta = function totpVerifyDelta (options) {
    // shadow options
    options = Object.create(options);
    // verify secret and token exist
    var secret = options.secret;
    var token = options.token;

    if (secret === null || typeof secret === 'undefined') throw new Error('Speakeasy - totp.verifyDelta - Missing secret');
    if (token === null || typeof token === 'undefined') throw new Error('Speakeasy - totp.verifyDelta - Missing token');
  
    // unpack options
    var window = parseInt(options.window, 10) || 0;
    console.log(window,"window")
  
    // calculate default counter value
    if (options.counter == null) options.counter = exports._counter(options);
  
    // adjust for two-sided window
    options.counter -= window;
    options.window += window;
  
    // pass to hotp.verifyDelta
    var delta = exports.hotp.verifyDelta(options);
    console.log("__delta___",delta)
    // adjust for two-sided window
    if (delta) {
      delta.delta -= window;
    }
    console.log(delta)
    return delta;
  };
  
  exports.verifyOTP = function totpVerify (options) {
    return exports.totp.verifyDelta(options) != null;
  };
  
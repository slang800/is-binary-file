var fs = require('fs');
var path = require("path");
var maxBytes = 512;

module.exports = function(bytes, size) {
  var file = bytes;
  // Read the file with no encoding for raw buffer access.
  if (size === undefined) {
    try {
      if(!fs.statSync(file).isFile()) return false;
    } catch (err) {
      // otherwise continue on
    }
    var descriptor = fs.openSync(file, 'r');
    try {
      bytes = new Buffer(maxBytes);
      size = fs.readSync(descriptor, bytes, 0, bytes.length, 0);
    } finally {
      fs.closeSync(descriptor);
    }
  }
  // async version has a function instead of a `size`
  else if (typeof size === "function") {
    callback = size;
    fs.stat(file, function(err, stat) {
      if (err || !stat.isFile()) return callback(null, false);

      fs.open(file, 'r', function(err, descriptor){
          if (err) return callback(err);
          var bytes = new Buffer(maxBytes);
          // Read the file with no encoding for raw buffer access.
          fs.read(descriptor, bytes, 0, bytes.length, 0, function(err, size, bytes){
            fs.close(descriptor, function(err2){
                if (err || err2)
                    return callback(err || err2);
                return callback(null, isBinaryCheck(bytes, size));
            });
          });
      });
    });
  }

  return isBinaryCheck(bytes, size);
};

function isBinaryCheck(bytes, size) {
  if (size === 0)
    return false;

  var suspiciousBytes = 0;
  var totalBytes = Math.min(size, maxBytes);

  if (size >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF) {
    // UTF-8 BOM. This isn't binary.
    return false;
  }

  for (var i = 0; i < totalBytes; i++) {
    if (bytes[i] === 0) { // NULL byte--it's binary!
      return true;
    }
    else if ((bytes[i] < 7 || bytes[i] > 14) && (bytes[i] < 32 || bytes[i] > 127)) {
      // UTF-8 detection
      if (bytes[i] > 193 && bytes[i] < 224 && i + 1 < totalBytes) {
          i++;
          if (bytes[i] > 127 && bytes[i] < 192) {
              continue;
          }
      }
      else if (bytes[i] > 223 && bytes[i] < 240 && i + 2 < totalBytes) {
          i++;
          if (bytes[i] > 127 && bytes[i] < 192 && bytes[i + 1] > 127 && bytes[i + 1] < 192) {
              i++;
              continue;
          }
      }
      suspiciousBytes++;
      // Read at least 32 bytes before making a decision
      if (i > 32 && (suspiciousBytes * 100) / totalBytes > 10) {
          return true;
      }
    }
  }

  if ((suspiciousBytes * 100) / totalBytes > 10) {
    return true;
  }

  return false;
}

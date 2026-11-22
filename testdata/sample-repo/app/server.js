const lodash = require('lodash');

function processArray(arr) {
  return lodash.uniq(arr).sort();
}

module.exports = { processArray };

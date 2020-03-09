const mongoose = require('mongoose')
const {mongodpath_cvedb} = require('./setting');
const url_cvedb = mongodpath_cvedb;
const mongoose_cvedb = mongoose.createConnection(url_cvedb);
module.exports = exports = mongoose_cvedb;
const mongoose = require('mongoose');
const {mongodpath_firmalyzer} = require('./setting');
const url_firmalyzer = mongodpath_firmalyzer;
const mongoose_firmalyzer = mongoose.createConnection(url_firmalyzer);
module.exports = exports = mongoose_firmalyzer;


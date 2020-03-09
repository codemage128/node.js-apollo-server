exports._port = 4000;
exports.tablename = "firmware";
exports.url = "http://localhost:" + this._port;
exports.sqlitedbPath = './meta.db';
exports.mongodpath_firmalyzer = 'mongodb://localhost:27017/firmalyzer';
exports.mongodpath_cvedb = 'mongodb://localhost:27017/cvedb';

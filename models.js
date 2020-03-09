const mongoose_cvedb = require("./cve_confing");
const mongoose_firmalyzer = require('./firmalyzer_config');
const mongoose = require('mongoose');
const {Schema} = mongoose;
const cvesSchema = new Schema({
   cveid: String,
   cvss: String,
   cwe: String,
   references: String,
   summary: String
});
var issuesSchema = new Schema({
  name: String,
  warning: [String]
})
const firmwaresSchema = new Schema({
  checksum: String,
  firmware_name: String,
  firmware_hash: String,
  Version: String,
  ComponentName: String,
  vulnerabilities: [String],
  issues: [issuesSchema]
})

const Vulnerability = mongoose_cvedb.model('cves', cvesSchema);
const AnalyzedFirmware = mongoose_firmalyzer.model('firmwares', firmwaresSchema);

module.exports = {
  Vulnerability,
  AnalyzedFirmware
};
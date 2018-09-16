const fileScan = require('./file-scan')
const urlScan = require('./url-scan')
const urlReport = require('./url-report')
const ipAddressReport = require('./ipAddress-report')
const domainReport = require('./domain-report')

module.exports = {
  fileScan,
  urlScan,
  urlReport,
  ipAddressReport,
  domainReport
}

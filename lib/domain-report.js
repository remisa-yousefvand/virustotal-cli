const fs = require('fs')
const VirusTotalApi = require('virustotal-api')

function domainReport (apiKey, domain, out = null) {
  const virusTotal = new VirusTotalApi(apiKey)
  virusTotal.domainReport(domain)
    .then((report) => {
      if (report.response_code === 1) {
        const content = JSON.stringify(report)
        if (out) {
          fs.writeFile(out, content, (err) => {
            if (err) {
              console.log(`Cannot save report at: ${out}
              Error: ${err}`)
            } else {
              console.log(`Report successfully saved at: ${out}`)
            }
          })
        } else {
          console.log(content)
        }
      } else {
        console.log('Domain report is not available.')
      }
    })
    .catch((err) => {
      console.log(`Domain report failed! Error: ${err}`)
    })
}

module.exports = domainReport

const fs = require('fs')
const VirusTotalApi = require('virustotal-api')

function ipAddressReport (apiKey, ip, out = null) {
  const virusTotal = new VirusTotalApi(apiKey)
  virusTotal.ipAddressReport(ip)
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
        console.log('IP address report is not available.')
      }
    })
    .catch((err) => {
      console.log(`IP adress report failed! Error: ${err}`)
    })
}

module.exports = ipAddressReport

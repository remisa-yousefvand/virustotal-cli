const fs = require('fs')
const VirusTotalApi = require('virustotal-api')

function urlScan (apiKey, url, out = null) {
  const virusTotal = new VirusTotalApi(apiKey)
  virusTotal.urlScan(url)
    .then((result) => {
      if (result.response_code === 1) {
        virusTotal.urlReport(result.scan_id)
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
              console.log(`Scan queued. Come back later.
                resource: ${report.resource}`)
            }
          })
          .catch((err) => {
            console.log(`Cannot retreive url report. Error: ${err}`)
          })
      } else {
        console.log(`Scan queued successfully. Come back later for retreiving result.
        resource: ${result.resource}`)
      }
    })
    .catch((err) => {
      console.log(`Url scan failed! Error: ${err}`)
    })
}

module.exports = urlScan

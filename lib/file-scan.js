const fs = require('fs')
const path = require('path')
const VirusTotalApi = require('virustotal-api')

const maxFileUploadSize = 32 * 1024 * 1024 // 32 MB

function fileScan (apiKey, filePath, out = null) {
  const virusTotal = new VirusTotalApi(apiKey)
  fs.stat(filePath, (err, stats) => {
    if (err) {
      console.log(`Error: ${err}
        Cannot read the file at ${filePath}`)
      process.exit(1)
    } else {
      const fileName = path.basename(filePath)
      const fileSize = stats['size']
      if (fileSize > maxFileUploadSize) {
        // TODO: Handle > 32mb files
        throw Error('Not implemented!')
      } else {
        fs.readFile(filePath, (err, data) => {
          if (err) {
            console.log(`Error: ${err}
              Cannot read the file at ${filePath}`)
            process.exit(1)
          } else {
            virusTotal.fileScan(data, fileName)
              .then((result) => {
                if (result.response_code === 1) {
                  virusTotal.fileReport(result.resource)
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
                      console.log(`Cannot retreive file report. Error: ${err}`)
                    })
                } else {
                  console.log(`Scan queued successfully. Come back later for retreiving result.
                    resource: ${result.resource}`)
                }
              })
              .catch((err) => {
                console.log(`File scan failed! Error: ${err}`)
              })
          }
        })
      }
    }
  })
}

module.exports = fileScan

const path = require('path')
const app = require('commander')

const lib = require('./lib')

app
  .version('1.0.0', '-v, --version')
  .option('-k, --key <key>', 'Virustotal api key')
  .option('-f, --file [file]', 'file')
  .option('-u, --url [url]', 'url')
  .option('-i, --ip <ip>', 'IP address')
  .option('-d, --domain <domain>', 'domain')
  .option('-s, --scan', 'scan')
  .option('-r, --report <resource>', 'retreive report')
  .option('--rescan <resource>', 'Re-scan a file')
  .option('--download <hash>', 'Download a file')
  .option('-b, --behaviour <hash>', 'Retrieve behaviour report')
  .option('-n, --network-traffic <hash>', 'Retrieve network traffic report')
  .option('--feed <package>', 'Retrieve live feed of all files/urls submitted to VirusTotal')
  .option('--clusters <date>', 'Retrieve file clusters')
  .option('-q, --search <query> [offset]', 'Search for files')
  .option('-c, --comment <resource> [before]', 'Get/Put comments for a file/url')
  .option('-p, --put', 'Put comments for a file/url')
  .option('-g, --get', 'Get comments for a file/url')
  .option('-o, --out [file]', 'file to save results as json')
  .parse(process.argv)

let outputFile = app.out ? path.join(process.cwd(), app.out) : null

if (app.scan) {
  if (app.file) {
    lib.fileScan(app.key, app.file, outputFile)
  } else if (app.url) {
    lib.urlScan(app.key, app.url, outputFile)
  } else {
    console.log('Error: You can only scan file and url!')
  }
} else if (app.report) {
  if (app.ip) {
    lib.ipAddressReport(app.key, app.ip, outputFile)
  } else if (app.domain) {
    lib.domainReport(app.key, app.domain, outputFile)
  } else if (app.url) {
    lib.urlReport(app.key, app.url, outputFile)
  }
} else if (app.rescan) {
  // TODO
} else if (app.download) {
  // TODO
} else if (app.behaviour) {
  // TODO
} else if (app.networkTraffic) {
  // TODO
} else if (app.feed) {
  // TODO
} else if (app.clusters) {
  // TODO
} else if (app.search) {
  // TODO
} else if (app.comment) {
  // TODO
} else if (app.hash) {
  // TODO
}

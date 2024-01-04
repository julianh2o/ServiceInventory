import 'express-async-errors';
import express from 'express';
import nmap from 'node-nmap';
import fs from 'fs/promises';
import _ from 'lodash';
import axios from 'axios';
import cheerio from 'cheerio';
import p from 'p-iteration';
import bodyParser from 'body-parser';
import { spawn } from 'child_process';
import { createWriteStream } from 'fs';
import path from 'path';
import * as uuid from 'uuid';
import { fileTypeFromBuffer } from 'file-type';
import crypto from "crypto";
import multer from "multer";
import { parseFavicon } from 'parse-favicon'

const PORT = 4004;
const HOST = "localhost";

async function fetchFavicons(url) {
  return new Promise((resolve, reject) => {
    const results  = [];
    parseFavicon(
      url,
      async (url) => fetch(url).then(res => res.text()),
      async (rel) => fetch(`${url}${rel}`).then(res => res.arrayBuffer())
    ).subscribe({
      next(icon) { results.push(icon) },
      error(err) { reject(err) },
      complete() { resolve(results) },
    })
  })
}

async function downloadLargestFavicon(url) {
  console.log(`Downloading Favicon for ${url}`)
  const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
  try {
    // Fetch the HTML content of the website
    if (url.includes("6789")) {
      const favicons = await fetchFavicons(url);
      console.log(favicons);
    }
    const response = await axios.get(url);
    const html = response.data;

    // Load the HTML content into Cheerio
    const $ = cheerio.load(html);

    // Find all favicon links in the HTML
    const faviconLinks = $('link[rel="icon"], link[rel="shortcut icon"]');

    let largestFaviconUrl = '';
    let largestFaviconSize = 0;

    // Iteratethrough the favicon links to find the largest one

    faviconLinks.each((_index, element) => {
      const faviconUrl = $(element).attr('href');
      const faviconSizeStr = $(element).attr('sizes');
      const faviconSize = faviconSizeStr ? parseInt(faviconSizeStr) : 0;

      if (!largestFaviconSize || faviconSize > largestFaviconSize) {
        largestFaviconSize = faviconSize;
        largestFaviconUrl = faviconUrl || '';
      }
    });

    if (!largestFaviconUrl) throw new Error('No favicon found on the website ' + url);

    if (largestFaviconUrl.startsWith(".")) largestFaviconUrl = largestFaviconUrl.substring(1);
    if (!largestFaviconUrl.startsWith("/")) largestFaviconUrl = `/${largestFaviconUrl}`;
    console.log("Downloading favicon from: "+`${url}${largestFaviconUrl}`)
    const faviconResponse = await axios.get(`${url}${largestFaviconUrl}`, {
      responseType: 'arraybuffer',
    });
    const buf = faviconResponse.data;

    let {ext} = await fileTypeFromBuffer(buf);
    if (ext === "xml") ext = "svg";
    var hash = crypto.createHash('sha1');
    hash.setEncoding("hex");
    hash.write(buf);
    hash.end();
    const name = hash.read();
    const filename = `./ico/${name}.${ext}`;

    await fs.writeFile(filename,buf);
    return filename;
  } catch (cause) {
    throw new Error('Error while downloading favicon: '+cause.message, {cause});
  }
}

function runNmap(host, fast){
  return new Promise((resolve, reject) => {
    const args = [];

    if (fast) {
      args.push('-sS', '-F');
    } else {
      args.push('-sS', '-T5', '-p-');
      // args.push('-sT', '-p 1-10000');
    }

    args.push(host);

    const nmapProcess = spawn('nmap', args);
    let nmapOutput = '';

    nmapProcess.stdout.on('data', (data) => {
      nmapOutput += data.toString();
    });

    nmapProcess.stderr.on('data', (data) => {
      const errorMessage = data.toString();
      reject(new Error(`Nmap stderr: ${errorMessage}`));
    });

    nmapProcess.on('close', (code) => {
      if (code === 0) {
        resolve(nmapOutput);
      } else {
        reject(new Error(`Nmap process exited with code ${code}`));
      }
    });
  });
}

function parseNmapOutput(output) {
  const hosts = [];
  const lines = output.split('\n');
  let currentHost = null;

  for (const line of lines) {
    if (line.startsWith('Nmap scan report for ')) {
      // Start of a new host entry
      if (currentHost !== null) {
        hosts.push(currentHost);
      }
      const ip = line.split('Nmap scan report for ')[1].trim();
      currentHost = {
        ip,
        openPorts: [],
      };
    } else if (line.includes(' open ')) {
      // Line contains an open port
      const parts = line.split(/\s+/);
      if (currentHost !== null) {
        const portMatch = parts[0].match(/(\d+)\/(\w+)/);
        if (portMatch) {
          const port = parseInt(portMatch[1], 10);
          const protocol = portMatch[2];
          currentHost.openPorts.push({
            port,
            protocol,
            state: parts[1],
            service: parts.slice(2).join(' '),
          });
        }
      }
    }
  }

  // Add the last host to the array
  if (currentHost !== null) {
    hosts.push(currentHost);
  }

  return hosts;
}

async function getTitleFromUrl(url) {
  try {
    console.time(`Fetching Page Title: ${url}`);
    const response = await axios.get(url, { timeout: 1000 });

    if (response.status !== 200)
      throw new Error('Request returned with error: ' + response.status);

    const html = response.data;
    const $ = cheerio.load(html);
    const title = $('title') && $('title').text();
    const ogTitleElement = $('meta[property="og:title"]').attr('content');

    return title || ogTitleElement;
  } catch (error) {
    console.error(`Error fetching title for ${url}: ${error.message}`);
    return null;
  } finally {
    console.timeEnd(`Fetching Page Title: ${url}`);
  }
}

const HOST_CACHE = './cache.json';
const CONFIG_PATH = './config.json';

const scan = async (host, fast) => {
  console.log(`Starting scan: ${host} ${fast ? '(fast)' : ''}`);
  console.time(`Scan ${host} ${fast ? '(fast)' : ''}`);
  const raw = await runNmap(host, fast);
  const parsed = parseNmapOutput(raw);
  console.timeEnd(`Scan ${host} ${fast ? '(fast)' : ''}`);
  return parsed;
};

const scanNmap = async (host, fast) => {
  return new Promise((resolve, reject) => {
    console.log(`Starting scan: ${host} ${fast ? '(fast)' : ''}`);
    console.time(`Scan ${host} ${fast ? '(fast)' : ''}`);
    const scan = new nmap.NmapScan(host, fast ? '-sT -F' : '-sT -p-');
    scan.on('complete', function (data) {
      resolve(data);
      console.timeEnd(`Scan ${host} ${fast ? '(fast)' : ''}`);
    });
    scan.on('error', function (err) {
      reject(err);
      console.timeEnd(`Scan ${host} ${fast ? '(fast)' : ''}`);
    });
    scan.startScan();
  });
};

const loadJson = async (p, defaultValue) => {
  try {
    const raw = await fs.readFile(p, 'utf-8');
    return JSON.parse(raw);
  } catch (err) {
    return defaultValue;
  }
};

const saveJson = async (o, p) => {
  await fs.writeFile(p, JSON.stringify(o, undefined, 2), 'utf-8');
};

const getConfig = (ip, port) => {
  let hostMatch = _.find(config.hosts, { ip });
  if (!hostMatch) {
    // Create the host entry
    hostMatch = { ..._.cloneDeep(defaultHost), ip };
    config.hosts.push(hostMatch);
  }
  if (!port) {
    return hostMatch;
  }

  let serviceMatch = _.find(hostMatch.openPorts, { port });
  if (serviceMatch) return serviceMatch;

  // Create the port entry
  serviceMatch = { ..._.cloneDeep(defaultService), port };
  hostMatch.openPorts.push(serviceMatch);
  return serviceMatch;
};

let hosts = [];
const tick = async () => {
  console.time('Port scan');
  const newHosts = await scan('192.168.0.200', true);
  const processedHosts = await p.mapSeries(newHosts, async (hostRaw) => {
    const host = _.cloneDeep(hostRaw);
    host.openPorts = host.openPorts ?? [];
    const hostConfig = getConfig(host.ip);
    host.favorite =
      hostConfig.favorite ?? !!_.find(host.openPorts, { service: 'ssh' });
    host.name = host.hostname ?? '';

    if (host.favorite) Object.assign(host, _.first(await scan(host.ip, false)));
    host.openPorts = await p.mapSeries(host.openPorts, async (svc) => {
      // console.log(`${host.ip}:${svc.port} ${svc.service}`);
      svc = _.cloneDeep(svc);
      const serviceUrl = `http://${host.ip}:${svc.port}`;
      const titleFromUrl =
        svc.protocol === 'tcp' &&
        svc.service !== 'jetdirect' &&
        (await getTitleFromUrl(serviceUrl));
      let icon = null;
      try {
        icon =
          svc.protocol === 'tcp' && (await downloadLargestFavicon(serviceUrl));
      } catch (err) {
        console.error(`Failed to download icon: ${serviceUrl} ${err.message}`);
      }
      svc.name = titleFromUrl || svc.service || '';
      svc.icon = icon && icon.substring(1);
      return svc;
    });
    return host;
  });
  await saveJson(processedHosts, HOST_CACHE);
  hosts = processedHosts;
  console.timeEnd('Port scan');
};

const processHosts = async (hosts, config) => {
  let processed = _.map(hosts, (host) => {
    host = {
      ..._.cloneDeep(host),
      ..._.omit(getConfig(host.ip), 'ip', 'openPorts'),
    };
    host.openPorts = _.reject(host.openPorts, (svc) =>
      config.ignoreList.includes(svc.service)
    );
    // console.log('host', host, host.openPorts, getConfig(host.ip, 80));
    host.openPorts = _.map(host.openPorts, (svc) => ({
      ..._.cloneDeep(svc),
      ...getConfig(host.ip, svc.port),
    }));
    return host;
  });

  processed = _.reject(processed, (host) => host.openPorts.length === 0);

  return processed;
};

const defaultHost = {
  openPorts: [],
};

const defaultService = {};

let config = {};
const defaultConfig = {
  ignoreList: ['upnp', 'https-alt', 'ajp13'],
  hosts: [],
};

const SCAN_FREQUENCY_MINUTES = 30;

const app = express();
app.set('view engine', 'pug');
app.use(express.static('public'));
app.use("/ico",express.static('ico'));

app.get('/', async (_req, res) => {
  res.render('index', {
    title: 'Hey',
    message: 'Hello there!',
    hosts: await processHosts(hosts, config),
  });
});

const upload = multer({ storage: multer.memoryStorage() });
app.post('/hosts/:ip/services/:port/icon', upload.single('favicon'), async (req, res) => {
  try {
    if (!req.file) {
      throw new Error('No file uploaded');
    }

    const buffer = req.file.buffer;
    const { ext } = await fileTypeFromBuffer(buffer);

    // Generating a SHA-1 hash of the file's content
    var hash = crypto.createHash('sha1');
    hash.update(buffer);
    const name = hash.digest('hex');
    const filename = `./ico/${name}.${ext}`;

    const {ip,port} = req.params;
    const serviceConfig = getConfig(ip,parseInt(port));
    serviceConfig.icon = filename.substring(1);
    await saveJson(config, CONFIG_PATH);
    console.log(`Uploaded icon for ${ip}:${port}`);

    // Saving the file
    await fs.writeFile(filename, buffer);

    res.send({ message: 'File uploaded successfully', filename });
  } catch (error) {
    console.error(error);
    res.status(500).send({ message: 'Error processing file', error: error.message });
  }
});

app.post(
  ['/hosts/:ip/services/:port/:key', '/hosts/:ip/:key'],
  bodyParser.text({ type: '*/*' }),
  async (req, res) => {
    const { ip, port, key } = req.params;
    let value = req.body;
    if (['true', 'false'].includes(value)) value = value === 'true';
    const service = getConfig(ip, parseInt(port));
    service[key] = value;
    await saveJson(config, CONFIG_PATH);
    res.sendStatus(200);
  }
);

app.use('/_healthcheck', (_req, res) => {
  res.status(200).json({ uptime: process.uptime() });
});

async function main() {
  await app.listen({ port: PORT, host: HOST }, async () => {
    hosts = await loadJson(HOST_CACHE, []);
    config = await loadJson(CONFIG_PATH, defaultConfig);
    // const res = await downloadLargestFavicon("http://192.168.0.200:5076/");
    // console.log(res);
    await tick();
    setTimeout(tick, SCAN_FREQUENCY_MINUTES * 60 * 60 * 1000);
  });
  console.log(`Running at http://${HOST}:${PORT}`);
}

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('Something broke!');
});

process.on('unhandledRejection', (err) => {
  if (err) console.error(err);
});

main();

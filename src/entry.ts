import 'express-async-errors';
import logger from './core/logger.js';
import secrets from './core/secrets.ts';
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

async function downloadLargestFavicon(url: string): Promise<string> {
  try {
    // Fetch the HTML content of the website
    const response = await axios.get(url);
    const html = response.data;

    // Load the HTML content into Cheerio
    const $ = cheerio.load(html);

    // Find all favicon links in the HTML
    const faviconLinks = $('link[rel="icon"], link[rel="shortcut icon"]');

    let largestFaviconUrl = '';
    let largestFaviconSize = 0;

    // Iterate through the favicon links to find the largest one
    faviconLinks.each((_index, element) => {
      const faviconUrl = $(element).attr('href');
      const faviconSizeStr = $(element).attr('sizes');
      const faviconSize = faviconSizeStr ? parseInt(faviconSizeStr) : 0;

      if (faviconSize > largestFaviconSize) {
        largestFaviconSize = faviconSize;
        largestFaviconUrl = faviconUrl || '';
      }
    });

    if (largestFaviconUrl) {
      // Download the largest favicon
      console.log('fetching', `${url}${largestFaviconUrl}`);
      const faviconResponse = await axios.get(`${url}${largestFaviconUrl}`, {
        responseType: 'stream',
      });
      const faviconStream = faviconResponse.data;

      // Generate a unique filename with an appropriate extension
      // const buf = Buffer.from(faviconStream);
      console.log(await fileTypeFromBuffer(Buffer.from('')));
      const extension = path.extname(largestFaviconUrl) || '.ico';
      const filename = `./ico/${uuid.v4()}${extension}`;

      // Create a write stream to save the favicon locally
      const writeStream = createWriteStream(filename);

      faviconStream.pipe(writeStream);

      return new Promise<string>((resolve, reject) => {
        writeStream.on('finish', () => {
          console.log(`Downloaded largest favicon to ${filename}`);
          resolve(filename);
        });

        writeStream.on('error', (error) => {
          console.error('Error while saving favicon:', error);
          reject(error);
        });
      });
    } else {
      throw new Error('No favicon found on the website ' + url);
    }
  } catch (cause) {
    throw new Error('Error while downloading favicon:' + cause.message);
  }
}

function runNmap(host: string, fast: boolean): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const args: string[] = [];

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

function parseNmapOutput(output: string): HostInfo[] {
  const hosts: HostInfo[] = [];
  const lines = output.split('\n');
  let currentHost: HostInfo | null = null;

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

interface HostInfo {
  ip: string;
  openPorts: PortInfo[];
}

interface PortInfo {
  port: number;
  protocol: string;
  state: string;
  service: string;
}

async function getTitleFromUrl(url: string): Promise<string> {
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
    logger.error(`Error fetching title for ${url}: ${error.message}`);
    return null;
  } finally {
    console.timeEnd(`Fetching Page Title: ${url}`);
  }
}

const HOST_CACHE = './cache.json';
const CONFIG_PATH = './config.json';

const scan = async (host: string, fast: boolean) => {
  console.log(`Starting scan: ${host} ${fast ? '(fast)' : ''}`);
  console.time(`Scan ${host} ${fast ? '(fast)' : ''}`);
  const raw = await runNmap(host, fast);
  const parsed = parseNmapOutput(raw);
  console.timeEnd(`Scan ${host} ${fast ? '(fast)' : ''}`);
  return parsed;
};

const scanNmap = async (host: string, fast: boolean) => {
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

const getConfig = (ip: string, port?: number) => {
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
  const newHosts = (hosts = (await scan('192.168.0.200', true)) as any[]);
  const processedHosts = await p.mapSeries(newHosts, async (hostRaw) => {
    const host = _.cloneDeep(hostRaw);
    host.openPorts = host.openPorts ?? [];
    const hostConfig = getConfig(host.ip);
    host.favorite =
      hostConfig.favorite ?? !!_.find(host.openPorts, { service: 'ssh' });
    host.name = host.hostname ?? '';

    if (host.favorite) Object.assign(host, _.first(await scan(host.ip, false)));
    host.openPorts = await p.mapSeries(host.openPorts, async (svc: any) => {
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
        logger.error(`Failed to download icon: ${serviceUrl} ${err.message}`);
      }
      svc.name = titleFromUrl || svc.service || '';
      svc.ico = icon && icon.substring(1);
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

let config: any = {};
const defaultConfig = {
  ignoreList: ['upnp', 'https-alt', 'ajp13'],
  hosts: [],
};

tick();
const SCAN_FREQUENCY_MINUTES = 30;

const app = express();
app.set('view engine', 'pug');
app.use(express.static('public'));
app.use(express.static('ico'));

app.get('/', async (_req, res) => {
  res.render('index', {
    title: 'Hey',
    message: 'Hello there!',
    hosts: await processHosts(hosts, config),
  });
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
  await app.listen({ port: secrets.PORT, host: secrets.HOST }, async () => {
    hosts = await loadJson(HOST_CACHE, []);
    config = await loadJson(CONFIG_PATH, defaultConfig);
    setTimeout(tick, SCAN_FREQUENCY_MINUTES * 60 * 60 * 1000);
  });
  logger.info(`Running at http://${secrets.HOST}:${secrets.PORT}`);
}

app.use((err, req, res, next) => {
  console.error(err);
  logger.error(err);
  res.status(500).send('Something broke!');
});

process.on('unhandledRejection', (err) => {
  if (err) logger.error(err);
});

main();

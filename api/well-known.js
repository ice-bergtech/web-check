import { URL } from 'url';
import followRedirects from 'follow-redirects';
import middleware from './_common/middleware.js';

const { https } = followRedirects;

// https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml#well-known-uris-1
const WELL_KNOWN_URIS = [
  'acme-challenge',
  'amphtml',
  'api-catalog',
  'appspecific',
  'ashrae',
  'assetlinks.json',
  'broadband-labels',
  'brski',
  'caldav',
  'carddav',
  'change-password',
  'cmp',
  'coap',
  'core',
  'csaf',
  'csaf-aggregator',
  'csvm',
  'did.json',
  'did-configuration.json',
  'dnt',
  'dnt-policy.txt',
  'dots',
  'ecips',
  'edhoc',
  'enterprise-network-security',
  'enterprise-transport-security',
  'est',
  'genid',
  'gnap-as-rs',
  'gpc.json',
  'gs1resolver',
  'hoba',
  'host-meta',
  'host-meta.json',
  'hosting-provider',
  'http-opportunistic',
  'idp-proxy',
  'jmap',
  'keybase.txt',
  'knx',
  'looking-glass',
  'masque',
  'matrix',
  'mercure',
  'mta-sts.txt',
  'mud',
  'nfv-oauth-server-configuration',
  'ni',
  'nodeinfo',
  'nostr.json',
  'oauth-authorization-server',
  'oauth-protected-resource',
  'ohttp-gateway',
  'openid-federation',
  'open-resource-discovery',
  'openid-configuration',
  'openorg',
  'oslc',
  'pki-validation',
  'posh',
  'privacy-sandbox-attestations.json',
  'probing.txt',
  'pvd',
  'rd',
  'related-website-set.json',
  'reload-config',
  'repute-template',
  'resourcesync',
  'sbom',
  'security.txt',
  'ssf-configuration',
  'sshfp',
  'stun-key',
  'terraform.json',
  'thread',
  'time',
  'timezone',
  'tdmrep.json',
  'tor-relay',
  'tpcd',
  'traffic-advice',
  'trust.txt',
  'uma2-configuration',
  'void',
  'webfinger',
  'webweaver.json',
  'wot'
]

const SECURITY_TXT_PATHS = [
  '/security.txt',
  '/.well-known/security.txt',
];

const parseSecuritytxt = (result) => {
  let output = {};
  let counts = {};
  const lines = result.split('\n');
  const regex = /^([^:]+):\s*(.+)$/;
  
  for (const line of lines) {
    if (!line.startsWith("#") && !line.startsWith("-----") && line.trim() !== '') {
      const match = line.match(regex);
      if (match && match.length > 2) {
        let key = match[1].trim();
        const value = match[2].trim();
        if (output.hasOwnProperty(key)) {
          counts[key] = counts[key] ? counts[key] + 1 : 1;
          key += counts[key];
        }
        output[key] = value;
      }
    }
  }
  
  return output;
};

const fetchSecurityTxt = async (url) => {
  for (let path of SECURITY_TXT_PATHS) {
    try {
      const result = await fetchPromiseSecurityTxt(url, path);
      if (result && result.includes('<html')) return { isPresent: false };
      if (result) {
        return {
          title: `Security.txt @ ${path}`,
          isPresent: true,
          foundIn: path,
          content: result,
          isPgpSigned: result.includes('-----BEGIN PGP SIGNED MESSAGE-----'),
          fields: parseSecuritytxt(result),
        };
      }
    } catch (error) {
      throw new Error(error.message);
    }
  }
};

const fetchAcmeChallenge = async (url) => {
  const ACME_CHALLENGE_PATHS = [
    '/.well-known/acme-challenge/',
    '/.well-known/acme-challenge/LDummyToken0000xbmR7SCTNo3tiAXDfowyjxAjEuX0',
  ];

  for (let path of ACME_CHALLENGE_PATHS) {
    try {
      const result = await fetchPromiseSecurityTxt(url, path);
      if (result && result.includes('<html')) return { isPresent: false };
      if (result) {
        return {
          title: `ACME Challenge @ ${path}`,
          isPresent: true,
          foundIn: path,
          content: result,
          about: "Automatic Certificate Management Environment endpoint. RFC8555 Section 8.3",
          link: "https://www.iana.org/go/rfc8555"
        };
      }
    } catch (error) {
      throw new Error(error.message);
    }
  }
};

const fetchAmphtml = async (url) => {
  const ENDPOINT_PATHS = [
    '/.well-known/amphtml/apikey.pub',
  ];

  for (let path of ENDPOINT_PATHS) {
    try {
      const result = await fetchPromiseSecurityTxt(url, path);
      if (result && result.includes('<html')) return { isPresent: false };
      if (result) {
        return {
          title: `Google AMP HTML API Key @ ${path}`,
          isPresent: true,
          foundIn: path,
          content: result,
          about: "Google Amp mgmt public key endpoint.",
          link: "https://developers.google.com/amp/cache/update-cache"
        };
      }
    } catch (error) {
      throw new Error(error.message);
    }
  }
};

const fetchApiCatalog = async (url) => {
  const ENDPOINT_PATHS = [
    '/.well-known/api-catalog',
  ];

  for (let path of ENDPOINT_PATHS) {
    try {
      const result = await fetchPromiseSecurityTxt(url, path);
      if (result && result.includes('<html')) return { isPresent: false };
      if (result) {
        return {
          title: `API Catalog @ ${path}`,
          isPresent: true,
          foundIn: path,
          content: result,
          about: "JSON data detailing the APIs available on the server.",
          link: "https://www.iana.org/go/draft-ietf-httpapi-api-catalog-08"
        };
      }
    } catch (error) {
      throw new Error(error.message);
    }
  }
};

async function fetchPromiseSecurityTxt(baseURL, path) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseURL);
    https.get(url.toString(), (res) => {
      if (res.statusCode === 200) {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          resolve(data);
        });
      } else {
        resolve(null);
      }
    }).on('error', (err) => {
      reject(err);
    });
  });
}

const wellKnownHandler = async (urlParam) => {

  let url;
  try {
    url = new URL(urlParam.includes('://') ? urlParam : 'https://' + urlParam);
  } catch (error) {
    throw new Error('Invalid URL format');
  }
  url.pathname = '';
  url_string = url.toString(); 
  return {
    acme_challenge: await fetchAcmeChallenge(url_string),
    amphtml: await fetchAmphtml(url_string),
    api_catalog: await fetchApiCatalog(url_string),
  // appspecific: 
  // ashrae: 
  // assetlinks.json: 
  // broadband-labels: 
  // brski: 
  // caldav: 
  // carddav: 
  // change-password: 
  // cmp: 
  // coap: 
  // core: 
  // csaf: 
  // csaf-aggregator: 
  // csvm: 
  // did.json: 
  // did-configuration.json: 
  // dnt: 
  // dnt-policy.txt: 
  // dots: 
  // ecips: 
  // edhoc: 
  // enterprise-network-security: 
  // enterprise-transport-security: 
  // est: 
  // genid: 
  // gnap-as-rs: 
  // gpc.json: 
  // gs1resolver: 
  // hoba: 
  // host-meta: 
  // host-meta.json: 
  // hosting-provider: 
  // http-opportunistic: 
  // idp-proxy: 
  // jmap: 
  // keybase.txt: 
  // knx: 
  // looking-glass: 
  // masque: 
  // matrix: 
  // mercure: 
  // mta-sts.txt: 
  // mud: 
  // nfv-oauth-server-configuration: 
  // ni: 
  // nodeinfo: 
  // nostr.json: 
  // oauth-authorization-server: 
  // oauth-protected-resource: 
  // ohttp-gateway: 
  // openid-federation: 
  // open-resource-discovery: 
  // openid-configuration: 
  // openorg: 
  // oslc: 
  // pki-validation: 
  // posh: 
  // privacy-sandbox-attestations.json: 
  // probing.txt: 
  // pvd: 
  // rd: 
  // related-website-set.json: 
  // reload-config: 
  // repute-template: 
  // resourcesync: 
  // sbom:  
    securityTxt: await fetchSecurityTxt(url_string),
  // ssf-configuration: 
  // sshfp: 
  // stun-key: 
  // terraform.json: 
  // thread: 
  // time: 
  // timezone: 
  // tdmrep.json: 
  // tor-relay: 
  // tpcd: 
  // traffic-advice: 
  // trust.txt: 
  // uma2-configuration: 
  // void: 
  // webfinger: 
  // webweaver.json: 
  // wot: 
   };
};


export const handler = middleware(wellKnownHandler);
export default handler;

// SPDX-License-Identifier: AGPL-3.0-or-later
// The shape of the documents of the map (docs/api.html, Data format), checked wherever one comes in: on the server
// (the live map, imports, proposals and connector runs) and in the browser (a file imported into a map kept in the
// browser). A document of the wrong shape (vlans that is not a list, a name that is not text) would break the
// interface for every viewer, including the approver reviewing it; an id inside a document (a VLAN, a zone, a
// flow…) ends up in HTML attributes and CSS selectors, so it follows the same rule as the document ids. Unknown
// fields are kept: this checks what the interface relies on, nothing more. The server loads this same file.
(function(root){
'use strict';
const ID_RE = /^(?!(?:__proto__|constructor|prototype)$)[A-Za-z0-9_.:@+~-]{1,120}$/;

const isObj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const TEXT = ['string', 'undefined'];

// Returns '' when the document is fine, or what is wrong with it
function docProblem(kind, doc) {
  if (!isObj(doc)) return 'must be a JSON object';
  const text = (o, keys, where) => { for (const k of keys) if (o[k] !== null && !TEXT.includes(typeof o[k])) return `${where}${k} must be text`; return ''; };
  const list = (k, check) => {
    if (doc[k] === undefined || doc[k] === null) return '';
    if (!Array.isArray(doc[k])) return `${k} must be a list`;
    for (let i = 0; i < doc[k].length; i++) {
      const x = doc[k][i];
      if (!isObj(x)) return `${k}[${i}] must be an object`;
      const p = check(x, `${k}[${i}].`);
      if (p) return p;
    }
    return '';
  };
  const withId = (keys = []) => (x, w) => (typeof x.id !== 'string' || !ID_RE.test(x.id)) ? `${w}id must be an id (letters, digits, . _ - : @ + ~)` : text(x, keys, w);
  const contact = (x, w) => text(x, ['name', 'role', 'phone', 'email', 'dispo'], w);
  let p;
  if (kind === 'si') {
    if ((p = text(doc, ['name', 'kind', 'description'], ''))) return p;
    if ((p = list('zones', withId(['name'])))) return p;
    if ((p = list('vlans', (x, w) => withId(['name', 'cidr'])(x, w) || (x.zone != null && (typeof x.zone !== 'string' || !ID_RE.test(x.zone)) ? `${w}zone must be a zone id` : '')))) return p;
    if ((p = list('flows', (x, w) => withId(['src', 'dst', 'port', 'note'])(x, w) || (x.via != null && !(Array.isArray(x.via) && x.via.every(v => typeof v === 'string' && ID_RE.test(v))) ? `${w}via must be a list of asset ids` : '')))) return p;
    if ((p = list('business', withId(['name', 'owner', 'notes'])))) return p;
    if ((p = list('contacts', contact))) return p;
    if ((p = list('services', (x, w) => text(x, ['id', 'name', 'host', 'port'], w)))) return p;
    if (doc.landscape != null && !isObj(doc.landscape)) return 'landscape must be an object';
    return '';
  }
  if (kind === 'assets') {
    if (doc.site != null && (typeof doc.site !== 'string' || !ID_RE.test(doc.site))) return 'site must be an IS id';
    if (doc.vlan != null && (typeof doc.vlan !== 'string' || !ID_RE.test(doc.vlan))) return 'vlan must be a VLAN id';
    if ((p = text(doc, ['name', 'ip', 'os', 'role', 'notes', 'type', 'scannedAt'], ''))) return p;
    if ((p = list('vulns', (x, w) => text(x, ['id', 'title', 'sev', 'src'], w)))) return p;
    if ((p = list('apps', (x, w) => text(x, ['name', 'version'], w)))) return p;
    if ((p = list('contacts', contact))) return p;
    for (const k of ['ext', 'risk']) if (doc[k] != null && !isObj(doc[k])) return `${k} must be an object`;
    return '';
  }
  return '';
}

root.StrataValidate={ID_RE,docProblem};
})(typeof globalThis!=='undefined'?globalThis:this);

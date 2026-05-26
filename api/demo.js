import { sampleFindings, triageSecurityFindings } from './_triage-core.js';

export default function handler(request, response) {
  response.status(200).json(triageSecurityFindings(sampleFindings));
}

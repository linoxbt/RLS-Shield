export default function handler(request, response) {
  response.status(200).json({
    status: 'ok',
    agent: 'RLS Shield',
    version: '1.0.0',
    runtime: 'vercel-serverless',
    requires_external_api: false
  });
}

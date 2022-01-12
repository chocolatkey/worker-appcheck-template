const appcheck = require('./appcheck')

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})
/**
 * Respond with hello worker text
 * @param {Request} request
 */
async function handleRequest(request) {
  const url = new URL(request.url)

  // Check for the parameter
  if (!url.searchParams.has('act'))
    return new Response("No 'act' parameter in URL", { status: 428 })

  // Verify app check token
  if (!(await appcheck.verify(url.searchParams.get('act'))))
    return new Response('App check verification failed', { status: 403 })

  // Verified!
  return new Response('Hello checked worker!', {
    headers: { 'content-type': 'text/plain' },
  })
}

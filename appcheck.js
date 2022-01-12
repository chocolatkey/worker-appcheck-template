const jose = require('jose')
const custom = require('./custom_jwks')

const APPCHECK_JWKS = 'https://firebaseappcheck.googleapis.com/v1beta/jwks'
const FIREBASE_PROJECT = 'YOUR_FIREBASE_PROJECT_NUMBER' // Can be found in Firebase project settings, the "Project number"

module.exports = {
  /**
   * Verify Firebase App Check JWT
   * @param {string} token Raw JWT
   * @returns {Promise<boolean>}
   */
  verify: async function(token) {
    const jwks = custom.createRemoteJWKSet(new URL(APPCHECK_JWKS))
    try {
      await jose.jwtVerify(token, jwks, {
        typ: 'JWT',
        algorithms: ['RS256'],
        audience: [`projects/${FIREBASE_PROJECT}`],
        issuer: `https://firebaseappcheck.googleapis.com/${FIREBASE_PROJECT}`,
        clockTolerance: 5,
      })
      return true
    } catch (error) {
      console.warn(error)
      return false
    }
  },
}

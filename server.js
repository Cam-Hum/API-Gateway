require('dotenv').config();
const jose = require('jose');
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const app = express();
app.use(express.json());

// Enable CORS. Use CORS_ORIGIN env var or default to localhost:3000
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));

const REGION = process.env.AWS_REGION;
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
const JWKS = jose.createRemoteJWKSet(
  new URL(`${ISSUER}/.well-known/jwks.json`)
);

async function authMiddleware(req, res, next) {
  if (process.env.DEV_AUTH_BYPASS === 'true') {
    const devUser = req.headers['x-dev-user'];
    if (devUser) {
      req.user = { sub: String(devUser) };
      return next();
    }
  }

  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const { payload } = await jose.jwtVerify(token, JWKS, {
      issuer: ISSUER,
      audience: CLIENT_ID,
    });
    req.user = payload;
    console.log('JWT verified for user:', payload.sub);
    return next();
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    console.log('JWT verification failed:', msg);

    return res.status(401).json({ error: 'Invalid token' });
  }
}



app.get('/ping', (req, res) => {
    res.status(200).send('pong');
});

app.use('/booking', authMiddleware, async (req, res) => {
  try {
    const forwardPath = req.originalUrl.replace(/^\/booking/, '') || '/';
    const url = 'http://bookingservice:8082' + forwardPath;

    const headers = { ...req.headers };
    delete headers.host;
    if (req.user && req.user.sub) headers['x-user-id'] = req.user.sub;

    const axiosConfig = {
      method: req.method,
      url,
      headers,
      params: req.query,
      data: req.body,
      validateStatus: () => true,
      responseType: 'arraybuffer'
    };

    const resp = await axios(axiosConfig);

    const hopByHop = ['transfer-encoding', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'upgrade'];
    Object.entries(resp.headers || {}).forEach(([k, v]) => {
      if (!hopByHop.includes(k.toLowerCase())) res.setHeader(k, v);
    });

    res.status(resp.status).send(resp.data);
  } catch (error) {
    console.error('Error proxying to booking service:', error && error.message ? error.message : error);
    res.status(502).json({ error: 'Bad gateway' });
  }
});


app.listen(process.env.PORT, () => {
    console.log("API Gateway listening on port " + process.env.PORT);
});
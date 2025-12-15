require('dotenv').config();
import http from "http";
import { jwtVerify, createRemoteJWKSet } from "jose";

const REGION = process.env.AWS_REGION;
const USER_POOL_ID = process.env.COGNITO_USER_POOL_ID;
const CLIENT_ID = process.env.COGNITO_CLIENT_ID;
const ISSUER = `https://cognito-idp.${REGION}.amazonaws.com/${USER_POOL_ID}`;
const JWKS = createRemoteJWKSet(
  new URL(`${ISSUER}/.well-known/jwks.json`)
);

async function verifyJWT(req) {
    const auth = req.headers.authorization;
    if (!auth) {
        throw new Error("No authorization header");
    }
    const token = auth.split(" ")[1];
    const { payload } = await jwtVerify(token, JWKS, {
        issuer: ISSUER,
        audience: CLIENT_ID,
    });
    return payload;
}

function forward(req, res, host, port) {
    const options = {
        hostname: host,
        port,
        path: req.url,
        method: req.method,
        headers: req.headers,
    };

    const proxyReq = http.request(options, proxyRes => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    });
    req.pipe(proxyReq);
}

const server = http.createServer(async (req, res) => {
    if (req.url === "/ping") {
        return res.statusCode = 200, res.end("pong");
    }
    try {
        const user =await verifyJWT(req);

        req.headers["x-user-id"] = user.sub;
        req.headers["x-user-email"] = user.email || "";

        forward(req, res, "localhost", 8082);
    } catch (err) {
        return res.statusCode = 401, res.end("Unauthorized");
    }
});
server.listen(process.env.PORT, () => {
    console.log("API Gateway listening on port " + process.env.PORT);
});
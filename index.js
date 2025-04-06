require('dotenv').config();
const express = require('express');
const querystring = require('querystring');
const axios = require('axios');
const session = require('express-session');
const NodeCache = require('node-cache'); // 🆕 Add token cache

const app = express();
app.set('view engine', 'pug');

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'http://localhost:3000/oauth-callback';
const authUrl = `https://app.hubspot.com/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=crm.objects.contacts.read%20oauth`;

const accessTokenCache = new NodeCache();        // 🧠 In-memory access token cache
const refreshTokenStore = {};                    // 🔒 Stores refresh tokens by session ID

app.use(session({
  secret: Math.random().toString(36).substring(2),
  resave: false,
  saveUninitialized: true
}));

const isAuthorized = (userId) => {
  return refreshTokenStore[userId] ? true : false;
};

// 🔁 Get access token from cache or refresh if needed
const getToken = async (userId) => {
  if (accessTokenCache.get(userId)) {
    return accessTokenCache.get(userId);
  }

  try {
    const refreshTokenProof = {
      grant_type: 'refresh_token',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      refresh_token: refreshTokenStore[userId]
    };

    const response = await axios.post(
      'https://api.hubspot.com/oauth/v1/token',
      querystring.stringify(refreshTokenProof),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // 🧠 Cache new token and store updated refresh token
    const newAccessToken = response.data.access_token;
    const newRefreshToken = response.data.refresh_token;

    accessTokenCache.set(userId, newAccessToken, Math.round(response.data.expires_in * 0.75));
    refreshTokenStore[userId] = newRefreshToken;

    return newAccessToken;

  } catch (error) {
    console.error('Failed to refresh access token:', error.response?.data || error.message);
    throw error;
  }
};

// Route: home
app.get('/', async (req, res) => {
  if (isAuthorized(req.sessionID)) {
    try {
      const accessToken = await getToken(req.sessionID);
      const headers = {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      };

      const url = 'https://api.hubapi.com/crm/v3/objects/contacts?properties=firstname,lastname,email';
      const resp = await axios.get(url, { headers });
      const data = resp.data;

      console.log('Contacts response:', data);

      res.render('home', {
        token: accessToken,
        contacts: data.results
      });
    } catch (err) {
      res.status(500).send('Failed to fetch contacts');
    }
  } else {
    res.render('home', { authUrl });
  }
});

// Route: OAuth callback
app.get('/oauth-callback', async (req, res) => {
  const userId = req.sessionID;

  const authCodeProof = {
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: REDIRECT_URI,
    code: req.query.code,
  };

  try {
    const responseBody = await axios.post(
      'https://api.hubapi.com/oauth/v1/token',
      querystring.stringify(authCodeProof),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const accessToken = responseBody.data.access_token;
    const refreshToken = responseBody.data.refresh_token;

    // Store tokens
    refreshTokenStore[userId] = refreshToken;

    const expiresIn = responseBody.data.expires_in || 1800;
    const bufferTime = Math.floor(expiresIn * 0.9);

    accessTokenCache.set(userId, accessToken, bufferTime);

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.status(500).send('Failed to retrieve tokens');
  }
});


app.listen(3000, () => console.log('Listening on http://localhost:3000'));

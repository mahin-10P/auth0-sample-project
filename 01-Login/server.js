const dotenv = require('dotenv');
const express = require('express');
const http = require('http');
const logger = require('morgan');
const path = require('path');
const router = require('./routes/index');
const { auth } = require('express-openid-connect');

const bodyParser = require('body-parser');

dotenv.load();

const app = express();
app.use(bodyParser.json());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const config = {
  authRequired: false,
  auth0Logout: false,
  baseURL: 'http://127.0.0.1:3000',
  clientID: 'goSw6f8iiCdon5FDwYCdVJKGaIhaUPUv',
  issuerBaseURL: 'http://127.0.0.1:3000',
  secret: 'TKKnJWpt8ljT6CZjnvtyNxJfuwLm3wwcM4nWOEoWnjiOKHn2LqACWNZQpil7vZad'
};

const port = process.env.PORT || 3000;
if (!config.baseURL && !process.env.BASE_URL && process.env.PORT && process.env.NODE_ENV !== 'production') {
  config.baseURL = `http://localhost:${port}`;
}

const axios = require('axios');
app.post('/api/login', async (req, res) => {
  const { token } = req.body;

  try {
    // Authenticate the user using the Auth0 Management API
    const auth0Response = await axios.post(`https://dev-uxkzwzq6c7k20313.us.auth0.com/oauth/token`, {
      grant_type: 'password',
      client_id: 'goSw6f8iiCdon5FDwYCdVJKGaIhaUPUv',
      client_secret: 'TKKnJWpt8ljT6CZjnvtyNxJfuwLm3wwcM4nWOEoWnjiOKHn2LqACWNZQpil7vZad',
      username: req.body.email, // Replace with the provided username
      password: req.body.password, // Replace with the provided password
      audience: 'https://dev-uxkzwzq6c7k20313.us.auth0.com/api/v2/',
      scope: 'openid profile offline_access email',
    });
    const customClaim = auth0Response.data['https://dev-uxkzwzq6c7k20313.us.auth0.com/user_metadata'];

    console.log('Custom Claim:', customClaim);
    res.json({ data: auth0Response.data });
  } catch (error) {
    console.error(error);
    res.status(400).json({ error:error,message: 'Invalid Login' });

  }
});
app.post('/api/login-mfa', async (req, res) => {
  const { token } = req.body;

  try {
    // Authenticate the user using the Auth0 Management API
    const auth0Response = await axios.post(`https://dev-uxkzwzq6c7k20313.us.auth0.com/oauth/token`, {
      grant_type: 'password',
      client_id: 'goSw6f8iiCdon5FDwYCdVJKGaIhaUPUv',
      client_secret: 'TKKnJWpt8ljT6CZjnvtyNxJfuwLm3wwcM4nWOEoWnjiOKHn2LqACWNZQpil7vZad',
      username: req.body.email, // Replace with the provided username
      password: req.body.password, // Replace with the provided password
      audience: 'https://dev-uxkzwzq6c7k20313.us.auth0.com/api/v2/',
      scope: 'openid profile offline_access email',
    });
 if (auth0Response.data.mfa_token) {
      // MFA challenge is required; handle it here
      req.session.mfaToken = auth0Response.data.mfa_token;
      res.status(200).json({ mfaRequired: true });
    } else {
      // MFA challenge not required; continue with authentication
      req.session.accessToken = auth0Response.data.access_token;
      res.status(200).json({ mfaRequired: false });
    }
  } catch (error) {
    console.error(error.response.data.mfa_token,'startmfa');
    req.mfaToken = error.response.data.mfa_token;
    verifyMfa(req,res);
  }
});

const verifyMfa = async (req, res) => {
  try {
    console.log('verifymfaaa')
    const auth0Response = await axios.post(`https://dev-uxkzwzq6c7k20313.us.auth0.com/mfa/challenge`, {
      /* client_id: 'goSw6f8iiCdon5FDwYCdVJKGaIhaUPUv',
      client_secret: 'TKKnJWpt8ljT6CZjnvtyNxJfuwLm3wwcM4nWOEoWnjiOKHn2LqACWNZQpil7vZad',
       */challenge_type: 'otp oob',
      mfa_token: req.mfaToken
    });

    res.status(200).json({ data: auth0Response });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error , message: 'Failed to obtain an access token' });
  }
};
 const getAccessToken = async (req, res, next) => {
  try {
    const auth0Response = await axios.post(`https://dev-uxkzwzq6c7k20313.us.auth0.com/oauth/token`, {
      grant_type: 'client_credentials',
      client_id: 'goSw6f8iiCdon5FDwYCdVJKGaIhaUPUv',
      client_secret: 'TKKnJWpt8ljT6CZjnvtyNxJfuwLm3wwcM4nWOEoWnjiOKHn2LqACWNZQpil7vZad',
      audience: 'https://dev-uxkzwzq6c7k20313.us.auth0.com/api/v2/',
    });

    req.accessToken = auth0Response.data.access_token;
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: error , message: 'Failed to obtain an access token' });
  }
};
app.post('/api/refreshToken', getAccessToken, async (req, res) => {
  try {
    // Define the refresh token data
    const refreshTokenData = {
      grant_type: 'refresh_token',
      client_id: 'goSw6f8iiCdon5FDwYCdVJKGaIhaUPUv',
      client_secret: 'TKKnJWpt8ljT6CZjnvtyNxJfuwLm3wwcM4nWOEoWnjiOKHn2LqACWNZQpil7vZad',
      refresh_token: req.body.refresh_token, // Replace with the refresh token
      scope: 'openid profile offline_access email', // Include the "offline_access" scope to get a new refresh token
    };

    // Send a POST request to Auth0's /oauth/token endpoint to refresh the tokens
    const auth0Response = await axios.post(`https://dev-uxkzwzq6c7k20313.us.auth0.com/oauth/token`, refreshTokenData, {
      headers: {
        'Content-Type': 'application/json',
      },
    });

    res.json({
      data: auth0Response.data
    });
  } catch (error) {
    console.error(error);
    
    res.status(500).json({ error:error , message: 'Failed to refresh the tokens' });
  }
});
app.post('/api/create-user', getAccessToken, async (req, res) => {
  try {
    // Define the user data
    const userData = {
      email: req.body.email, // Replace with the email address of the user to create
      password: req.body.password, // Replace with the password of the user to create
      connection: 'Username-Password-Authentication', // Replace with the appropriate connection name
      user_metadata: {
        name: req.body.name, // Custom field: name
        age: req.body.age,   // Custom field: age
      },
    };

    // Send a POST request to Auth0's /api/v2/users endpoint to create a new user
    const auth0Response = await axios.post(`https://dev-uxkzwzq6c7k20313.us.auth0.com/api/v2/users`, userData, {
      headers: {
        authorization: `Bearer ${req.accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    res.json(auth0Response.data);
  } catch (error) {
    console.error(error);

    res.status(500).json({ error: error , message: 'Failed to create a user' });
  }
});

app.get('/api/userById/:id', async (req, res) => {
  try {
    const url = `https://dev-uxkzwzq6c7k20313.us.auth0.com/api/v2/users/${req.params.id}`;
    const accessToken = req.header('authorization');
    const auth0Response = await axios.get(url, {
      headers: {
        authorization: `${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    res.json(auth0Response.data);
  } catch (error) {
    console.error(error);

    res.status(500).json({ error: error , message: 'Failed to create a user' });
  }
});

const getUserData = async (req, res, next) => {
  try {
    const accessToken = req.header('authorization').replace('Bearer ', '');

    // Send a GET request to Auth0's /userinfo endpoint to obtain user data
    const auth0Response = await axios.get(`https://dev-uxkzwzq6c7k20313.us.auth0.com/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });
   /*  const customClaim = auth0Response.data['https://dev-uxkzwzq6c7k20313.us.auth0.com/user_metadata'];

    console.log('Custom Claim:', customClaim); */
    req.userData = auth0Response.data;
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({error:error, message: 'Failed to obtain user data' });
  }
};

app.get('/api/user-data', getUserData, (req, res) => {
  res.json(req.userData);
});
// Middleware to make the `user` object available for all views
app.use(function (req, res, next) {
  res.locals.user = req.oidc.user;
  next();
});

app.use('/', router);

// Catch 404 and forward to error handler
app.use(function (req, res, next) {
  const err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// Error handlers
app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: process.env.NODE_ENV !== 'production' ? err : {}
  });
});

http.createServer(app)
  .listen(port, () => {
    console.log(`Listening on ${config.baseURL}`);
  });

const express = require('express');
const bodyParser = require('body-parser');
const saml = require('@boxyhq/saml20').default;
const stream = require('stream');
const util = require('util');
const crypto = require('crypto');
const path = require('path');
const { config, getEntityId, getSSOUrl } = require('./config');


const app = express();
const PORT = process.env.PORT || 3000;

const pipeline = util.promisify(stream.pipeline);

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Helper function to process SAML request
async function processSAMLRequest(req, res, isPost) {
    let samlRequest, relayState, isDeflated;

    if (isPost) {
        relayState = req.body.RelayState;
        samlRequest = req.body.SAMLRequest;
        isDeflated = false;
    } else {
        relayState = req.query.RelayState;
        samlRequest = req.query.SAMLRequest;
        isDeflated = true;
    }

    console.log('relayState:', relayState);
    console.log('samlRequest:', samlRequest);
    console.log('isDeflated:', isDeflated);

    try {
        const rawRequest = await saml.decodeBase64(samlRequest, isDeflated);
        // console.log('rawRequest:', rawRequest);


        const { id, audience, acsUrl, providerName, publicKey } = await saml.parseSAMLRequest(rawRequest, isPost);

        if (isPost) {
            const { valid } = await saml.hasValidSignature(rawRequest, publicKey, null);
            if (!valid) {
                throw new Error('Invalid signature');
            }
        }

        const params = new URLSearchParams({ id, audience, acsUrl, providerName, relayState });

        console.log(params.toString());
        console.log('id:', id);
        console.log('audience:', audience);
        console.log('acsUrl:', acsUrl);
        console.log('providerName:', providerName);
        console.log('publicKey:', publicKey);
        

        // const loginUrl = (req.query.namespace ? `/namespace/${req.query.namespace}` : '') + '/saml/login';
        const loginUrl = '/login';

        res.redirect(302, `${loginUrl}?${params.toString()}`);
    } catch (err) {
        console.error(err);
        res.status(500).send(`${err}`);
    }
}

  

// Endpoint 1: GET /api/saml/metadata
app.get('/api/saml/metadata', async (req, res) => {
    const namespace = "example.com";

    const xml = saml.createIdPMetadataXML({
        entityId: getEntityId(config.entityId, namespace),
        ssoUrl: getSSOUrl(config.appUrl, namespace),
        x509cert: saml.stripCertHeaderAndFooter(config.publicKey),
        wantAuthnRequestsSigned: true,
    });

    res.setHeader('Content-type', 'text/xml');

    res.send(xml);
});

// Endpoint 2: POST /api/saml/auth
app.post('/api/saml/auth', async (req, res) => {
    console.log("POST /api/saml/auth")

    const { email, audience, acsUrl, id, relayState } = req.body;
    const { namespace } = req.query;

    console.log('email:', email);
    console.log('audience:', audience);
    console.log('acsUrl:', acsUrl);
    console.log('id:', id);
    console.log('relayState:', relayState);
    console.log('namespace:', namespace);

    if (!email.endsWith('@example.com') && !email.endsWith('@example.org')) {
        return res.status(403).send(`${email} denied access`);
    }

    const userId = crypto.createHash('sha256').update(email).digest('hex');
    const userName = email.split('@')[0];

    const user = {
        id: userId,
        email,
        firstName: userName,
        lastName: userName,
    };

    try {
        const xmlSigned = await saml.createSAMLResponse({
            issuer: getEntityId(config.entityId, namespace),
            audience,
            acsUrl,
            requestId: id,
            claims: {
                email: user.email,
                raw: user,
            },
            privateKey: config.privateKey,
            publicKey: config.publicKey,
        });

        const encodedSamlResponse = Buffer.from(xmlSigned).toString('base64');
        const html = saml.createPostForm(acsUrl, [
            {
                name: 'RelayState',
                value: relayState,
            },
            {
                name: 'SAMLResponse',
                value: encodedSamlResponse,
            },
        ]);

        res.send(html);
    } catch (error) {
        console.error('Error creating SAML response:', error);
        res.status(500).send('Internal Server Error');
    }
});



// Endpoint 3: GET /api/saml/sso
app.get('/api/saml/sso', async (req, res) => {
    console.log("GET /api/saml/sso")
    await processSAMLRequest(req, res, false);
});

// Endpoint 4: POST /api/saml/sso
app.post('/api/saml/sso', async (req, res) => {
    console.log("POST /api/saml/sso")
    await processSAMLRequest(req, res, true);
});

// Serve the login page
app.get('/login', (req, res) => {

    const { id, audience, acsUrl, providerName, relayState } = req.query;
    const { namespace } = req.query;

    res.render('login', {
        id,
        audience,
        acsUrl,
        providerName,
        relayState,
        namespace,
    });
  });

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
